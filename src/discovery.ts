import * as dgram from "node:dgram";
import * as os from "node:os";
import * as https from "node:https";
import { execSync } from "node:child_process";
import { PROTOCOL_VERSION } from "./protocol-schema.js";

export const DEFAULT_PORT = 9900;
export const UDP_DISCOVERY_PORT = 9901;

export interface NetworkInfo {
  hostname: string;
  tailscaleIp: string | null;
  lanIps: string[];
  broadcastIps: string[];
}

export interface DiscoveredHub {
  hubId: string;
  host: string;
  ip: string;
  port: number;
  transport: "wss";
  spkiFingerprint: string;
  principalId?: string;
  certificateFingerprint?: string; // legacy alias
  /** Opaque room identity advertised by the hub. Never a user-visible label. */
  roomId?: string;
  source: "tailscale" | "lan" | "local";
  endpoints?: string[];
}

export function getNetworkInfo(): NetworkInfo {
  const nets = os.networkInterfaces();
  let tailscaleIp: string | null = null;
  const lanIps: string[] = [];
  const broadcastIps: string[] = [];

  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === "IPv4" && !net.internal) {
        if (net.address.startsWith("100.")) {
          const second = parseInt(net.address.split(".")[1], 10);
          if (second >= 64 && second <= 127) {
            tailscaleIp = net.address;
          }
        } else if (
          net.address.startsWith("10.") ||
          net.address.startsWith("192.168.") ||
          net.address.startsWith("172.")
        ) {
          lanIps.push(net.address);
          if (net.netmask) {
            const ipParts = net.address.split(".").map(Number);
            const maskParts = net.netmask.split(".").map(Number);
            const bcast = ipParts.map((b, i) => (b | (~maskParts[i] & 255)) >>> 0).join(".");
            broadcastIps.push(bcast);
          }
        }
      }
    }
  }

  return {
    hostname: os.hostname(),
    tailscaleIp,
    lanIps,
    broadcastIps: Array.from(new Set(broadcastIps)),
  };
}

export function resolveTailscaleBin(): string | null {
  const candidates = [
    "tailscale",
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "/usr/local/bin/tailscale",
    "/opt/homebrew/bin/tailscale",
  ];
  for (const c of candidates) {
    try {
      execSync(`"${c}" version`, { stdio: "ignore" });
      return c;
    } catch {}
  }
  return null;
}

/**
 * The responder is an unauthenticated oracle: anything that can route a datagram to this host
 * learns that a hub exists and on which port, and a spoofed source address turns it into an
 * unsolicited packet aimed at a third party. LAN discovery only ever needs to answer the local
 * broadcast domain, so the reply set is confined to the ranges this host is actually attached to
 * (plus loopback for same-machine scans) and rate limited per source. Amplification is not a
 * real concern here — the reply is smaller than the request — so the limit exists to bound the
 * unsolicited traffic a spoofer can aim somewhere, not to protect this host.
 */
const UDP_RESPONSE_WINDOW_MS = 10_000;
/**
 * `discoverLanHubsViaUdp` rebroadcasts every 200 ms for its whole scan window, so a single
 * honest scan already costs 4-5 replies, and several terminals on one machine share a source
 * address. The cap is sized to let a person scan repeatedly and never notice it (~6 scans per
 * window) while still bounding what a spoofed source can aim at a third party: a reply is 24
 * bytes, so this is 3 packets and ~72 B/s at worst.
 */
const UDP_MAX_RESPONSES_PER_SOURCE = 30;
const UDP_SOURCE_TABLE_MAX = 512;
const UDP_RANGE_REFRESH_MS = 60_000;
const MAX_DISCOVERY_DATAGRAM_BYTES = 64;
/** 127.0.0.0/8 — a scan from this machine arrives over loopback and is always answered. */
const LOOPBACK_NETWORK = 0x7f000000;
const LOOPBACK_MASK = 0xff000000;

interface Ipv4Range {
  network: number;
  mask: number;
}

function ipv4ToInt(address: string): number | null {
  const parts = address.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value >>> 0;
}

/**
 * Every IPv4 network this host has an address on, as (network, mask) pairs, plus 127.0.0.0/8.
 * Read straight from the interface list — the same source `getNetworkInfo()` uses — because the
 * netmask is what defines the broadcast domain and `NetworkInfo` only publishes the derived
 * broadcast addresses.
 */
function collectLocalIpv4Ranges(): Ipv4Range[] {
  const ranges: Ipv4Range[] = [{ network: LOOPBACK_NETWORK, mask: LOOPBACK_MASK }];
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family !== "IPv4" || net.internal) continue;
      const address = ipv4ToInt(net.address);
      const mask = net.netmask ? ipv4ToInt(net.netmask) : null;
      if (address === null || mask === null) continue;
      ranges.push({ network: (address & mask) >>> 0, mask: mask >>> 0 });
    }
  }
  return ranges;
}

function isWithinRanges(address: string, ranges: Ipv4Range[]): boolean {
  // A udp4 socket reports dotted quads, but an IPv4-mapped form costs nothing to accept.
  const plain = address.startsWith("::ffff:") ? address.slice("::ffff:".length) : address;
  const value = ipv4ToInt(plain);
  if (value === null) return false;
  return ranges.some((range) => ((value & range.mask) >>> 0) === range.network);
}

export function startUdpDiscoveryResponder(
  tcpPort: number,
  options: { bindHost?: string; enabled?: boolean } = {},
): dgram.Socket | null {
  if (options.enabled === false) {
    return null;
  }
  // If bindHost is loopback or Tailscale IP, disable LAN UDP discovery
  if (
    options.bindHost === "127.0.0.1" ||
    options.bindHost === "::1" ||
    (options.bindHost && options.bindHost.startsWith("100."))
  ) {
    return null;
  }

  try {
    const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });

    let ranges = collectLocalIpv4Ranges();
    let rangesComputedAt = Date.now();
    /** Sliding window of reply timestamps per source address. */
    const recentReplies = new Map<string, number[]>();

    const allowSource = (address: string): boolean => {
      if (isWithinRanges(address, ranges)) return true;
      // A laptop changes networks without restarting its hub: re-read the interfaces at most
      // once a minute, and only when a datagram would otherwise be dropped.
      if (Date.now() - rangesComputedAt < UDP_RANGE_REFRESH_MS) return false;
      ranges = collectLocalIpv4Ranges();
      rangesComputedAt = Date.now();
      return isWithinRanges(address, ranges);
    };

    const withinRateLimit = (address: string): boolean => {
      const now = Date.now();
      const seen = (recentReplies.get(address) || []).filter((ts) => now - ts < UDP_RESPONSE_WINDOW_MS);
      if (seen.length >= UDP_MAX_RESPONSES_PER_SOURCE) {
        recentReplies.set(address, seen);
        return false;
      }
      if (!recentReplies.has(address) && recentReplies.size >= UDP_SOURCE_TABLE_MAX) {
        for (const [key, stamps] of recentReplies) {
          if (stamps.every((ts) => now - ts >= UDP_RESPONSE_WINDOW_MS)) recentReplies.delete(key);
        }
        // Still full: refuse rather than let the table grow without bound.
        if (recentReplies.size >= UDP_SOURCE_TABLE_MAX) return false;
      }
      seen.push(now);
      recentReplies.set(address, seen);
      return true;
    };

    socket.on("message", (msg, rinfo) => {
      if (msg.length > MAX_DISCOVERY_DATAGRAM_BYTES) return;
      const text = msg.toString().trim();
      if (!text.startsWith("OMP_LINK_DISCOVER")) return;
      if (!allowSource(rinfo.address)) return;
      if (!withinRateLimit(rinfo.address)) return;
      const resp = Buffer.from(`OMP_LINK_HUB_V5:${tcpPort}`);
      try {
        socket.send(resp, rinfo.port, rinfo.address);
      } catch {}
    });
    socket.on("error", () => {
      try { socket.close(); } catch {}
    });
    socket.bind(UDP_DISCOVERY_PORT, options.bindHost && options.bindHost !== "0.0.0.0" ? options.bindHost : "0.0.0.0");
    return socket;
  } catch {
    return null;
  }
}

/**
 * A `/status` response is unauthenticated by definition, and every field below is rendered to a
 * human or handed to a model. Keep only plain printable ASCII, bounded: a peer that can smuggle
 * a newline or an ANSI escape can forge a line that looks like output from this tool.
 */
function safePrintable(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength) return undefined;
  return /^[\x20-\x7E]+$/.test(trimmed) ? trimmed : undefined;
}

/** Accept a fingerprint only in the canonical 32-octet form the rest of the code compares. */
function safeFingerprint(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const upper = value.trim().toUpperCase();
  return /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(upper) ? upper : undefined;
}

export async function fetchPublicHubStatus(
  host: string,
  port: number,
  timeoutMs = 800,
): Promise<DiscoveredHub | null> {
  return new Promise((resolve) => {
    const agent = new https.Agent({
      rejectUnauthorized: false, // For probing discovery status only
      minVersion: "TLSv1.3",
    });

    const timer = setTimeout(() => {
      try { req.destroy(); } catch {}
      resolve(null);
    }, timeoutMs);

    const req = https.get(
      {
        host,
        port,
        path: "/status",
        agent,
        headers: {
          Accept: "application/json",
        },
      },
      (res) => {
        let body = "";
        const MAX_STATUS_BYTES = 16 * 1024;
        res.on("data", (chunk) => {
          body += chunk;
          if (body.length > MAX_STATUS_BYTES) {
            clearTimeout(timer);
            try { req.destroy(); } catch {}
            resolve(null);
          }
        });
        res.on("end", () => {
          clearTimeout(timer);
          try {
            const data = JSON.parse(body);
            if (data.service === "omp-link" && Number(data.protocolVersion) === PROTOCOL_VERSION) {
              // Everything here came from an endpoint nobody has authenticated yet, and all of
              // it is rendered to an operator (and into an agent's context via link_discover).
              // Anything that is not plainly printable is dropped rather than shown: a peer
              // that can embed newlines or ANSI can paint a convincing "verified" line.
              const spkiFp = safeFingerprint(data.spkiFingerprint || data.certificateFingerprint);
              if (!spkiFp) {
                resolve(null);
                return;
              }
              resolve({
                hubId: safePrintable(data.instanceId, 64) || `hub-${spkiFp.replace(/:/g, "").slice(0, 16)}`,
                roomId: safePrintable(data.roomId, 64),
                host,
                ip: host,
                port,
                transport: "wss",
                spkiFingerprint: spkiFp,
                certificateFingerprint: spkiFp,
                principalId: safePrintable(data.principalId, 128),
                source: host === "127.0.0.1" ? "local" : (host.startsWith("100.") ? "tailscale" : "lan"),
              });
              return;
            }
          } catch {}
          resolve(null);
        });
      },
    );

    req.on("error", () => {
      clearTimeout(timer);
      resolve(null);
    });
  });
}

export function discoverLanHubsViaUdp(
  port = DEFAULT_PORT,
  timeoutMs = 800,
): Promise<Array<{ host: string; port: number }>> {
  return new Promise((resolve) => {
    const found = new Map<string, { host: string; port: number }>();
    let socket: dgram.Socket | null = null;
    let bcastInterval: NodeJS.Timeout | null = null;

    const timer = setTimeout(() => {
      if (bcastInterval) clearInterval(bcastInterval);
      try { socket?.close(); } catch {}
      resolve(Array.from(found.values()));
    }, timeoutMs);

    try {
      socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
      socket.on("message", (msg, rinfo) => {
        const text = msg.toString().trim();
        if (text.startsWith("OMP_LINK_HUB_V5:")) {
          const p = Number(text.slice("OMP_LINK_HUB_V5:".length)) || port;
          found.set(`${rinfo.address}:${p}`, { host: rinfo.address, port: p });
        }
      });

      socket.on("error", () => {
        if (bcastInterval) clearInterval(bcastInterval);
        clearTimeout(timer);
        try { socket?.close(); } catch {}
        resolve(Array.from(found.values()));
      });

      socket.bind(0, () => {
        try {
          socket?.setBroadcast(true);
          const req = Buffer.from("OMP_LINK_DISCOVER");
          const net = getNetworkInfo();
          const targets = new Set(["255.255.255.255", ...net.broadcastIps]);

          const sendPackets = () => {
            for (const bcast of targets) {
              try {
                socket?.send(req, UDP_DISCOVERY_PORT, bcast);
              } catch {}
            }
          };

          sendPackets();
          bcastInterval = setInterval(sendPackets, 200);
        } catch {}
      });
    } catch {
      clearTimeout(timer);
      resolve([]);
    }
  });
}

export async function discoverAllHubs(
  port = DEFAULT_PORT,
  timeoutMs = 1200,
  options: { mode?: "tailscale" | "lan" | "loopback" | "all" } = {},
): Promise<DiscoveredHub[]> {
  const mode = options.mode || "all";
  const hubs: DiscoveredHub[] = [];
  const probed = new Set<string>();

  // 1. Probe localhost
  probed.add(`127.0.0.1:${port}`);
  const localHub = await fetchPublicHubStatus("127.0.0.1", port, Math.min(timeoutMs, 400));
  if (localHub) hubs.push({ ...localHub, source: "local" });

  if (mode === "loopback") {
    return hubs;
  }

  // 2. Discover via LAN UDP (only if mode is 'lan' or 'all')
  if (mode === "lan" || mode === "all") {
    const lanEndpoints = await discoverLanHubsViaUdp(port, Math.min(timeoutMs, 600));
    const lanProbes = lanEndpoints.map(async (ep) => {
      const key = `${ep.host}:${ep.port}`;
      if (probed.has(key)) return null;
      probed.add(key);
      const res = await fetchPublicHubStatus(ep.host, ep.port, timeoutMs);
      if (res) return { ...res, source: "lan" as const };
      return null;
    });

    const lanResults = await Promise.all(lanProbes);
    for (const h of lanResults) {
      if (h && !hubs.some((existing) => existing.hubId === h.hubId)) {
        hubs.push(h);
      }
    }
  }

  // 3. Discover via Tailscale (only if mode is 'tailscale' or 'all')
  if (mode === "tailscale" || mode === "all") {
    const tsBin = resolveTailscaleBin();
    if (tsBin) {
      try {
        const stdout = execSync(`"${tsBin}" status --json`, {
          encoding: "utf8",
          timeout: 2000,
          stdio: ["ignore", "pipe", "ignore"],
        });
        const tsStatus = JSON.parse(stdout);
        const peerIps: string[] = [];
        if (tsStatus.Peer) {
          for (const peer of Object.values<any>(tsStatus.Peer)) {
            if (peer.Online && peer.TailscaleIPs) {
              const ip4 = peer.TailscaleIPs.find((ip: string) => ip.startsWith("100."));
              if (ip4) peerIps.push(ip4);
            }
          }
        }

        const tsProbes = peerIps.map(async (ip) => {
          const key = `${ip}:${port}`;
          if (probed.has(key)) return null;
          probed.add(key);
          const res = await fetchPublicHubStatus(ip, port, timeoutMs);
          if (res) return { ...res, source: "tailscale" as const };
          return null;
        });

        const tsResults = await Promise.all(tsProbes);
        for (const h of tsResults) {
          if (h && !hubs.some((existing) => existing.hubId === h.hubId)) {
            hubs.push(h);
          }
        }
      } catch {}
    }
  }

  return hubs;
}
