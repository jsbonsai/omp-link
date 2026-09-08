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
  sessionId: string;
  host: string;
  ip: string;
  port: number;
  transport: "wss";
  certificateFingerprint: string;
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

export function startUdpDiscoveryResponder(tcpPort: number): dgram.Socket | null {
  try {
    const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
    socket.on("message", (msg, rinfo) => {
      const text = msg.toString().trim();
      if (text.startsWith("OMP_LINK_DISCOVER")) {
        const resp = Buffer.from(`OMP_LINK_HUB_V5:${tcpPort}`);
        try {
          socket.send(resp, rinfo.port, rinfo.address);
        } catch {}
      }
    });
    socket.on("error", () => {
      try { socket.close(); } catch {}
    });
    socket.bind(UDP_DISCOVERY_PORT, "0.0.0.0");
    return socket;
  } catch {
    return null;
  }
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
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => {
          clearTimeout(timer);
          try {
            const data = JSON.parse(body);
            if (data.service === "omp-link" && data.protocolVersion === PROTOCOL_VERSION) {
              resolve({
                hubId: data.instanceId,
                sessionId: data.sessionId || "team-link",
                host,
                ip: host,
                port,
                transport: "wss",
                certificateFingerprint: data.certificateFingerprint,
                source: host === "127.0.0.1" ? "local" : "lan",
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
): Promise<DiscoveredHub[]> {
  const hubs: DiscoveredHub[] = [];
  const probed = new Set<string>();

  // 1. Probe localhost
  probed.add(`127.0.0.1:${port}`);
  const localHub = await fetchPublicHubStatus("127.0.0.1", port, Math.min(timeoutMs, 400));
  if (localHub) hubs.push({ ...localHub, source: "local" });

  // 2. Discover via LAN UDP
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

  // 3. Discover via Tailscale
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

  return hubs;
}
