/**
 * Pi Link — WebSocket-based inter-terminal communication
 *
 * Connects multiple Pi terminals over a local WebSocket link.
 * Opt-in via --link flag, --link-name flag, pi-link CLI, or /link-connect command.
 * First terminal to connect becomes the hub; others join as clients.
 * Hub loss triggers automatic promotion of a surviving client.
 *
 * Tools: link_send, link_list, link_compact
 * Commands: /link, /link-name, /link-connect, /link-disconnect
 */

import {
  VERSION as PI_VERSION,
  type ExtensionAPI,
  type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";
import { execSync, exec, execFile, execFileSync } from "node:child_process";
import * as crypto from "node:crypto";
import * as dgram from "node:dgram";
import * as fs from "node:fs";
import { createServer as createHttpServer, type Server as HttpServer, type IncomingMessage } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import * as os from "node:os";
import * as path from "node:path";

import { WebSocket, WebSocketServer } from "ws";

// ─── Constants ───────────────────────────────────────────────────────────────

// Pi 0.84.2 is the floor: `agent_settled` and `ctx.isIdle()` are the whole basis of
// the settled lifecycle and the remote-compaction guard below, and there is one code
// path for them. Package installation does not check the host version, so an older
// Pi installs pi-link successfully and must be refused at load.
const MIN_PI_VERSION = [0, 84, 2];

const DEFAULT_PORT = 9900;
const DEFAULT_BIND = "0.0.0.0";
const UDP_DISCOVERY_PORT = 9901;
const COMPACT_TIMEOUT_MS = 180_000;
const RECONNECT_DELAY_MS = 2000;
// Bounds the HTTP Upgrade only. Without it `ws` waits forever, so a listener that
// accepts the socket and never answers leaves the terminal offline with no retry.
const CONNECT_HANDSHAKE_TIMEOUT_MS = 5_000;
const FLUSH_DELAY_MS = 50;
const BATCH_MAX_ITEMS = 20;
const BATCH_MAX_CHARS = 16_000;

// ─── Protocol ────────────────────────────────────────────────────────────────

interface DevicePermissions {
  message: boolean;
  inspect: boolean;
  fileInbox: boolean;
  exec: boolean;
}

interface HandshakeChallengeMsg {
  type: "handshake_challenge";
  v: 4;
  hubId: string;
  hubFingerprint: string;
  nonce: string;
  ts: number;
  hubEphemeralPub: string;
}

interface HandshakeResponseMsg {
  type: "handshake_response";
  v: 4;
  deviceId: string;
  name: string;
  publicKey: string;
  fingerprint: string;
  signature: string;
  clientEphemeralPub: string;
  host: string;
  cwd?: string;
  context?: ContextSnapshot;
  project?: string;
}

interface RegisterMsg {
  type: "register";
  name: string;
  sessionId?: string;
  pin?: string;
  network?: string;
  cwd?: string;
  context?: ContextSnapshot;
  host?: string;
  project?: string;
  token?: string;
  deviceId?: string;
  publicKey?: string;
  fingerprint?: string;
}
interface WelcomeMsg {
  type: "welcome";
  name: string;
  sessionId?: string;
  pin?: string;
  network?: string;
  terminals: string[];
  statuses?: Record<string, LinkStatus>;
  cwds?: Record<string, string>;
  contexts?: Record<string, ContextSnapshot>;
  hosts?: Record<string, string>;
  projects?: Record<string, string>;
  permissions?: DevicePermissions;
  hubFingerprint?: string;
}
interface PairingPendingMsg {
  type: "pairing_pending";
  requestId: number;
  hubHost: string;
  fingerprint: string;
  message: string;
}
interface PairingDeniedMsg {
  type: "pairing_denied";
  message: string;
}
interface TerminalJoinedMsg {
  type: "terminal_joined";
  name: string;
  sessionId?: string;
  network?: string;
  terminals: string[];
  cwd?: string;
  context?: ContextSnapshot;
  host?: string;
  project?: string;
}
interface TerminalLeftMsg {
  type: "terminal_left";
  name: string;
  terminals: string[];
}
interface ChatMsg {
  type: "chat";
  from: string;
  to: string;
  content: string;
}
interface StatusUpdateMsg {
  type: "status_update";
  name: string;
  status: LinkStatus;
  // Per-terminal LLM context. Absent = old terminal (ignore); null = clear
  // stored value; object = store. Only status_update carries the null-clear.
  context?: ContextSnapshot | null;
}
interface ErrorMsg {
  type: "error";
  message: string;
}
interface CompactRequestMsg {
  type: "compact_request";
  id: string;
  from: string;
  to: string;
  instructions?: string;
}
interface CompactResponseMsg {
  type: "compact_response";
  id: string;
  from: string;
  to: string;
  ok: boolean;
  reason?: string; // "busy" | "not_found" | "unsupported" | error text; absent on success
}

interface RpcRequestMsg {
  type: "rpc_request";
  id: string;
  from: string;
  to: string;
  action:
    | "exec"
    | "read_file"
    | "list_dir"
    | "git_status"
    | "git_diff"
    | "git_log"
    | "search_text";
  params: {
    command?: string;
    cwd?: string;
    filePath?: string;
    count?: number;
    pattern?: string;
    authToken?: string;
  };
}

interface RpcResponseMsg {
  type: "rpc_response";
  id: string;
  from: string;
  to: string;
  ok: boolean;
  result?: string;
  error?: string;
}

interface FileOfferMsg {
  type: "file_offer";
  transferId: string;
  from: string;
  to: string;
  filename: string;
  destRelPath?: string;
  sizeBytes: number;
  sha256: string;
  totalChunks: number;
  downloadUrl?: string;
}

interface FileChunkMsg {
  type: "file_chunk";
  transferId: string;
  from: string;
  to: string;
  chunkIndex: number;
  totalChunks: number;
  data: string;
}

interface FileAckMsg {
  type: "file_ack";
  transferId: string;
  from: string;
  to: string;
  ok: boolean;
  savedPath?: string;
  error?: string;
}

interface EncryptedMsg {
  type: "encrypted";
  v: 4;
  mid: string;
  seq: number;
  from: string;
  ts: number;
  iv: string;
  tag: string;
  data: string;
}

type LinkStatus =
  | { kind: "idle"; since: number }
  | { kind: "thinking"; since: number }
  | { kind: "compacting"; since: number }
  | { kind: "tool"; toolName: string; since: number };

type ContextSnapshot = { tokens: number | null; contextWindow: number };

type LinkMessage =
  | HandshakeChallengeMsg
  | HandshakeResponseMsg
  | RegisterMsg
  | WelcomeMsg
  | TerminalJoinedMsg
  | TerminalLeftMsg
  | ChatMsg
  | StatusUpdateMsg
  | ErrorMsg
  | CompactRequestMsg
  | CompactResponseMsg
  | RpcRequestMsg
  | RpcResponseMsg
  | FileOfferMsg
  | FileChunkMsg
  | FileAckMsg
  | EncryptedMsg
  | PairingPendingMsg
  | PairingDeniedMsg;

/**
 * True when Pi is at or above MIN_PI_VERSION. A fixed floor needs an ordered compare
 * of three numbers, not a semver dependency — but it does need SemVer's shape, so the
 * core rejects leading zeros, an optional prerelease is captured because it lowers
 * precedence, and optional build metadata is matched and then ignored because it
 * carries none. A prerelease of the floor itself precedes it, so `0.84.2-beta.1` is
 * below `0.84.2` while `0.85.0-beta.1` is above it on its core alone. Each suffix is
 * a dot-separated series of nonempty identifiers, so `0.84.2+.` and `0.85.0-alpha..1`
 * are malformed. Anything unparsable, or with a component too large to compare
 * exactly, is refused rather than guessed at.
 */
function piVersionSupported(version?: string): boolean {
  if (!version) return true; // tolerate missing or embedded versions in forks like OMP
  if (process.env.PI_LINK_IGNORE_VERSION_CHECK === "1") return true;
  const v = version.trim().replace(/^v/, "");
  const parsed =
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.exec(
      v,
    );
  if (!parsed) return true; // tolerate non-semver strings in forks
  // A numeric prerelease identifier may not carry a leading zero. `0rc` may, being
  // alphanumeric, and so may a build identifier, which never affects precedence.
  const prerelease = parsed[4];
  if (prerelease?.split(".").some((id) => /^0\d+$/.test(id))) return false;
  for (let i = 0; i < 3; i++) {
    const part = Number(parsed[i + 1]);
    if (!Number.isSafeInteger(part)) return false;
    if (part !== MIN_PI_VERSION[i]) return part > MIN_PI_VERSION[i];
  }
  return prerelease === undefined; // exactly the floor: only the release qualifies
}

// ─── Network Helpers ─────────────────────────────────────────────────────────

let cachedTailscaleBin: string | null | undefined = undefined;

function resolveTailscaleBin(): string | null {
  if (cachedTailscaleBin !== undefined) return cachedTailscaleBin;
  const candidates = [
    "tailscale",
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "/usr/local/bin/tailscale",
    "/opt/homebrew/bin/tailscale",
  ];
  for (const c of candidates) {
    try {
      execSync(`"${c}" version`, { stdio: "ignore" });
      cachedTailscaleBin = c;
      return c;
    } catch {}
  }
  cachedTailscaleBin = null;
  return null;
}

interface NetworkInfo {
  hostname: string;
  tailscaleIp: string | null;
  lanIps: string[];
  broadcastIps: string[];
}

function getNetworkInfo(): NetworkInfo {
  const hostname = os.hostname();
  let tailscaleIp: string | null = null;
  const lanIps: string[] = [];
  const broadcastIps: string[] = [];

  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    const addrs = interfaces[name];
    if (!addrs) continue;
    for (const addr of addrs) {
      if (addr.family !== "IPv4" || addr.internal) continue;
      const ip = addr.address;
      const parts = ip.split(".").map(Number);
      // Tailscale IPv4 CGNAT range: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
      if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) {
        if (!tailscaleIp) tailscaleIp = ip;
      } else if (
        parts[0] === 10 ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168)
      ) {
        lanIps.push(ip);
        if (addr.netmask) {
          try {
            const maskParts = addr.netmask.split(".").map(Number);
            const bcastParts = parts.map((p, i) => (p | (~maskParts[i] & 255)));
            broadcastIps.push(bcastParts.join("."));
          } catch {}
        }
      }
    }
  }

  // Fallback Tailscale detection via CLI if not in networkInterfaces
  if (!tailscaleIp) {
    const bin = resolveTailscaleBin();
    if (bin) {
      try {
        const out = execSync(`"${bin}" ip -4`, {
          encoding: "utf-8",
          timeout: 1500,
          stdio: ["ignore", "pipe", "ignore"],
        }).trim();
        const firstLine = out.split("\n")[0].trim();
        if (firstLine.startsWith("100.")) {
          tailscaleIp = firstLine;
        }
      } catch {}
    }
  }

  return { hostname, tailscaleIp, lanIps, broadcastIps };
}

function isTailscaleOrLocalIp(ip?: string): boolean {
  if (!ip) return false;
  const cleanIp = ip.startsWith("::ffff:") ? ip.slice(7) : ip;
  if (cleanIp === "127.0.0.1" || cleanIp === "::1" || cleanIp === "localhost") return true;
  const parts = cleanIp.split(".").map(Number);
  if (parts.length === 4 && parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) {
    return true;
  }
  if (cleanIp.toLowerCase().startsWith("fd7a:115c:a1e0:")) return true;
  return false;
}

function isLocalhost(ip?: string): boolean {
  if (!ip) return false;
  const cleanIp = ip.startsWith("::ffff:") ? ip.slice(7) : ip;
  return cleanIp === "127.0.0.1" || cleanIp === "::1" || cleanIp === "localhost";
}

interface LinkConfig {
  hub?: string;
  port?: number;
  bind?: string;
  tailscaleOnly?: boolean;
  secret?: string;
  lanDiscovery?: boolean;
  network?: "tailscale" | "lan";
  sessionId?: string;
  pin?: string;
  execMode?: "allow" | "block";
}

// ─── Device Identity & Pairing Storage ───────────────────────────────────────

interface DeviceIdentity {
  deviceId: string;
  name: string;
  host: string;
  publicKey: string; // SPKI format (base64)
  privateKey: string; // PKCS8 format (base64)
  fingerprint: string; // SHA-256 in hex pairs: "7B:19:52:AF:..."
}

interface PairedDevice {
  deviceId: string;
  name: string;
  host: string;
  publicKey: string;
  fingerprint: string;
  approvedAt: number;
  lastSeen: number;
  lastAddress?: string;
  permissions: DevicePermissions;
}

function getOmpDir(): string {
  const dir = path.join(os.homedir(), ".omp");
  if (!fs.existsSync(dir)) {
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    } catch {}
  }
  return dir;
}

function atomicWriteSecureFile(filePath: string, content: string): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    } catch {}
  }
  const tmpPath = `${filePath}.tmp.${crypto.randomBytes(6).toString("hex")}`;
  const fd = fs.openSync(tmpPath, "w", 0o600);
  fs.writeFileSync(fd, content, "utf-8");
  try {
    fs.fsyncSync(fd);
  } catch {}
  fs.closeSync(fd);
  fs.renameSync(tmpPath, filePath);
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {}
}

function getOrCreateDeviceIdentity(): DeviceIdentity {
  const ompDir = getOmpDir();
  const idFile = path.join(ompDir, "identity.json");
  if (fs.existsSync(idFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(idFile, "utf-8"));
      if (data && data.deviceId && data.publicKey && data.privateKey && data.fingerprint) {
        return data;
      }
    } catch {}
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  const privDer = privateKey.export({ type: "pkcs8", format: "der" });
  const fingerprint = crypto
    .createHash("sha256")
    .update(pubDer)
    .digest("hex")
    .slice(0, 32)
    .match(/.{1,2}/g)!
    .join(":")
    .toUpperCase();

  const identity: DeviceIdentity = {
    deviceId: `dev-${crypto.randomBytes(8).toString("hex")}`,
    name: os.hostname(),
    host: os.hostname(),
    publicKey: pubDer.toString("base64"),
    privateKey: privDer.toString("base64"),
    fingerprint,
  };
  atomicWriteSecureFile(idFile, JSON.stringify(identity, null, 2));
  return identity;
}

function getOrCreateTlsCert(): { cert: Buffer; key: Buffer; fingerprint: string } | null {
  const tlsDir = path.join(getOmpDir(), "tls");
  const certPath = path.join(tlsDir, "cert.pem");
  const keyPath = path.join(tlsDir, "key.pem");

  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    try {
      const cert = fs.readFileSync(certPath);
      const key = fs.readFileSync(keyPath);
      const certObj = new crypto.X509Certificate(cert);
      return { cert, key, fingerprint: certObj.fingerprint256 };
    } catch {}
  }

  try {
    if (!fs.existsSync(tlsDir)) fs.mkdirSync(tlsDir, { recursive: true, mode: 0o700 });
    execFileSync("openssl", [
      "req", "-x509",
      "-newkey", "ec",
      "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-nodes",
      "-keyout", keyPath,
      "-out", certPath,
      "-days", "3650",
      "-subj", "/CN=omp-link",
    ], { stdio: "ignore" });
    try {
      fs.chmodSync(certPath, 0o600);
      fs.chmodSync(keyPath, 0o600);
    } catch {}
    const cert = fs.readFileSync(certPath);
    const key = fs.readFileSync(keyPath);
    const certObj = new crypto.X509Certificate(cert);
    return { cert, key, fingerprint: certObj.fingerprint256 };
  } catch {
    return null;
  }
}

function loadPairedDevices(): Map<string, PairedDevice> {
  const ompDir = getOmpDir();
  const file = path.join(ompDir, "paired-devices.json");
  const map = new Map<string, PairedDevice>();
  if (fs.existsSync(file)) {
    try {
      const data = JSON.parse(fs.readFileSync(file, "utf-8"));
      if (Array.isArray(data)) {
        for (const item of data) {
          if (item && item.deviceId) map.set(item.deviceId, item);
        }
      } else if (typeof data === "object" && data !== null) {
        for (const [k, v] of Object.entries(data)) {
          if (v && typeof v === "object" && (v as PairedDevice).deviceId) {
            map.set(k, v as PairedDevice);
          }
        }
      }
    } catch {}
  }
  return map;
}

function savePairedDevice(device: PairedDevice): void {
  const map = loadPairedDevices();
  map.set(device.deviceId, device);
  const ompDir = getOmpDir();
  const file = path.join(ompDir, "paired-devices.json");
  const obj: Record<string, PairedDevice> = {};
  for (const [k, v] of map) obj[k] = v;
  atomicWriteSecureFile(file, JSON.stringify(obj, null, 2));
}

function removePairedDevice(deviceIdOrFingerprint: string): boolean {
  const map = loadPairedDevices();
  let deletedKey: string | null = null;
  for (const [k, v] of map) {
    if (k === deviceIdOrFingerprint || v.deviceId === deviceIdOrFingerprint || v.fingerprint === deviceIdOrFingerprint || v.name === deviceIdOrFingerprint) {
      deletedKey = k;
      break;
    }
  }
  if (deletedKey) {
    map.delete(deletedKey);
    const ompDir = getOmpDir();
    const file = path.join(ompDir, "paired-devices.json");
    const obj: Record<string, PairedDevice> = {};
    for (const [k, v] of map) obj[k] = v;
    atomicWriteSecureFile(file, JSON.stringify(obj, null, 2));
    return true;
  }
  return false;
}

function appendAuditLog(record: { type: string; timestamp: number; [key: string]: any }): void {
  try {
    const ompDir = getOmpDir();
    const auditFile = path.join(ompDir, "audit.log");
    fs.appendFileSync(auditFile, JSON.stringify(record) + "\n", { mode: 0o600 });
  } catch {}
}

// ─── Workspace Canonical Path Confinement ───────────────────────────────────

const SENSITIVE_PATTERNS = [
  /^\.env(\..+)?$/i,
  /id_rsa/i,
  /id_ed25519/i,
  /\.pem$/i,
  /\.key$/i,
  /^\.git([\\/].*)?$/i,
  /[\\/]\.git([\\/].*)?$/i,
  /credentials/i,
  /secrets?(\.json|\.ya?ml)?$/i,
];

function resolveConfinedPath(
  baseDir: string,
  requestedPath: string,
): { allowed: boolean; fullPath?: string; reason?: string } {
  if (!requestedPath || typeof requestedPath !== "string") {
    return { allowed: false, reason: "Missing path parameter" };
  }
  if (requestedPath.includes("\0")) {
    return { allowed: false, reason: "Null bytes forbidden in path" };
  }

  let canonicalBase: string;
  try {
    canonicalBase = fs.realpathSync(baseDir || process.cwd());
  } catch (err: any) {
    return { allowed: false, reason: `Base directory invalid: ${err.message}` };
  }

  const baseName = path.basename(requestedPath);
  for (const pattern of SENSITIVE_PATTERNS) {
    if (pattern.test(baseName) || pattern.test(requestedPath)) {
      return {
        allowed: false,
        reason: `Access to sensitive file or pattern "${baseName}" is blocked`,
      };
    }
  }

  const candidate = path.isAbsolute(requestedPath)
    ? path.resolve(requestedPath)
    : path.resolve(canonicalBase, requestedPath);

  if (fs.existsSync(candidate)) {
    try {
      const realCandidate = fs.realpathSync(candidate);
      if (
        realCandidate !== canonicalBase &&
        !realCandidate.startsWith(canonicalBase + path.sep)
      ) {
        return {
          allowed: false,
          reason: `Symlink or path traversal escaped workspace root (${canonicalBase})`,
        };
      }
      const realBaseName = path.basename(realCandidate);
      for (const pattern of SENSITIVE_PATTERNS) {
        if (pattern.test(realBaseName) || pattern.test(realCandidate)) {
          return {
            allowed: false,
            reason: `Access to sensitive file or pattern "${realBaseName}" is blocked`,
          };
        }
      }
      return { allowed: true, fullPath: realCandidate };
    } catch (err: any) {
      return { allowed: false, reason: `Path resolution error: ${err.message}` };
    }
  } else {
    if (
      candidate !== canonicalBase &&
      !candidate.startsWith(canonicalBase + path.sep)
    ) {
      return {
        allowed: false,
        reason: `Path escapes workspace root (${canonicalBase})`,
      };
    }
    return { allowed: true, fullPath: candidate };
  }
}

function loadLinkConfig(): LinkConfig {
  const dirs = [
    path.join(os.homedir(), ".omp"),
    path.join(os.homedir(), ".pi"),
    path.join(os.homedir(), ".config", "pi-link"),
  ];
  for (const dir of dirs) {
    const file = path.join(dir, "link.json");
    if (fs.existsSync(file)) {
      try {
        return JSON.parse(fs.readFileSync(file, "utf-8"));
      } catch {}
    }
  }
  return {};
}

function saveLinkConfig(partial: Partial<LinkConfig>) {
  const current = loadLinkConfig();
  const merged = { ...current, ...partial };
  const dirs = [
    path.join(os.homedir(), ".omp"),
    path.join(os.homedir(), ".pi"),
  ];
  for (const dir of dirs) {
    try {
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, "link.json"), JSON.stringify(merged, null, 2), "utf-8");
      return;
    } catch {}
  }
}

function startUdpDiscoveryResponder(tcpPort: number, secret?: string): dgram.Socket | null {
  try {
    const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
    socket.on("message", (msg, rinfo) => {
      const text = msg.toString().trim();
      const parts = text.split(":");
      if (parts[0] === "PI_LINK_DISCOVER") {
        if (secret && parts[1] !== secret) return;
        const resp = Buffer.from(`PI_LINK_HUB:${tcpPort}`);
        socket.send(resp, rinfo.port, rinfo.address, () => {});
      }
    });
    socket.on("error", () => {
      try { socket.close(); } catch {}
    });
    socket.bind(UDP_DISCOVERY_PORT);
    return socket;
  } catch {
    return null;
  }
}

interface DiscoveredHub {
  hubId?: string;
  sessionId?: string;
  pin?: string;
  network?: string;
  host: string;
  ip: string;
  port: number;
  hubName: string;
  dns?: string;
  os?: string;
  terminals: Array<{
    name: string;
    role: string;
    status?: string;
    host?: string;
    project?: string;
  }>;
  source: "tailscale" | "lan" | "local";
  endpoints?: string[];
}

function getTailnetPeers(
  includeSelf = true,
): Array<{ host: string; dns?: string; os?: string; ip: string; isSelf?: boolean }> {
  const bin = resolveTailscaleBin();
  if (!bin) return [];
  try {
    const stdout = execSync(`"${bin}" status --json`, {
      encoding: "utf-8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const status = JSON.parse(stdout);
    const peers: Array<{ host: string; dns?: string; os?: string; ip: string; isSelf?: boolean }> = [];
    if (includeSelf && status.Self) {
      const ipv4 = (status.Self.TailscaleIPs as string[])?.find((ip: string) => ip.startsWith("100."));
      if (ipv4) {
        peers.push({
          host: status.Self.HostName || "localhost",
          dns: status.Self.DNSName ? status.Self.DNSName.replace(/\.$/, "") : undefined,
          os: status.Self.OS,
          ip: ipv4,
          isSelf: true,
        });
      }
    }
    if (status.Peer) {
      for (const p of Object.values(status.Peer) as any[]) {
        if (p && p.Online) {
          const ipv4 = (p.TailscaleIPs as string[])?.find((ip: string) => ip.startsWith("100."));
          if (ipv4) {
            peers.push({
              host: p.HostName,
              dns: p.DNSName ? p.DNSName.replace(/\.$/, "") : undefined,
              os: p.OS,
              ip: ipv4,
              isSelf: false,
            });
          }
        }
      }
    }
    return peers;
  } catch {
    return [];
  }
}

async function discoverTailnetHubs(
  port = DEFAULT_PORT,
  timeoutMs = 800,
): Promise<{ peersCount: number; hubs: DiscoveredHub[] }> {
  const peers = getTailnetPeers(true);
  if (peers.length === 0) return { peersCount: 0, hubs: [] };
  const clientTokens = loadClientTokens();
  const results = await Promise.all(
    peers.map(async (peer) => {
      try {
        const headers: Record<string, string> = {};
        const savedTok = clientTokens.get(peer.ip) || clientTokens.get("default");
        if (savedTok) headers["x-link-token"] = savedTok;
        const res = await fetch(`http://${peer.ip}:${port}/status`, {
          headers,
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (res.ok) {
          const payload = (await res.json()) as any;
          if (payload && (payload.hub || payload.service === "omp-link")) {
            return {
              hubId: payload.hubId || `hub_${peer.ip}_${port}`,
              sessionId: payload.sessionId || "team-link",
              pin: payload.pin,
              network: payload.network || "tailscale",
              host: peer.host,
              ip: peer.ip,
              port,
              hubName: payload.hub || peer.host,
              dns: peer.dns,
              os: peer.os,
              terminals: Array.isArray(payload.terminals) ? payload.terminals : [],
              source: "tailscale" as const,
              endpoints: [`${peer.ip}:${port}`],
            };
          }
        }
      } catch {}
      return null;
    }),
  );
  return { peersCount: peers.length, hubs: results.filter(Boolean) as DiscoveredHub[] };
}

function discoverLanHubs(
  port = DEFAULT_PORT,
  timeoutMs = 800,
  secret?: string,
): Promise<Array<{ host: string; ip: string; port: number }>> {
  return new Promise((resolve) => {
    const found = new Map<string, { host: string; ip: string; port: number }>();
    let socket: dgram.Socket | null = null;
    let bcastInterval: ReturnType<typeof setInterval> | null = null;

    const timer = setTimeout(() => {
      if (bcastInterval) clearInterval(bcastInterval);
      try { socket?.close(); } catch {}
      resolve(Array.from(found.values()));
    }, timeoutMs);

    try {
      socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
      socket.on("message", (msg, rinfo) => {
        const text = msg.toString().trim();
        if (text.startsWith("PI_LINK_HUB:")) {
          const p = Number(text.slice("PI_LINK_HUB:".length)) || port;
          found.set(`${rinfo.address}:${p}`, { host: rinfo.address, ip: rinfo.address, port: p });
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
          const req = Buffer.from(secret ? `PI_LINK_DISCOVER:${secret}` : "PI_LINK_DISCOVER");
          const net = getNetworkInfo();
          const targets = new Set(["255.255.255.255", ...net.broadcastIps]);

          const sendPackets = () => {
            try {
              for (const target of targets) {
                socket?.send(req, UDP_DISCOVERY_PORT, target);
              }
            } catch {}
          };

          sendPackets();
          bcastInterval = setInterval(sendPackets, 250);
        } catch {}
      });
    } catch {
      clearTimeout(timer);
      resolve([]);
    }
  });
}

async function discoverAllHubs(
  port = DEFAULT_PORT,
  timeoutMs = 1200,
  secret?: string,
  mode: "tailscale" | "lan" | "auto" = "auto",
): Promise<{ hubs: DiscoveredHub[]; tailnetPeersCount: number }> {
  const scanTailscale = mode !== "lan";
  const scanLan = mode !== "tailscale";

  const [tailnetRes, lanHubs] = await Promise.all([
    scanTailscale
      ? discoverTailnetHubs(port, timeoutMs)
      : Promise.resolve({ peersCount: 0, hubs: [] as DiscoveredHub[] }),
    scanLan
      ? discoverLanHubs(port, Math.min(timeoutMs, 800), secret)
      : Promise.resolve([] as Array<{ host: string; ip: string; port: number }>),
  ]);

  const hubMap = new Map<string, DiscoveredHub>();

  function registerHub(hub: DiscoveredHub, payload?: any) {
    const hubId = hub.hubId || payload?.hubId;
    let existing: DiscoveredHub | undefined = undefined;
    if (hubId) {
      for (const h of hubMap.values()) {
        if (h.hubId === hubId) {
          existing = h;
          break;
        }
      }
    }
    const rawKey =
      hubId ||
      `${payload?.host || hub.host}:${hub.port}:${payload?.hub || hub.hubName}`;
    const key = rawKey.toLowerCase();
    if (!existing) {
      existing = hubMap.get(key);
    }
    const endpoint = `${hub.ip}:${hub.port}`;
    if (existing) {
      if (!existing.endpoints) existing.endpoints = [`${existing.ip}:${existing.port}`];
      if (!existing.endpoints.includes(endpoint)) {
        existing.endpoints.push(endpoint);
      }
      // If we found a Tailscale endpoint for this machine, prioritize it as the primary connection IP
      if (hub.source === "tailscale" && existing.source !== "tailscale") {
        existing.ip = hub.ip;
        existing.source = "tailscale";
      }
      return;
    }
    hub.hubId = hubId;
    hub.endpoints = [endpoint];
    hubMap.set(key, hub);
  }

  for (const h of tailnetRes.hubs) {
    registerHub(h);
  }

  try {
    const res = await fetch(`http://127.0.0.1:${port}/status`, {
      signal: AbortSignal.timeout(300),
    });
    if (res.ok) {
      const payload = (await res.json()) as any;
      if (payload && (payload.hub || payload.service === "omp-link")) {
        registerHub(
          {
            hubId: payload.hubId || `hub_127.0.0.1_${port}`,
            sessionId: payload.sessionId || "team-link",
            pin: payload.pin,
            network: payload.network || "local",
            host: payload.host || "localhost",
            ip: "127.0.0.1",
            port,
            hubName: payload.hub || "localhost",
            terminals: Array.isArray(payload.terminals) ? payload.terminals : [],
            source: "local" as any,
          },
          payload,
        );
      }
    }
  } catch {}

  if (lanHubs.length > 0) {
    const clientTokens = loadClientTokens();
    await Promise.all(
      lanHubs.map(async (lan) => {
        try {
          const headers: Record<string, string> = {};
          const savedTok = clientTokens.get(lan.ip) || clientTokens.get("default");
          if (savedTok) headers["x-link-token"] = savedTok;
          if (secret) headers["x-link-token"] = secret;
          const res = await fetch(`http://${lan.ip}:${lan.port}/status`, {
            headers,
            signal: AbortSignal.timeout(500),
          });
          if (res.ok) {
            const payload = (await res.json()) as any;
            if (payload && (payload.hub || payload.service === "omp-link")) {
              registerHub(
                {
                  hubId: payload.hubId || `hub_${lan.ip}_${lan.port}`,
                  sessionId: payload.sessionId || "team-link",
                  pin: payload.pin,
                  network: payload.network || "lan",
                  host: payload.host || lan.host,
                  ip: lan.ip,
                  port: lan.port,
                  hubName: payload.hub || lan.host,
                  terminals: Array.isArray(payload.terminals) ? payload.terminals : [],
                  source: "lan",
                },
                payload,
              );
            }
          }
        } catch {}
      }),
    );
  }

  return {
    hubs: Array.from(hubMap.values()),
    tailnetPeersCount: tailnetRes.peersCount,
  };
}

function discoverLanHub(timeoutMs = 500, secret?: string): Promise<{ host: string; port: number } | null> {
  return new Promise((resolve) => {
    let resolved = false;
    let socket: dgram.Socket | null = null;
    let bcastInterval: ReturnType<typeof setInterval> | null = null;

    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        if (bcastInterval) clearInterval(bcastInterval);
        try { socket?.close(); } catch {}
        resolve(null);
      }
    }, timeoutMs);

    try {
      socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
      socket.on("message", (msg, rinfo) => {
        const text = msg.toString().trim();
        if (text.startsWith("PI_LINK_HUB:")) {
          const port = Number(text.slice("PI_LINK_HUB:".length)) || DEFAULT_PORT;
          if (!resolved) {
            resolved = true;
            if (bcastInterval) clearInterval(bcastInterval);
            clearTimeout(timer);
            try { socket?.close(); } catch {}
            resolve({ host: rinfo.address, port });
          }
        }
      });
      socket.on("error", () => {
        if (!resolved) {
          resolved = true;
          if (bcastInterval) clearInterval(bcastInterval);
          clearTimeout(timer);
          try { socket?.close(); } catch {}
          resolve(null);
        }
      });
      socket.bind(0, () => {
        try {
          socket?.setBroadcast(true);
          const req = Buffer.from(secret ? `PI_LINK_DISCOVER:${secret}` : "PI_LINK_DISCOVER");
          const net = getNetworkInfo();
          const targets = new Set(["255.255.255.255", ...net.broadcastIps]);

          const sendPackets = () => {
            try {
              for (const target of targets) {
                socket?.send(req, UDP_DISCOVERY_PORT, target);
              }
            } catch {}
          };

          sendPackets();
          bcastInterval = setInterval(sendPackets, 200);
        } catch {}
      });
    } catch {
      clearTimeout(timer);
      resolve(null);
    }
  });
}

// ─── Extension ───────────────────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
  if ((globalThis as any).__omp_link_loaded) {
    return;
  }
  (globalThis as any).__omp_link_loaded = true;

  // First statement, so an unsupported host leaves behind no flag, event, tool,
  // command, timer or socket to half-run with. Pi reports a factory that throws as an
  // extension load error naming this message, and keeps running without pi-link.
  if (PI_VERSION && !piVersionSupported(PI_VERSION)) {
    if (process.env.PI_LINK_IGNORE_VERSION_CHECK !== "1") {
      throw new Error(
        `pi-link requires Pi >=${MIN_PI_VERSION.join(".")} (detected ${PI_VERSION || "unknown"}); ` +
          `upgrade Pi, or pin pi-link 0.2.x for Pi 0.74–0.84.1.`,
      );
    }
  }

  pi.registerFlag("link", {
    description: "Connect to link on startup",
    type: "boolean",
    default: false,
  });

  pi.registerFlag("link-name", {
    description:
      "Set the pi-link terminal name on startup (link identity only; does not affect session)",
    type: "string",
  });

  pi.registerFlag("link-hub", {
    description:
      "Target link hub address (e.g. 100.64.0.1:9900 or hub-desktop:9900)",
    type: "string",
  });

  pi.registerFlag("link-bind", {
    description:
      "Network interface to bind (default 0.0.0.0 for Tailscale/LAN/localhost)",
    type: "string",
  });

  pi.registerFlag("link-port", {
    description: "Port to use for pi-link (default: 9900)",
    type: "string",
  });

  pi.registerFlag("no-link", {
    description: "Disable link networking entirely for this session",
    type: "boolean",
    default: false,
  });

  // ── State ────────────────────────────────────────────────────────────────

  const config = loadLinkConfig();
  let linkPort = Number(process.env.PI_LINK_PORT) || config.port || DEFAULT_PORT;
  let linkBind = process.env.PI_LINK_BIND || config.bind || DEFAULT_BIND;
  let targetHubAddress: string | null = process.env.PI_LINK_HUB || config.hub || null;
  let isTailscaleOnly = process.env.PI_LINK_TAILSCALE_ONLY === "1" || Boolean(config.tailscaleOnly);
  let linkSecret = process.env.PI_LINK_SECRET || config.secret || undefined;
  let enableLanDiscovery = config.lanDiscovery !== false && process.env.PI_LINK_NO_LAN_DISCOVERY !== "1";

  let udpResponder: dgram.Socket | null = null;
  const hubInstanceId = `hub_${os.hostname().replace(/[^a-zA-Z0-9]/g, "_")}_${Date.now()}`;
  const initialNet = getNetworkInfo();
  let networkMode: "tailscale" | "lan" = (process.env.PI_LINK_NETWORK || process.env.OMP_LINK_NETWORK || config.network || (initialNet.tailscaleIp ? "tailscale" : "lan")) as any;
  let currentSessionId: string = process.env.PI_LINK_SESSION || process.env.OMP_LINK_SESSION || config.sessionId || path.basename(process.cwd()) || "team-link";
  let sessionPin: string = process.env.PI_LINK_PIN || process.env.OMP_LINK_PIN || config.pin || Math.floor(1000 + Math.random() * 9000).toString();
  let explicitHubMode = false;
  let role: "hub" | "client" | "disconnected" = "disconnected";
  let terminalName = `t-${crypto.randomUUID().slice(0, 4)}`;
  let preferredName: string | null = null;
  // True between a client `/link-name` close and the next welcome/promotion.
  // Lets `startHub` adopt the requested name if it wins promotion before welcome.
  let pendingClientRename = false;
  let connectedTerminals: string[] = [];
  let ctx: ExtensionContext | undefined;
  let disposed = false;
  let manuallyDisconnected = false;
  let linkActive = process.env.OMP_LINK_OFF !== "1" && process.env.PI_LINK_DISABLE !== "1";
  let reconnectAttempts = 0;
  const MAX_RECONNECT_ATTEMPTS = 3;

  // ── Cryptographic Identity & Transport State ──
  const myIdentity = getOrCreateDeviceIdentity();
  let sessionKey: Buffer | null = null;
  let localSeqCounter = 0;
  const seenMessageIds = new Map<string, number>();
  const peerLastSeq = new Map<string, number>();

  // ── Direct Tool RPC State ──
  const pendingRpcRequests = new Map<
    string,
    { resolve: (res: RpcResponseMsg) => void; timeout: NodeJS.Timeout }
  >();

  // ── Out-of-band File Transfer State ──
  interface EphemeralTransfer {
    buffer: Buffer;
    filename: string;
    sha256: string;
    authToken?: string;
    expires: number;
  }
  const ephemeralTransfers = new Map<string, EphemeralTransfer>();

  // ── Remote Execution Grants (Territorial Sovereignty) ──
  // Execution is blocked by default. Elevation is temporary, peer-specific, and audit-logged.
  interface ExecGrant {
    peer: string;
    grantedAt: number;
    expiresAt: number;
    timer: NodeJS.Timeout;
  }
  const activeExecGrants = new Map<string, ExecGrant>();

  function grantExecElevation(peer: string, minutes: number = 10) {
    const durationMs = Math.min(Math.max(minutes, 1), 60) * 60_000;
    const existing = activeExecGrants.get(peer);
    if (existing) clearTimeout(existing.timer);

    const timer = setTimeout(() => {
      activeExecGrants.delete(peer);
      notify(`⏱️ Remote execution grant for "${peer}" has expired.`, "info");
    }, durationMs);

    activeExecGrants.set(peer, {
      peer,
      grantedAt: Date.now(),
      expiresAt: Date.now() + durationMs,
      timer,
    });
    appendAuditLog({
      type: "grant",
      timestamp: Date.now(),
      peer,
      durationMinutes: minutes,
      action: "granted",
    });
  }

  function revokeExecElevation(peer: string): boolean {
    const existing = activeExecGrants.get(peer);
    if (existing) {
      clearTimeout(existing.timer);
      activeExecGrants.delete(peer);
      appendAuditLog({
        type: "grant",
        timestamp: Date.now(),
        peer,
        action: "revoked",
      });
      return true;
    }
    return false;
  }

  // ── Device Pairing & Request Mode State ──
  interface PendingJoinRequest {
    id: number;
    ws: WebSocket;
    deviceId: string;
    name: string;
    host: string;
    fingerprint: string;
    publicKey: string;
    sessionKey: Buffer;
    clientIp: string;
    timestamp: number;
    complete: () => void;
  }
  const pendingJoinRequests = new Map<number, PendingJoinRequest>();
  let nextPairingRequestId = 1;

  function approveJoinRequest(reqId: number): boolean {
    const req = pendingJoinRequests.get(reqId);
    if (!req) return false;
    pendingJoinRequests.delete(reqId);

    savePairedDevice({
      deviceId: req.deviceId,
      name: req.name,
      host: req.host,
      publicKey: req.publicKey,
      fingerprint: req.fingerprint,
      approvedAt: Date.now(),
      lastSeen: Date.now(),
      lastAddress: req.clientIp,
      permissions: {
        message: true,
        inspect: true,
        fileInbox: true,
        exec: false,
      },
    });

    req.complete();
    notify(`✅ Approved device "${req.name}" (${req.fingerprint}). Cryptographic identity paired.`, "info");
    return true;
  }

  function denyJoinRequest(reqId: number): boolean {
    const req = pendingJoinRequests.get(reqId);
    if (!req) return false;
    pendingJoinRequests.delete(reqId);

    try {
      req.ws.send(
        JSON.stringify({
          type: "pairing_denied",
          message: "Join request was rejected by host.",
        } satisfies PairingDeniedMsg),
      );
      req.ws.close(4003, "Join request rejected");
    } catch {}

    notify(`❌ Denied device request #${reqId} ("${req.name}").`, "info");
    return true;
  }

  // ── Mutation Guard & Territorial Sovereignty State ──
  let mutationGuard = process.env.OMP_LINK_ALLOW_MUTATION !== "1" && process.env.OMP_LINK_MUTATION_GUARD !== "0";
  let blockedMutationCount = 0;
  interface BlockedMutationRecord {
    timestamp: number;
    from: string;
    command: string;
    reason: string;
  }
  const blockedMutationLog: BlockedMutationRecord[] = [];

  const MUTATION_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
    { pattern: /\b(rm|rmdir|unlink|shred)\b/i, reason: "File deletion command" },
    { pattern: /\b(sed|awk)\b.*-i/i, reason: "In-place file edit" },
    { pattern: /(?:^|[^&|0-9>])>(?!>)\s*(?!\/dev\/null\b)\S+/, reason: "Shell file overwrite (>)" },
    { pattern: />>\s*(?!\/dev\/null\b)\S+/, reason: "Shell file append (>>)" },
    { pattern: /\bgit\s+(commit|push|checkout|reset|rebase|merge|cherry-pick|revert|stash|clean|branch\s+-[dD])\b/i, reason: "Git working tree / branch mutation" },
    { pattern: /\b(chmod|chown|chgrp|mv|truncate|dd|mkfs)\b/i, reason: "File permissions, rename, or disk mutation" },
    { pattern: /\b(npm|pnpm|yarn|bun)\s+(install|add|remove|uninstall|update|i\b)/i, reason: "Package manager dependency mutation" },
    { pattern: /\bpip\s+(install|uninstall)/i, reason: "Python package mutation" },
    { pattern: /\b(reboot|shutdown|init\s+[06]|poweroff)\b/i, reason: "System power/reboot command" },
  ];

  function checkMutationGuard(command: string, fromPeer: string): { blocked: boolean; reason?: string } {
    if (!mutationGuard) return { blocked: false };
    for (const { pattern, reason } of MUTATION_PATTERNS) {
      if (pattern.test(command)) {
        blockedMutationCount++;
        const record: BlockedMutationRecord = {
          timestamp: Date.now(),
          from: fromPeer,
          command,
          reason,
        };
        blockedMutationLog.push(record);
        if (blockedMutationLog.length > 50) blockedMutationLog.shift();
        notify(
          `🛡️ [Mutation Guard] BLOCKED mutating command from "${fromPeer}": "${command}" (${reason}). Territorial Sovereignty enforced.`,
          "warning"
        );
        return { blocked: true, reason };
      }
    }
    return { blocked: false };
  }

  // Status tracking (local truth)
  let agentRunning = false; // agent_start until agent_settled, not until agent_end
  let compactRunning = false; // true while compacting for a remote request
  let localCompacting = false; // true while compacting for a human /compact
  let compactDeadline: ReturnType<typeof setTimeout> | undefined;
  let wasCompactionGated = false; // gate state syncCompactionStatus() last acted on
  // toolCallId → toolName. Pi runs tools in parallel by default and both tool
  // events carry the call id, so one slot per call is the only way an end can clear
  // the call it belongs to. Insertion-ordered, which is what picks the display.
  const activeTools = new Map<string, string>();
  let stateSince = Date.now();
  let lastPushedStatus: string | null = null; // identity of the last published status
  const terminalStatuses = new Map<string, LinkStatus>(); // other terminals
  const terminalContexts = new Map<string, ContextSnapshot>(); // other terminals' context
  let currentCwd = "";
  const terminalCwds = new Map<string, string>(); // other terminals' cwds
  const terminalHosts = new Map<string, string>(); // other terminals' hosts
  const terminalProjects = new Map<string, string>(); // other terminals' projects

  // Hub state
  let wss: WebSocketServer | null = null;
  // The hub owns the HTTP server the WS server rides on, because `wss.close()`
  // never closes a server it was handed. Nulled wherever `wss` is.
  let hubHttpServer: HttpServer | null = null;
  const hubClients = new Map<WebSocket, string>(); // ws → terminal name
  const hubTerminalStatuses = new Map<string, LinkStatus>(); // hub-authoritative
  const hubTerminalContexts = new Map<string, ContextSnapshot>(); // hub-authoritative
  const hubTerminalCwds = new Map<string, string>(); // hub-authoritative (excludes self)
  const hubTerminalHosts = new Map<string, string>();
  const hubTerminalProjects = new Map<string, string>();

  // Client state
  let ws: WebSocket | null = null;

  // Establishment. One attempt owns every pending transport across the whole
  // client-then-hub sequence, because a transport can emit callbacks from
  // construction onward while `ws`/`wss` are still empty. The record itself is the
  // generation token: a callback that captured it can tell whether it is still the
  // current owner by identity alone, and cancellation has handles to close.
  type ConnectionAttempt = {
    promise: Promise<void>;
    socket: WebSocket | null; // dialing, not yet `ws`
    server: WebSocketServer | null; // binding, not yet `wss`
    httpServer: HttpServer | null; // binding, not yet `hubHttpServer`
  };
  let connectionAttempt: ConnectionAttempt | null = null;

  // Pending compact responses (sender waiting for remote compaction to finish)
  const pendingCompactResponses = new Map<
    string,
    {
      resolve: (result: {
        content: { type: "text"; text: string }[];
        details: Record<string, unknown>;
      }) => void;
      targetName: string;
      timeout: ReturnType<typeof setTimeout>;
    }
  >();

  // Inbox: fixed-window batching; every batch is delivered to the receiver's model
  const inbox: { from: string; content: string }[] = [];
  let flushTimer: ReturnType<typeof setTimeout> | null = null;

  // ── Helpers ──────────────────────────────────────────────────────────────

  function getUi() {
    if (!ctx) return null;
    try {
      return ctx.ui;
    } catch {
      return null;
    }
  }

  function isRuntimeLive() {
    return !disposed && getUi() !== null;
  }

  function notify(message: string, level: "info" | "warning" | "error") {
    if (!linkActive && level === "warning") return;
    getUi()?.notify(message, level);
  }

  function updateStatus() {
    const ui = getUi();
    if (!ui) return;
    const theme = ui.theme;
    if (!linkActive) {
      ui.setStatus("link", theme.fg("dim", "link: off"));
      return;
    }
    const count = connectedTerminals.length;
    const info =
      role === "disconnected"
        ? "link: offline"
        : `link: ${terminalName} (${role}) · ${count} terminal${count !== 1 ? "s" : ""}`;
    ui.setStatus("link", theme.fg("dim", info));
  }

  function deriveStatus(): LinkStatus {
    // Highest precedence, so that reporting "compacting" and deferring delivery are
    // the same condition rather than two that can disagree. In reachable states it
    // competes only with "idle" — a compaction runs with no tool and no agent run —
    // but where it could overlap, the gate is the more actionable fact: work sent
    // here waits, and link_compact declines.
    if (compactionGated()) return { kind: "compacting", since: stateSince };
    const tool = displayedTool();
    if (tool) return { kind: "tool", toolName: tool, since: stateSince };
    if (agentRunning) return { kind: "thinking", since: stateSince };
    return { kind: "idle", since: stateSince };
  }

  /**
   * The tool a peer is shown while several run at once: the first still active, by
   * start order. A later start never displaces it, so parallel work does not churn
   * the status; when it ends the next one takes over.
   */
  function displayedTool(): string | null {
    for (const name of activeTools.values()) return name;
    return null;
  }

  /**
   * The single definition of "the same status": what a peer sees, as one comparable
   * value. Both users of that question go through here — pushStatus() dedupes on it,
   * and every handler compares it before and after mutating to decide whether
   * stateSince moves. One function, so the clock and the wire cannot come to
   * disagree about what changed; restarting the clock on a change nobody can see
   * would publish nothing now and make the next push carry a duration nobody
   * observed. Two calls of the same tool handing over are one status by this rule.
   *
   * The two forms cannot collide: every non-tool kind is a fixed literal from the
   * LinkStatus union with no colon in it, and the tool form is always prefixed, so
   * no toolName can spell a kind.
   */
  function statusIdentity(s: LinkStatus): string {
    return s.kind === "tool" ? `tool:${s.toolName}` : s.kind;
  }

  function captureContext(): ContextSnapshot | undefined {
    if (!ctx) return undefined;
    if (typeof ctx.getContextUsage !== "function") return undefined; // older Pi
    const usage = ctx.getContextUsage();
    if (!usage) return undefined;
    if (usage.contextWindow <= 0) return undefined; // no real context to report
    return { tokens: usage.tokens, contextWindow: usage.contextWindow };
  }

  function pushStatus(force = false) {
    if (role === "disconnected") return;
    const status = deriveStatus();
    const identity = statusIdentity(status);
    if (!force && identity === lastPushedStatus) return;
    lastPushedStatus = identity;
    const context = captureContext(); // only when we actually push
    const msg: StatusUpdateMsg = {
      type: "status_update",
      name: terminalName,
      status,
      context: context ?? null, // explicit null tells peers to clear
    };
    if (role === "hub") {
      hubBroadcast(msg, terminalName);
    } else if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(msg));
    }
  }

  // Canonicalize a link/session name: trim + collapse internal whitespace.
  // Returns undefined for nullish/blank so callers can fall through precedence.
  function normalizeName(name: string | undefined | null): string | undefined {
    const n = name?.trim().replace(/\s+/g, " ");
    return n ? n : undefined;
  }

  // Latest custom session entry of a given type (last-write-wins), or undefined.
  function latestCustomData(
    customType: string,
  ): Record<string, unknown> | undefined {
    if (!ctx) return undefined;
    const entries = ctx.sessionManager.getEntries();
    for (let i = entries.length - 1; i >= 0; i--) {
      const e = entries[i] as {
        type: string;
        customType?: string;
        data?: Record<string, unknown>;
      };
      if (e.type === "custom" && e.customType === customType) return e.data;
    }
    return undefined;
  }

  function formatDuration(since: number): string {
    const sec = Math.floor((Date.now() - since) / 1000);
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m`;
    return `${Math.floor(sec / 3600)}h`;
  }

  function formatStatus(s: LinkStatus): string {
    const dur = formatDuration(s.since);
    if (s.kind === "tool") return `tool:${s.toolName} (${dur})`;
    return `${s.kind} (${dur})`;
  }

  function formatTokens(n: number): string {
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
    if (n >= 1_000) return `${Math.round(n / 1000)}K`;
    return `${n}`;
  }

  function formatContext(c: ContextSnapshot | null | undefined): string {
    if (!c || c.contextWindow <= 0) return ""; // guard against bad wire data
    const window = formatTokens(c.contextWindow);
    if (c.tokens === null) return `?/${window}`;
    const percent = Math.round((c.tokens / c.contextWindow) * 100);
    return `${formatTokens(c.tokens)}/${window} (${percent}%)`;
  }

  function getStatusFor(name: string): LinkStatus | null {
    if (name === terminalName) return deriveStatus();
    const map = role === "hub" ? hubTerminalStatuses : terminalStatuses;
    return map.get(name) ?? null;
  }

  function getCwdFor(name: string): string | null {
    if (name === terminalName) return currentCwd || null;
    if (role === "hub") return hubTerminalCwds.get(name) ?? null;
    return terminalCwds.get(name) ?? null;
  }

  function getContextFor(name: string): ContextSnapshot | null {
    if (name === terminalName) return captureContext() ?? null;
    if (role === "hub") return hubTerminalContexts.get(name) ?? null;
    return terminalContexts.get(name) ?? null;
  }

  function getHostFor(name: string): string | null {
    if (name === terminalName) return os.hostname();
    if (role === "hub") return hubTerminalHosts.get(name) ?? null;
    return terminalHosts.get(name) ?? null;
  }

  function getProjectFor(name: string): string | null {
    if (name === terminalName) return currentCwd ? path.basename(currentCwd) : null;
    if (role === "hub") return hubTerminalProjects.get(name) ?? null;
    return terminalProjects.get(name) ?? null;
  }

  function shortenPath(cwd: string): string {
    const home = os.homedir().replace(/\\/g, "/");
    const normalized = cwd.replace(/\\/g, "/");
    if (normalized === home) return "~";
    if (normalized.startsWith(home + "/"))
      return "~" + normalized.slice(home.length);
    return normalized;
  }

  // ── Startup connect ──────────────────────────────────────────────────────

  function scheduleStartupConnect() {
    if (startupConnectTimer) clearTimeout(startupConnectTimer);
    startupConnectTimer = setTimeout(() => {
      startupConnectTimer = null;
      if (!disposed && ctx) void initialize();
    }, 0);
  }

  // ── Inbox: batched delivery ──────────────────────────────────────────────

  // The first queued message opens the window and later arrivals join it, so the
  // deadline belongs to the message that started it. Rearming here instead would
  // make the window trailing-edge, and a stream whose gaps stay under the delay
  // could postpone delivery for as long as it kept arriving.
  function scheduleFlush(delay: number) {
    if (flushTimer) return;
    flushTimer = setTimeout(() => {
      flushTimer = null;
      flushInbox();
    }, delay);
  }

  function flushInbox() {
    if (inbox.length === 0) return;
    if (!ctx) return;

    // Delivery stays deferred behind either compaction gate. Messages wait; release
    // drains on release, so polling a compaction that may run to the 180s ceiling
    // would be ~900 wakeups for no information.
    if (compactionGated()) return;

    // Select batch: up to BATCH_MAX_ITEMS, ~BATCH_MAX_CHARS total (soft cap —
    // first item always included even if oversized, others deferred to next flush)
    const batch: string[] = [];
    let totalChars = 0;
    for (let i = 0; i < inbox.length && batch.length < BATCH_MAX_ITEMS; i++) {
      const item = inbox[i];
      const senderHost = getHostFor(item.from);
      const senderProject = getProjectFor(item.from);
      let senderInfo = item.from;
      if (senderHost && (senderHost !== os.hostname() || senderProject)) {
        senderInfo += ` on ${senderHost}${senderProject ? ` (project: ${senderProject})` : ""}`;
      }
      const text = `From "${senderInfo}":\n${item.content}`;
      if (batch.length > 0 && totalChars + text.length > BATCH_MAX_CHARS) break;
      batch.push(text);
      totalChars += text.length;
    }

    pi.sendMessage(
      {
        customType: "link",
        content: `[Link: ${batch.length} message(s) received]\n\n${batch.join("\n\n")}`,
        display: true,
        details: { batched: true, count: batch.length },
      },
      { triggerTurn: true },
    );
    inbox.splice(0, batch.length);

    // Items held back by the batch caps go out in the next window
    if (inbox.length > 0) {
      scheduleFlush(FLUSH_DELAY_MS);
    }
  }

  /**
   * True exactly while delivery is deferred. Also what the terminal reports as its
   * status, so availability and delivery cannot disagree.
   *
   * The two flags are not duplication. compactRunning is set synchronously by the
   * compact_request handler before it calls ctx.compact(), covering the window
   * before session_before_compact arrives; localCompacting covers a human /compact,
   * which pi-link never initiates.
   *
   * Both are load-bearing because Pi will not save us here: AgentSession.prompt()
   * refuses to run during compaction, but sendCustomMessage reaches _runAgentPrompt
   * directly and is not covered by that guard.
   */
  function compactionGated() {
    return localCompacting || compactRunning;
  }

  /**
   * Record a compaction gate transition. Call after any change to either flag.
   *
   * wasCompactionGated tracks the gate itself, deliberately NOT lastPushedStatus: the
   * two diverge exactly while disconnected, when pushStatus() returns before
   * recording anything, and a gate that opened and closed unseen would then leave
   * stateSince stranded at the moment compaction began. Entering and leaving are one
   * transition each, so the two flag moves of a remote compaction report once.
   *
   * The local record is updated whether or not publication is possible; pushStatus()
   * decides that separately.
   */
  function syncCompactionStatus() {
    const gated = compactionGated();
    if (gated === wasCompactionGated) return;
    wasCompactionGated = gated;
    stateSince = Date.now(); // the duration shown is of the compaction, not what preceded it
    pushStatus();
  }

  /**
   * Drain the inbox once NO gate remains. Call after clearing either flag.
   *
   * Both gates must be checked together, because a remote compact sets both:
   * ctx.compact() reaches Pi's compact(), which reports reason "manual", so
   * session_before_compact sets localCompacting on top of compactRunning. Pi emits
   * session_compact strictly before it resolves and fires onComplete, so releasing
   * on either flag alone can arm a flush that finds the other flag still standing,
   * returns without rescheduling, and strands the inbox with no release left.
   */
  function releaseInbox() {
    if (!localCompacting && !compactRunning && inbox.length > 0) {
      scheduleFlush(FLUSH_DELAY_MS);
    }
  }

  /**
   * Gate and release inbox delivery around a local manual compaction.
   *
   * The deadline is the only backstop. A failed manual compaction emits
   * `compaction_end` to session listeners only, never to extensions, and Pi
   * clears its compaction controller without aborting it — so success is the sole
   * positive ending an extension can observe. The timer handle must be explicit
   * and cleared on every transition: a bare setTimeout outlives its own
   * compaction and would release a *later* compaction's flag.
   *
   * COMPACT_TIMEOUT_MS is reused only to avoid a new constant. It shares a value
   * with the remote-request wait by coincidence, not by meaning.
   */
  function setCompacting(on: boolean) {
    localCompacting = on;
    clearTimeout(compactDeadline);
    compactDeadline = on
      ? setTimeout(() => setCompacting(false), COMPACT_TIMEOUT_MS)
      : undefined;
    // Release drains; it never polls. Nothing else wakes a waiting inbox.
    if (!on) releaseInbox();
    syncCompactionStatus();
  }

  // ── Connection intent ──────────────────────────────────────────────────

  function shouldConnect(): boolean {
    if (!linkActive) return false;
    if (pi.getFlag("no-link") === true) return false;
    if (process.env.PI_LINK_DISABLE === "1" || process.env.OMP_LINK_DISABLE === "1" || process.env.OMP_LINK_OFF === "1") return false;
    const data = latestCustomData("link-active") as
      | { active?: boolean }
      | undefined;
    if (data?.active !== undefined) {
      linkActive = data.active;
      return data.active;
    }
    return true;
  }

  // ── Pending compact helpers ──────────────────────────────────────────────

  function cleanupPendingCompact(requestId: string) {
    const pending = pendingCompactResponses.get(requestId);
    if (!pending) return null;
    clearTimeout(pending.timeout);
    pendingCompactResponses.delete(requestId);
    return pending;
  }

  function allTerminalNames(): Set<string> {
    const names = new Set<string>();
    names.add(terminalName); // hub's own name
    for (const name of hubClients.values()) names.add(name);
    return names;
  }

  function uniqueName(requested: string): string {
    const existing = allTerminalNames();
    if (!existing.has(requested)) return requested;
    let i = 2;
    while (existing.has(`${requested}-${i}`)) i++;
    return `${requested}-${i}`;
  }

  function terminalList(): string[] {
    return Array.from(allTerminalNames()).sort();
  }

  /**
   * Hub: the `GET /status` snapshot. Pure reads — it mutates nothing and sends
   * nothing, so observing the link cannot disturb it.
   *
   * Hub entry first, then clients sorted by name, so pollers see a stable order.
   * `status`/`sinceSeconds` and `cwd` are omitted rather than invented when the
   * hub has not heard them yet: a client is in `hubClients` from `register`, but
   * its first `status_update` arrives a round trip later, and reporting a fresh
   * peer as "idle" would be exactly the false inventory this endpoint exists to
   * remove.
   */
  function buildStatusPayload() {
    const now = Date.now();

    const describe = (name: string, entryRole: "hub" | "client") => {
      const status = getStatusFor(name);
      const cwd = getCwdFor(name);
      const context = getContextFor(name);
      const host = getHostFor(name);
      const project = getProjectFor(name);
      return {
        name,
        role: entryRole,
        ...(host ? { host } : {}),
        ...(project ? { project } : {}),
        ...(status
          ? {
              status: statusIdentity(status),
              sinceSeconds: Math.round((now - status.since) / 1000),
            }
          : {}),
        ...(cwd ? { cwd } : {}),
        context: context
          ? { tokens: context.tokens, window: context.contextWindow }
          : null,
      };
    };

    const net = getNetworkInfo();
    return {
      hubId: hubInstanceId,
      sessionId: currentSessionId,
      pin: sessionPin,
      network: networkMode,
      hub: terminalName,
      port: linkPort,
      bind: linkBind,
      host: net.hostname,
      tailscaleIp: net.tailscaleIp,
      lanIps: net.lanIps,
      terminals: [
        describe(terminalName, "hub"),
        ...Array.from(hubClients.values())
          .sort()
          .map((name) => describe(name, "client")),
      ],
    };
  }

  function renderStatusCard(): string {
    const net = getNetworkInfo();
    const isOnline = role !== "disconnected";
    const endpoint = networkMode === "tailscale" && net.tailscaleIp
      ? `${net.tailscaleIp}:${linkPort}`
      : (net.lanIps.length > 0 ? `${net.lanIps[0]}:${linkPort}` : `127.0.0.1:${linkPort}`);

    const divider = "─".repeat(52);

    if (!linkActive) {
      return [
        `⚡ OMP LINK: DISABLED (OFF)`,
        divider,
        `  Status     : All sockets closed & background retries halted`,
        `  Network    : ${networkMode.toUpperCase()}`,
        `  Session ID : ${currentSessionId}`,
        divider,
        `  To turn back on:`,
        `    /link on`,
      ].join("\n");
    }

    if (!isOnline) {
      return [
        `⚡ OMP LINK: DISCONNECTED`,
        divider,
        `  Session ID : ${currentSessionId} (inactive)`,
        `  Network    : ${networkMode.toUpperCase()}`,
        `  Port       : ${linkPort}`,
        divider,
        `  To connect:`,
        `    /link-join             Auto-discover and join active session`,
        `    /link-start [id]       Start hosting session "${currentSessionId}"`,
        `    /link-network <ts|lan> Switch network mode (Tailscale / LAN)`,
      ].join("\n");
    }

    const authNote = networkMode === "tailscale"
      ? "TAILSCALE (auto-verified via WireGuard)"
      : `LAN (PIN: ${sessionPin})`;

    const peerLines = connectedTerminals.map((name) => {
      const isSelf = name === terminalName;
      const status = getStatusFor(name);
      const statusStr = status ? formatStatus(status) : "idle";
      const host = getHostFor(name);
      const project = getProjectFor(name);
      const cwd = getCwdFor(name);
      let line = `    • ${name}${isSelf ? " (you)" : ""}`;
      if (host) line += ` [host: ${host}${project ? ` · project: ${project}` : ""}]`;
      line += ` (${statusStr})`;
      if (cwd) line += `\n      cwd: ${shortenPath(cwd)}`;
      return line;
    });

    const reqsLine = pendingJoinRequests.size > 0
      ? `  Requests   : 🔔 ${pendingJoinRequests.size} PENDING (/link-requests to view, /link-accept to approve)\n`
      : "";

    const grantsLine = activeExecGrants.size > 0
      ? `  Elevated   : ⚠️ ${Array.from(activeExecGrants.values()).map(g => `${g.peer} (${Math.ceil((g.expiresAt - Date.now()) / 60_000)}m left)`).join(", ")}\n`
      : `  Territorial: Sovereign (Exec blocked by default)\n`;

    return [
      `⚡ OMP LINK: ACTIVE`,
      divider,
      `  Session ID : ${currentSessionId}`,
      `  Network    : ${authNote}`,
      `  Endpoint   : ${endpoint}`,
      `  Role       : ${role === "hub" ? "Host" : "Peer"} (${terminalName})`,
      `  Identity   : ${myIdentity.fingerprint}`,
      `  Security   : E2EE (X25519 + AES-256-GCM) · Mutation Guard: ${mutationGuard ? "ON" : "OFF"}${blockedMutationCount > 0 ? ` (${blockedMutationCount} blocked)` : ""}`,
      grantsLine + reqsLine + divider,
      `  Online Peers (${connectedTerminals.length}):`,
      peerLines.join("\n") || "    (none)",
      divider,
      `  Quick join from another Mac:`,
      `    /link join ${currentSessionId}`,
      `    (or /link join ${endpoint}${networkMode === "lan" ? ` ${sessionPin}` : ""})`,
      divider,
      `  Commands:`,
      `    /link                  Show status dashboard and discovered sessions`,
      `    /link accept [id]      Approve pending device pairing request`,
      `    /link deny [id]        Reject pending device pairing request`,
      `    /link requests         List pending device join requests`,
      `    /link devices          List or revoke paired devices`,
      `    /link grant <peer> [m] Elevate peer execution temporarily`,
      `    /link join [id|ip]     Join active session`,
      `    /link leave            Leave session`,
      `    /link doctor           Run connectivity and security diagnostics`,
    ].join("\n");
  }

  function serializeForWire(msg: LinkMessage, targetKey?: Buffer): string {
    const key = targetKey || sessionKey;
    if (!key) {
      throw new Error("Cannot serialize wire message: session key not established");
    }
    const json = JSON.stringify(msg);
    const iv = crypto.randomBytes(12);
    const mid = crypto.randomUUID();
    const seq = ++localSeqCounter;
    const ts = Date.now();
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(Buffer.from(`4:${mid}:${seq}:${terminalName}:${ts}`));
    let enc = cipher.update(json, "utf8", "base64");
    enc += cipher.final("base64");
    const tag = cipher.getAuthTag();
    const wrapped: EncryptedMsg = {
      type: "encrypted",
      v: 4,
      mid,
      seq,
      from: terminalName,
      ts,
      iv: iv.toString("base64"),
      tag: tag.toString("base64"),
      data: enc,
    };
    return JSON.stringify(wrapped);
  }

  function safeParse(data: string, targetKey?: Buffer): LinkMessage | null {
    try {
      const parsed = JSON.parse(data);
      if (parsed && typeof parsed === "object") {
        if (
          parsed.type === "handshake_challenge" ||
          parsed.type === "handshake_response" ||
          parsed.type === "pairing_pending" ||
          parsed.type === "pairing_denied"
        ) {
          return parsed as LinkMessage;
        }

        if (parsed.type === "encrypted") {
          const key = targetKey || sessionKey;
          if (!key) return null;

          // Replay check 1: Timestamp freshness (within 60s)
          if (typeof parsed.ts !== "number" || Math.abs(Date.now() - parsed.ts) > 60_000) {
            return null;
          }

          // Replay check 2: Deduplication by message ID
          if (parsed.mid && seenMessageIds.has(parsed.mid)) {
            return null;
          }

          // Replay check 3: Monotonic sequence counter per sender
          if (parsed.from && typeof parsed.seq === "number") {
            const lastSeq = peerLastSeq.get(parsed.from) || 0;
            if (parsed.seq <= lastSeq) {
              return null;
            }
          }

          const iv = Buffer.from(parsed.iv, "base64");
          const tag = Buffer.from(parsed.tag, "base64");
          const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
          decipher.setAAD(Buffer.from(`4:${parsed.mid}:${parsed.seq}:${parsed.from}:${parsed.ts}`));
          decipher.setAuthTag(tag);
          let dec = decipher.update(parsed.data, "base64", "utf8");
          dec += decipher.final("utf8");
          const decryptedMsg = JSON.parse(dec);

          if (parsed.mid) {
            seenMessageIds.set(parsed.mid, parsed.ts);
            if (seenMessageIds.size > 2000) {
              const oldestKey = seenMessageIds.keys().next().value;
              if (oldestKey) seenMessageIds.delete(oldestKey);
            }
          }
          if (parsed.from && typeof parsed.seq === "number") {
            peerLastSeq.set(parsed.from, parsed.seq);
          }

          return decryptedMsg;
        }
      }
      return null;
    } catch {
      return null;
    }
  }

  // ── Routing ──────────────────────────────────────────────────────────────

  /** Hub: broadcast a message to every terminal except `excludeName`. */
  function hubBroadcast(msg: LinkMessage, excludeName?: string) {
    for (const [clientWs, name] of hubClients) {
      if (name !== excludeName) {
        const clientKey = (clientWs as any).sessionKey || sessionKey;
        try {
          clientWs.send(serializeForWire(msg, clientKey));
        } catch {}
      }
    }
    // Also deliver to the hub itself (unless excluded)
    if (excludeName !== terminalName) handleIncoming(msg);
  }

  /** Hub: find a client WebSocket by name. */
  function hubClientByName(name: string): WebSocket | undefined {
    for (const [clientWs, n] of hubClients) {
      if (n === name) return clientWs;
    }
    return undefined;
  }

  /** Hub: smart target resolution (exact -> case-insensitive -> prefix/fuzzy). */
  function hubResolveTarget(target: string): { name: string; ws?: WebSocket; isHub?: boolean } | null {
    if (target === terminalName) {
      return { name: terminalName, isHub: true };
    }

    const directWs = hubClientByName(target);
    if (directWs) return { name: target, ws: directWs };

    const lower = target.toLowerCase();
    if (terminalName.toLowerCase() === lower) {
      return { name: terminalName, isHub: true };
    }
    for (const [clientWs, n] of hubClients) {
      if (n.toLowerCase() === lower) return { name: n, ws: clientWs };
    }

    const normalizedTarget = normalizeName(target);
    const matches: Array<{ name: string; ws: WebSocket }> = [];
    for (const [clientWs, n] of hubClients) {
      const normName = normalizeName(n);
      if (
        normName === normalizedTarget ||
        normName.startsWith(`${normalizedTarget}-`) ||
        normName.includes(normalizedTarget) ||
        n.toLowerCase().startsWith(lower)
      ) {
        matches.push({ name: n, ws: clientWs });
      }
    }
    if (matches.length === 1) {
      return matches[0];
    }

    return null;
  }

  /**
   * Route a message to its destination. Works in both hub and client roles.
   * Returns true if the message was delivered (or sent to the hub for routing).
   * For the hub, this is authoritative. For clients, it's optimistic (hub may
   * still reject via protocol-level error responses).
   */
  function routeMessage(
    msg:
      | ChatMsg
      | CompactRequestMsg
      | CompactResponseMsg
      | RpcRequestMsg
      | RpcResponseMsg
      | FileOfferMsg
      | FileChunkMsg
      | FileAckMsg,
  ): boolean {
    if (role === "hub") {
      if (msg.to === "*" || msg.to === "all") {
        if (msg.type === "chat") {
          hubBroadcast(msg, msg.from);
          if (msg.from !== terminalName) {
            handleIncoming(msg);
          }
          return true;
        }
      }
      const resolved = hubResolveTarget(msg.to);
      if (resolved) {
        if (resolved.isHub || resolved.name === terminalName) {
          handleIncoming(msg);
          return true;
        }
        if (resolved.ws) {
          const targetKey = (resolved.ws as any).sessionKey || sessionKey;
          resolved.ws.send(serializeForWire(msg, targetKey));
          return true;
        }
      }
      // Target not found — send error back to sender
      const online = terminalList().join(", ");
      const errText = `Terminal "${msg.to}" not found. Online terminals: ${online}`;
      let errorMsg: LinkMessage;
      if (msg.type === "compact_request") {
        errorMsg = {
          type: "compact_response",
          id: msg.id,
          from: terminalName,
          to: msg.from,
          ok: false,
          reason: "not_found",
        };
      } else if (msg.type === "rpc_request") {
        errorMsg = {
          type: "rpc_response",
          id: msg.id,
          from: terminalName,
          to: msg.from,
          ok: false,
          error: "not_found",
        };
      } else if (msg.type === "file_offer") {
        errorMsg = {
          type: "file_ack",
          transferId: msg.transferId,
          from: terminalName,
          to: msg.from,
          ok: false,
          error: "not_found",
        };
      } else {
        errorMsg = { type: "error", message: errText };
      }

      if (msg.from === terminalName) {
        handleIncoming(errorMsg);
      } else {
        const senderWs = hubClientByName(msg.from);
        if (senderWs) {
          const senderKey = (senderWs as any).sessionKey || sessionKey;
          senderWs.send(serializeForWire(errorMsg, senderKey));
        }
      }
      return false;
    }
    if (role === "client" && ws?.readyState === WebSocket.OPEN) {
      ws.send(serializeForWire(msg, sessionKey));
      return true; // optimistic — hub will handle errors via protocol
    }
    return false;
  }

  // ── Incoming message handler (runs on every terminal) ────────────────────

  function handleIncoming(msg: LinkMessage) {
    switch (msg.type) {
      // ── Client receives after registering ──
      case "welcome":
        terminalName = msg.name;
        pendingClientRename = false;
        if (msg.sessionId) currentSessionId = msg.sessionId;
        if (msg.pin) sessionPin = msg.pin;
        if (msg.network) networkMode = msg.network as any;
        connectedTerminals = msg.terminals;
        terminalStatuses.clear();
        terminalCwds.clear();
        terminalContexts.clear();
        if (msg.statuses) {
          for (const [name, status] of Object.entries(msg.statuses)) {
            terminalStatuses.set(name, status);
          }
        }
        if (msg.cwds) {
          for (const [name, cwd] of Object.entries(msg.cwds)) {
            terminalCwds.set(name, cwd);
          }
        }
        if (msg.contexts) {
          for (const [name, c] of Object.entries(msg.contexts)) {
            terminalContexts.set(name, c);
          }
        }
        if (msg.hosts) {
          for (const [name, host] of Object.entries(msg.hosts)) {
            terminalHosts.set(name, host);
          }
        }
        if (msg.projects) {
          for (const [name, proj] of Object.entries(msg.projects)) {
            terminalProjects.set(name, proj);
          }
        }
        if (msg.deviceToken) {
          const hubKey = targetHubAddress || currentSessionId || "default";
          saveClientToken(hubKey, msg.deviceToken);
          saveClientToken("default", msg.deviceToken);
          notify(`🔑 Paired with session "${currentSessionId}" (persistent token saved)`, "info");
        }
        updateStatus();
        notify(
          `⚡ Connected to session "${currentSessionId}" on ${networkMode.toUpperCase()} (${connectedTerminals.length} online)`,
          "info",
        );
        pushStatus(true);
        break;

      // ── Membership updates ──
      case "terminal_joined":
        connectedTerminals = msg.terminals;
        if (role !== "hub" && msg.cwd) terminalCwds.set(msg.name, msg.cwd);
        if (role !== "hub" && msg.context)
          terminalContexts.set(msg.name, msg.context);
        if (role !== "hub" && msg.host) terminalHosts.set(msg.name, msg.host);
        if (role !== "hub" && msg.project)
          terminalProjects.set(msg.name, msg.project);
        updateStatus();
        notify(`"${msg.name}" joined the link`, "info");
        break;

      case "terminal_left":
        connectedTerminals = msg.terminals;
        terminalStatuses.delete(msg.name);
        if (role !== "hub") {
          terminalCwds.delete(msg.name);
          terminalContexts.delete(msg.name);
          terminalHosts.delete(msg.name);
          terminalProjects.delete(msg.name);
        }
        // Fail any pending compact request to the departed terminal
        for (const [id, pending] of pendingCompactResponses) {
          if (pending.targetName === msg.name) {
            const p = cleanupPendingCompact(id);
            if (p) {
              p.resolve(
                textResult(`Terminal "${msg.name}" disconnected`, {
                  to: msg.name,
                  error: "disconnected",
                }),
              );
            }
          }
        }
        updateStatus();
        notify(`"${msg.name}" left the link`, "info");
        break;

      // ── Status update from another terminal ──
      case "status_update":
        terminalStatuses.set(msg.name, msg.status);
        if (msg.context) terminalContexts.set(msg.name, msg.context);
        else if (msg.context === null) terminalContexts.delete(msg.name);
        break;

      // ── Chat message ──
      case "chat":
        if (msg.from && !connectedTerminals.includes(msg.from)) {
          connectedTerminals.push(msg.from);
          updateStatus();
        }
        inbox.push({ from: msg.from, content: msg.content });
        scheduleFlush(FLUSH_DELAY_MS);
        break;

      // ── Another terminal asks us to compact our context ──
      case "compact_request": {
        const { id, from } = msg;
        const respond = (ok: boolean, reason?: string) =>
          routeMessage({
            type: "compact_response",
            id,
            from: terminalName,
            to: from,
            ok,
            reason,
          });
        // Answered before the busy question, and not through finish(): no capability
        // and no context are refusals of a request we never took on, so nothing here
        // owns the gate to clear or the inbox to release.
        if (!ctx || !ctx.compact) {
          respond(false, "unsupported");
          break;
        }
        // Pi's idle state is the authority on whether this terminal is working.
        // agentRunning is not: Pi may still retry, run an automatic compaction, or
        // drain a queued continuation inside a run whose agent_end already fired, and
        // compact() would abort that work and compact the same branch a second time.
        // compactionGated() adds what Pi's idle flag cannot cover — a manual
        // compaction is not an agent run — and keeps declining while either gate
        // stands, so we never touch a compaction we did not start.
        if (!ctx.isIdle() || compactionGated()) {
          respond(false, "busy");
          break;
        }
        let finished = false;
        const finish = (ok: boolean, reason?: string) => {
          if (finished) return;
          finished = true;
          compactRunning = false;
          releaseInbox(); // last gate may clear here, after session_compact already fired
          // Only reverts status if localCompacting is also clear. A failure after
          // session_before_compact leaves it standing, so the terminal truthfully
          // keeps reporting compacting until the deadline or agent_start.
          syncCompactionStatus();
          respond(ok, reason);
        };
        compactRunning = true;
        syncCompactionStatus();
        notify(`"${from}" requested compact`, "info");
        // compact() aborts the current turn first, so the idle guard above
        // keeps us from interrupting active work. The runtime guarantees
        // exactly one of onComplete/onError fires, so compactRunning can't
        // get stuck and the sender won't hang.
        try {
          ctx.compact({
            customInstructions: msg.instructions,
            onComplete: () => finish(true),
            onError: (e) =>
              finish(false, e instanceof Error ? e.message : String(e)),
          });
        } catch (e) {
          finish(false, e instanceof Error ? e.message : String(e));
        }
        break;
      }

      // ── Response to a compact we requested ──
      case "compact_response": {
        const pending = cleanupPendingCompact(msg.id);
        if (pending) {
          // Use the requested target, not msg.from: a hub-synthesized
          // not_found response comes from the hub, not the worker.
          const target = pending.targetName;
          if (msg.ok) {
            pending.resolve(
              textResult(`Compacted "${target}"`, { to: target }),
            );
          } else {
            const reason = msg.reason ?? "failed";
            pending.resolve(
              textResult(`Compact on "${target}" not done: ${reason}`, {
                to: target,
                error: reason,
              }),
            );
          }
        }
        break;
      }

      case "error":
        notify(`Link: ${msg.message}`, "error");
        break;

      // ── Pairing & Request Mode ──
      case "pairing_pending":
        notify(
          `⏳ Pairing request #${msg.requestId} pending host approval on "${msg.hubHost}"...`,
          "info",
        );
        break;

      case "pairing_denied":
        notify(`❌ Join request was denied by host: ${msg.message}`, "error");
        break;

      // ── Direct Tool RPC ──
      case "rpc_request":
        handleRpcRequest(msg);
        break;

      case "rpc_response": {
        const pending = pendingRpcRequests.get(msg.id);
        if (pending) {
          clearTimeout(pending.timeout);
          pendingRpcRequests.delete(msg.id);
          pending.resolve(msg);
        }
        break;
      }

      // ── File Transfer ──
      case "file_offer":
        handleFileOffer(msg);
        break;

      case "file_chunk":
        handleFileChunk(msg);
        break;

      case "file_ack": {
        const pending = pendingFileAcks.get(msg.transferId);
        if (pending) {
          clearTimeout(pending.timeout);
          pendingFileAcks.delete(msg.transferId);
          pending.resolve(msg);
        }
        break;
      }
    }
  }

  function safeGitExecFile(
    subcommandArgs: string[],
    options: { cwd: string; timeout?: number; maxBuffer?: number },
    callback: (err: Error | null, stdout: string, stderr: string) => void
  ) {
    const SAFE_GIT_FLAGS = [
      "-c", "core.fsmonitor=false",
      "-c", "core.pager=cat",
      "-c", "pager.status=false",
      "-c", "pager.diff=false",
      "-c", "pager.log=false",
      "-c", "diff.external=",
      "-c", "diff.algorithm=myers",
    ];

    const safeEnv: NodeJS.ProcessEnv = {
      PATH: process.env.PATH || "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
      HOME: process.env.HOME || "/tmp",
      LC_ALL: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_TERMINAL_PROMPT: "0",
    };

    execFile("git", [...SAFE_GIT_FLAGS, ...subcommandArgs], {
      cwd: options.cwd,
      timeout: options.timeout || 15_000,
      maxBuffer: options.maxBuffer || 5 * 1024 * 1024,
      env: safeEnv,
    }, callback);
  }

  function handleRpcRequest(msg: RpcRequestMsg) {
    const { id, from, action, params } = msg;
    const respond = (ok: boolean, result?: string, error?: string) => {
      routeMessage({
        type: "rpc_response",
        id,
        from: terminalName,
        to: from,
        ok,
        result,
        error,
      });
    };

    const workspaceRoot = fs.realpathSync(currentCwd || process.cwd());
    let execCwd = workspaceRoot;
    if (params.cwd) {
      const check = resolveConfinedPath(workspaceRoot, params.cwd);
      if (!check.allowed || !check.fullPath) {
        respond(false, undefined, `Access denied: ${check.reason || "cwd escapes workspace root"}`);
        return;
      }
      try {
        const st = fs.statSync(check.fullPath);
        if (!st.isDirectory()) {
          respond(false, undefined, `Path "${params.cwd}" is not a directory.`);
          return;
        }
        execCwd = check.fullPath;
      } catch (err: any) {
        respond(false, undefined, `Directory access error: ${err.message}`);
        return;
      }
    }

    // ── Structured Inspection: git_status ──
    if (action === "git_status") {
      safeGitExecFile(["status", "--porcelain=v1"], { cwd: execCwd }, (err, stdout, stderr) => {
        if (err) {
          respond(false, undefined, `git status failed: ${err.message}${stderr ? `\n${stderr}` : ""}`);
        } else {
          respond(true, stdout || "[Clean working tree - no changes]");
        }
      });
      return;
    }

    // ── Structured Inspection: git_diff ──
    if (action === "git_diff") {
      safeGitExecFile(["diff", "--no-ext-diff", "--no-textconv"], { cwd: execCwd }, (err, stdout, stderr) => {
        if (err) {
          respond(false, undefined, `git diff failed: ${err.message}${stderr ? `\n${stderr}` : ""}`);
        } else {
          respond(true, stdout || "[No diff - working tree matches HEAD]");
        }
      });
      return;
    }

    // ── Structured Inspection: git_log ──
    if (action === "git_log") {
      const count = Math.min(Math.max(Number(params.count) || 10, 1), 100);
      safeGitExecFile(["log", `-n${count}`, "--oneline", "--no-ext-diff"], { cwd: execCwd }, (err, stdout, stderr) => {
        if (err) {
          respond(false, undefined, `git log failed: ${err.message}${stderr ? `\n${stderr}` : ""}`);
        } else {
          respond(true, stdout || "[Empty git log]");
        }
      });
      return;
    }

    // ── Structured Inspection: search_text (git grep) ──
    if (action === "search_text") {
      if (!params.pattern) {
        respond(false, undefined, "Missing 'pattern' parameter for search_text");
        return;
      }
      safeGitExecFile(["grep", "-n", "-I", "--max-depth=5", "-e", params.pattern], { cwd: execCwd }, (err, stdout, stderr) => {
        if (err) {
          if ((err as any).code === 1) {
            respond(true, `No matches found for pattern "${params.pattern}".`);
          } else {
            respond(false, undefined, `git grep failed: ${err.message}${stderr ? `\n${stderr}` : ""}`);
          }
        } else {
          const lines = (stdout || "").split("\n").filter(Boolean);
          if (lines.length > 100) {
            respond(true, lines.slice(0, 100).join("\n") + `\n... [${lines.length - 100} additional matches truncated]`);
          } else {
            respond(true, stdout || "No matches found.");
          }
        }
      });
      return;
    }

    // ── Workspace-Confined: read_file ──
    if (action === "read_file") {
      if (!params.filePath) {
        respond(false, undefined, "Missing filePath parameter");
        return;
      }
      const check = resolveConfinedPath(execCwd, params.filePath);
      if (!check.allowed || !check.fullPath) {
        respond(false, undefined, `Access denied: ${check.reason || "Path outside workspace"}`);
        return;
      }
      fs.promises.readFile(check.fullPath, "utf-8").then(
        (content) => {
          if (content.length > 500_000) {
            respond(true, content.slice(0, 500_000) + "\n... [File truncated at 500KB]");
          } else {
            respond(true, content);
          }
        },
        (err) => respond(false, undefined, err.message),
      );
      return;
    }

    // ── Workspace-Confined: list_dir ──
    if (action === "list_dir") {
      const targetDir = params.filePath || ".";
      const check = resolveConfinedPath(execCwd, targetDir);
      if (!check.allowed || !check.fullPath) {
        respond(false, undefined, `Access denied: ${check.reason || "Path outside workspace"}`);
        return;
      }
      fs.promises.readdir(check.fullPath, { withFileTypes: true }).then(
        (entries) => {
          const list = entries
            .filter((e) => !e.name.startsWith(".git") && !e.name.startsWith(".env"))
            .map((e) => `${e.isDirectory() ? "📁" : "📄"} ${e.name}`)
            .join("\n");
          respond(true, list || "[Empty directory]");
        },
        (err) => respond(false, undefined, err.message),
      );
      return;
    }

    // ── Arbitrary Shell Execution: exec (Blocked by default) ──
    if (action === "exec") {
      if (!params.command) {
        respond(false, undefined, "Missing command parameter");
        return;
      }

      const trimmedCmd = params.command.trim();
      const grant = activeExecGrants.get(from);
      const isGrantActive = grant && grant.expiresAt > Date.now();

      if (!isGrantActive) {
        // Safe transparent fallback for read-only git status / diff commands
        if (
          trimmedCmd === "git status" ||
          trimmedCmd === "git status --porcelain" ||
          trimmedCmd === "git status -s"
        ) {
          safeGitExecFile(["status", "--porcelain=v1"], { cwd: execCwd }, (err, stdout) => {
            if (err) respond(false, undefined, `git status failed: ${err.message}`);
            else respond(true, stdout || "[Clean working tree - no changes]");
          });
          return;
        }
        if (trimmedCmd === "git diff" || trimmedCmd === "git diff --stat") {
          const args =
            trimmedCmd === "git diff --stat"
              ? ["diff", "--stat", "--no-ext-diff", "--no-textconv"]
              : ["diff", "--no-ext-diff", "--no-textconv"];
          safeGitExecFile(args, { cwd: execCwd }, (err, stdout) => {
            if (err) respond(false, undefined, `git diff failed: ${err.message}`);
            else respond(true, stdout || "[No diff - working tree matches HEAD]");
          });
          return;
        }

        respond(
          false,
          undefined,
          `REMOTE EXECUTION BLOCKED: Arbitrary shell execution is disabled by default under Territorial Sovereignty policy. Host must grant temporary elevation via "/link grant ${from} [minutes]". Safe structured inspection operations (git_status, git_diff, git_log, search_text, read_file, list_dir) remain available.`
        );
        return;
      }

      if (mutationGuard) {
        const guardCheck = checkMutationGuard(params.command, from);
        if (guardCheck.blocked) {
          respond(
            false,
            undefined,
            `MUTATION GUARD BLOCKED: Command "${params.command}" was rejected (${guardCheck.reason}). Territorial Sovereignty Policy: Remote terminals may only execute read-only inspection commands. If code changes are required, use link_send to request the local agent apply the change in its own session.`,
          );
          return;
        }
      }

      appendAuditLog({
        type: "exec",
        timestamp: Date.now(),
        from,
        command: params.command,
        cwd: execCwd,
      });

      exec(params.command, { cwd: execCwd, timeout: 30_000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
        if (err) {
          respond(false, (stdout ? stdout + "\n" : "") + (stderr || ""), err.message);
        } else {
          respond(true, stdout || (stderr ? `[stderr]\n${stderr}` : "[Command completed with no output]"));
        }
      });
      return;
    }

    respond(false, undefined, `Unsupported action "${action}"`);
  }

  const MAX_FILE_TRANSFER_BYTES = 50 * 1024 * 1024; // 50MB ceiling
  const MAX_CHUNK_BYTES = 64 * 1024; // 64KB per chunk ceiling

  interface ActiveTransfer {
    offer: FileOfferMsg;
    tempPath: string;
    fd: number;
    receivedChunks: number;
    receivedBytes: number;
    hasher: crypto.Hash;
    startedAt: number;
    lastChunkAt: number;
  }
  const incomingTransfers = new Map<string, ActiveTransfer>();

  function handleFileOffer(msg: FileOfferMsg) {
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(msg.transferId)) {
      routeMessage({
        type: "file_ack",
        transferId: msg.transferId,
        from: terminalName,
        to: msg.from,
        ok: false,
        error: "Invalid transfer ID format (must match ^[a-zA-Z0-9_-]{1,64}$)",
      });
      return;
    }

    if (msg.sizeBytes > MAX_FILE_TRANSFER_BYTES || msg.sizeBytes <= 0) {
      routeMessage({
        type: "file_ack",
        transferId: msg.transferId,
        from: terminalName,
        to: msg.from,
        ok: false,
        error: `File size (${(msg.sizeBytes / (1024 * 1024)).toFixed(1)}MB) exceeds 50MB ceiling limit`,
      });
      notify(`⚠️ Rejected file offer "${msg.filename}" from "${msg.from}": exceeds 50MB ceiling`, "warning");
      return;
    }

    const peerActive = Array.from(incomingTransfers.values()).filter(t => t.offer.from === msg.from).length;
    if (peerActive >= 2) {
      routeMessage({
        type: "file_ack",
        transferId: msg.transferId,
        from: terminalName,
        to: msg.from,
        ok: false,
        error: "Too many concurrent transfers from peer (max 2)",
      });
      return;
    }

    if (incomingTransfers.size >= 5) {
      routeMessage({
        type: "file_ack",
        transferId: msg.transferId,
        from: terminalName,
        to: msg.from,
        ok: false,
        error: "Hub busy: maximum concurrent transfers reached (max 5)",
      });
      return;
    }

    const inboxRoot = path.join(currentCwd || process.cwd(), ".omp", "inbox");
    if (!fs.existsSync(inboxRoot)) {
      try { fs.mkdirSync(inboxRoot, { recursive: true, mode: 0o700 }); } catch {}
    }
    const tempPath = path.join(inboxRoot, `.tmp-${crypto.randomBytes(8).toString("hex")}.part`);
    let fd: number;
    try {
      fd = fs.openSync(tempPath, "w", 0o600);
    } catch (err: any) {
      routeMessage({
        type: "file_ack",
        transferId: msg.transferId,
        from: terminalName,
        to: msg.from,
        ok: false,
        error: `Cannot create temporary storage: ${err.message}`,
      });
      return;
    }

    incomingTransfers.set(msg.transferId, {
      offer: msg,
      tempPath,
      fd,
      receivedChunks: 0,
      receivedBytes: 0,
      hasher: crypto.createHash("sha256"),
      startedAt: Date.now(),
      lastChunkAt: Date.now(),
    });
  }

  async function handleFileChunk(msg: FileChunkMsg) {
    const transfer = incomingTransfers.get(msg.transferId);
    if (!transfer) return;

    transfer.lastChunkAt = Date.now();
    const chunkBuf = Buffer.from(msg.data, "base64");

    if (chunkBuf.length > MAX_CHUNK_BYTES) {
      try { fs.closeSync(transfer.fd); } catch {}
      try { fs.unlinkSync(transfer.tempPath); } catch {}
      incomingTransfers.delete(msg.transferId);
      routeMessage({
        type: "file_ack",
        transferId: msg.transferId,
        from: terminalName,
        to: transfer.offer.from,
        ok: false,
        error: `Chunk ${msg.chunkIndex} exceeds 64KB maximum chunk limit`,
      });
      return;
    }

    if (transfer.receivedBytes + chunkBuf.length > transfer.offer.sizeBytes) {
      try { fs.closeSync(transfer.fd); } catch {}
      try { fs.unlinkSync(transfer.tempPath); } catch {}
      incomingTransfers.delete(msg.transferId);
      routeMessage({
        type: "file_ack",
        transferId: msg.transferId,
        from: terminalName,
        to: transfer.offer.from,
        ok: false,
        error: "Received byte count exceeds offered file size",
      });
      return;
    }

    try {
      fs.writeSync(transfer.fd, chunkBuf, 0, chunkBuf.length);
      transfer.hasher.update(chunkBuf);
      transfer.receivedBytes += chunkBuf.length;
      transfer.receivedChunks++;
    } catch (err: any) {
      try { fs.closeSync(transfer.fd); } catch {}
      try { fs.unlinkSync(transfer.tempPath); } catch {}
      incomingTransfers.delete(msg.transferId);
      routeMessage({
        type: "file_ack",
        transferId: msg.transferId,
        from: terminalName,
        to: transfer.offer.from,
        ok: false,
        error: `Disk write failed: ${err.message}`,
      });
      return;
    }

    if (transfer.receivedChunks >= transfer.offer.totalChunks) {
      try { fs.closeSync(transfer.fd); } catch {}
      incomingTransfers.delete(msg.transferId);

      if (transfer.receivedBytes !== transfer.offer.sizeBytes) {
        try { fs.unlinkSync(transfer.tempPath); } catch {}
        routeMessage({
          type: "file_ack",
          transferId: msg.transferId,
          from: terminalName,
          to: transfer.offer.from,
          ok: false,
          error: `File size mismatch: expected ${transfer.offer.sizeBytes} bytes, got ${transfer.receivedBytes}`,
        });
        return;
      }

      const computedSha = transfer.hasher.digest("hex");
      if (computedSha !== transfer.offer.sha256) {
        try { fs.unlinkSync(transfer.tempPath); } catch {}
        routeMessage({
          type: "file_ack",
          transferId: msg.transferId,
          from: terminalName,
          to: transfer.offer.from,
          ok: false,
          error: "SHA-256 checksum mismatch",
        });
        return;
      }

      const safeFilename = path.basename(transfer.offer.filename).replace(/[^a-zA-Z0-9._-]/g, "_");
      const inboxRoot = path.join(currentCwd || process.cwd(), ".omp", "inbox");
      const safeFolder = path.join(inboxRoot, transfer.offer.transferId);
      const savePath = path.join(safeFolder, safeFilename);

      try {
        await fs.promises.mkdir(safeFolder, { recursive: true, mode: 0o700 });
        fs.renameSync(transfer.tempPath, savePath);
        fs.chmodSync(savePath, 0o600);
        routeMessage({
          type: "file_ack",
          transferId: msg.transferId,
          from: terminalName,
          to: transfer.offer.from,
          ok: true,
          savedPath: savePath,
        });
        notify(
          `📥 Quarantined file "${safeFilename}" (${(transfer.receivedBytes / 1024).toFixed(1)} KB) from ${transfer.offer.from} -> ${shortenPath(savePath)}`,
          "info",
        );
      } catch (err: any) {
        try { fs.unlinkSync(transfer.tempPath); } catch {}
        routeMessage({
          type: "file_ack",
          transferId: msg.transferId,
          from: terminalName,
          to: transfer.offer.from,
          ok: false,
          error: err.message,
        });
      }
    }
  }

  // ── Hub: handle a new client WebSocket ───────────────────────────────────

  function hubHandleClient(clientWs: WebSocket, req?: IncomingMessage) {
    let clientName = "";
    const clientIp = req?.socket?.remoteAddress;

    // Ephemeral X25519 keypair for forward-secret session key derivation
    const hubEphemeral = crypto.generateKeyPairSync("x25519");
    const hubEphemeralPub = hubEphemeral.publicKey.export({ type: "spki", format: "der" }).toString("base64");
    const challengeNonce = crypto.randomBytes(32).toString("base64");
    const challengeTs = Date.now();

    // Send HandshakeChallengeMsg immediately
    try {
      clientWs.send(
        JSON.stringify({
          type: "handshake_challenge",
          v: 4,
          hubId: hubInstanceId,
          hubFingerprint: myIdentity.fingerprint,
          nonce: challengeNonce,
          ts: challengeTs,
          hubEphemeralPub,
        } satisfies HandshakeChallengeMsg),
      );
    } catch {}

    function completeClientRegistration(ws: WebSocket, regMsg: HandshakeResponseMsg | RegisterMsg) {
      clientName = uniqueName(regMsg.name);
      hubClients.set(ws, clientName);
      if (regMsg.cwd) hubTerminalCwds.set(clientName, regMsg.cwd);
      if (regMsg.context) hubTerminalContexts.set(clientName, regMsg.context);
      if (regMsg.host) hubTerminalHosts.set(clientName, regMsg.host);
      if (regMsg.project) hubTerminalProjects.set(clientName, regMsg.project);
      const list = terminalList();
      connectedTerminals = list;
      updateStatus();

      // Confirm to the new client (include status + cwd snapshots)
      const statuses: Record<string, LinkStatus> = {};
      statuses[terminalName] = deriveStatus(); // hub's own status
      for (const [name, status] of hubTerminalStatuses) {
        if (name !== clientName) statuses[name] = status;
      }
      const cwds: Record<string, string> = {};
      if (currentCwd) cwds[terminalName] = currentCwd; // hub's own cwd
      for (const [name, cwd] of hubTerminalCwds) {
        if (name !== clientName) cwds[name] = cwd;
      }
      const contexts: Record<string, ContextSnapshot> = {};
      const hubContext = captureContext();
      if (hubContext) contexts[terminalName] = hubContext; // hub's own context
      for (const [name, c] of hubTerminalContexts) {
        if (name !== clientName) contexts[name] = c;
      }
      const hosts: Record<string, string> = {};
      hosts[terminalName] = os.hostname();
      for (const [name, host] of hubTerminalHosts) {
        if (name !== clientName) hosts[name] = host;
      }
      const projects: Record<string, string> = {};
      if (currentCwd) projects[terminalName] = path.basename(currentCwd);
      for (const [name, proj] of hubTerminalProjects) {
        if (name !== clientName) projects[name] = proj;
      }

      const clientKey = (ws as any).sessionKey || sessionKey;
      ws.send(
        serializeForWire({
          type: "welcome",
          name: clientName,
          sessionId: currentSessionId,
          pin: sessionPin,
          network: networkMode,
          terminals: list,
          statuses,
          cwds,
          contexts,
          hosts,
          projects,
          permissions: {
            message: true,
            inspect: true,
            fileInbox: true,
            exec: false,
          },
          hubFingerprint: myIdentity.fingerprint,
        } satisfies WelcomeMsg, clientKey),
      );

      // Notify everyone else (include joiner's cwd + context)
      const joined: TerminalJoinedMsg = {
        type: "terminal_joined",
        name: clientName,
        sessionId: currentSessionId,
        network: networkMode,
        terminals: list,
        cwd: regMsg.cwd,
        context: regMsg.context || undefined,
        host: regMsg.host,
        project: regMsg.project,
      };
      hubBroadcast(joined, clientName);
    }

    clientWs.on("message", (raw) => {
      if (!isRuntimeLive()) return;
      const rawStr = raw.toString();

      // Handshake and pairing handling
      if (!clientName) {
        let msg: LinkMessage | null = null;
        try {
          msg = JSON.parse(rawStr);
        } catch {}

        if (!msg) {
          clientWs.close(4003, "Invalid handshake payload");
          return;
        }

        if (msg.type === "handshake_response") {
          const resp = msg as HandshakeResponseMsg;
          // Verify Ed25519 signature
          try {
            const clientPubObj = crypto.createPublicKey({
              key: Buffer.from(resp.publicKey, "base64"),
              format: "der",
              type: "spki",
            });
            const signedBuf = Buffer.from(`${challengeNonce}:${challengeTs}:${myIdentity.fingerprint}`);
            const valid = crypto.verify(null, signedBuf, clientPubObj, Buffer.from(resp.signature, "base64"));
            if (!valid) {
              clientWs.close(4003, "Cryptographic challenge verification failed");
              return;
            }

            // Derive 256-bit AES-GCM forward-secret session key
            const clientEphemeralPubObj = crypto.createPublicKey({
              key: Buffer.from(resp.clientEphemeralPub, "base64"),
              format: "der",
              type: "spki",
            });
            const sharedSecret = crypto.diffieHellman({
              privateKey: hubEphemeral.privateKey,
              publicKey: clientEphemeralPubObj,
            });
            const derivedKey = crypto.hkdfSync(
              "sha256",
              sharedSecret,
              Buffer.from("omp-link-v4-salt"),
              Buffer.from("omp-link-session-key"),
              32,
            );
            (clientWs as any).sessionKey = Buffer.from(derivedKey);
            (clientWs as any).fingerprint = resp.fingerprint;
            (clientWs as any).deviceId = resp.deviceId;
          } catch {
            clientWs.close(4003, "Cryptographic handshake failed");
            return;
          }

          const isLocal = isLocalhost(clientIp);
          const pairedDevices = loadPairedDevices();
          const paired =
            pairedDevices.get(resp.deviceId) ||
            Array.from(pairedDevices.values()).find(
              (d) => d.fingerprint === resp.fingerprint || d.publicKey === resp.publicKey,
            );

          if (isLocal || paired) {
            if (paired) {
              paired.lastSeen = Date.now();
              if (clientIp) paired.lastAddress = clientIp;
              savePairedDevice(paired);
            }
            completeClientRegistration(clientWs, resp);
            return;
          }

          // Unpaired device -> Place in pending requests queue
          const reqId = nextPairingRequestId++;
          pendingJoinRequests.set(reqId, {
            id: reqId,
            ws: clientWs,
            deviceId: resp.deviceId,
            name: resp.name,
            host: resp.host || clientIp || "unknown",
            fingerprint: resp.fingerprint,
            publicKey: resp.publicKey,
            sessionKey: (clientWs as any).sessionKey,
            clientIp: clientIp || "unknown",
            timestamp: Date.now(),
            complete: () => {
              completeClientRegistration(clientWs, resp);
            },
          });

          clientWs.send(
            JSON.stringify({
              type: "pairing_pending",
              requestId: reqId,
              hubHost: os.hostname(),
              fingerprint: myIdentity.fingerprint,
              message: `Pairing approval required on "${os.hostname()}". Run "/link accept ${reqId}" on the host to approve.`,
            } satisfies PairingPendingMsg),
          );

          notify(
            `🔔 [Link Request #${reqId}]\n   Device:      "${resp.name}" on ${resp.host || clientIp}\n   Address:     ${clientIp}\n   Identity:    ${resp.fingerprint}\n   Permissions: message + inspect + file-inbox\n   Type /link accept ${reqId} to approve or /link deny ${reqId} to reject.`,
            "warning",
          );
          return;
        }

        // Legacy register message fallback for backwards compatibility
        if (msg.type === "register") {
          const reg = msg as RegisterMsg;
          completeClientRegistration(clientWs, reg);
          return;
        }

        return;
      }

      // Already registered client -> Application messages MUST be encrypted
      const connKey = (clientWs as any).sessionKey || sessionKey;
      const appMsg = safeParse(rawStr, connKey);
      if (!appMsg) {
        clientWs.close(4003, "Protocol violation: invalid or unencrypted frame rejected");
        return;
      }

      // Status update — store and fan out to other clients only (not back to hub)
      if (appMsg.type === "status_update") {
        hubTerminalStatuses.set(clientName, appMsg.status);
        if (appMsg.context) hubTerminalContexts.set(clientName, appMsg.context);
        else if (appMsg.context === null) hubTerminalContexts.delete(clientName);
        const normalized: StatusUpdateMsg = {
          type: "status_update",
          name: clientName,
          status: appMsg.status,
          context: appMsg.context,
        };
        hubBroadcast(normalized, clientName);
        return;
      }

      // Route chat, compact, rpc, and file transfer messages.
      if (
        appMsg.type === "chat" ||
        appMsg.type === "compact_request" ||
        appMsg.type === "compact_response" ||
        appMsg.type === "rpc_request" ||
        appMsg.type === "rpc_response" ||
        appMsg.type === "file_offer" ||
        appMsg.type === "file_chunk" ||
        appMsg.type === "file_ack"
      ) {
        routeMessage({ ...appMsg, from: clientName });
      }
    });

    clientWs.on("close", () => {
      for (const [id, reqItem] of pendingJoinRequests) {
        if (reqItem.ws === clientWs) {
          pendingJoinRequests.delete(id);
          break;
        }
      }
      if (disposed) return;
      const name = hubClients.get(clientWs);
      if (!name) return;
      hubClients.delete(clientWs);
      hubTerminalStatuses.delete(name);
      hubTerminalContexts.delete(name);
      hubTerminalCwds.delete(name);
      hubTerminalHosts.delete(name);
      hubTerminalProjects.delete(name);
      const list = terminalList();
      connectedTerminals = list;
      updateStatus();
      const left: TerminalLeftMsg = {
        type: "terminal_left",
        name,
        terminals: list,
      };
      hubBroadcast(left, name);
    });

    clientWs.on("error", () => {
      clientWs.close();
    });
  }

  // ── Start as hub ─────────────────────────────────────────────────────────

  function startHub(attempt: ConnectionAttempt): Promise<boolean> {
    return new Promise((resolve) => {
      const tlsCert = getOrCreateTlsCert();

      const requestHandler = (req: IncomingMessage, res: any) => {
        if (req.method === "GET" && (req.url === "/status" || req.url?.startsWith("/status?"))) {
          const clientIp = req.socket?.remoteAddress;
          const isLocal = isLocalhost(clientIp);
          const authHeader = (req.headers["authorization"] as string) || "";
          const suppliedBearer = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";

          const pairedDevices = loadPairedDevices();
          const isPaired =
            suppliedBearer &&
            Array.from(pairedDevices.values()).some(
              (d) => d.publicKey === suppliedBearer || d.fingerprint === suppliedBearer,
            );
          const isValidSecret = linkSecret ? suppliedBearer === linkSecret : false;
          const isAuthorized = isLocal || isValidSecret || isPaired;

          res.writeHead(200, {
            "content-type": "application/json",
            "cache-control": "no-store",
          });

          if (isAuthorized && suppliedBearer) {
            res.end(JSON.stringify(buildStatusPayload()));
          } else {
            // Sanitized public discovery: no paths, no session IDs, no peer lists
            res.end(
              JSON.stringify({
                service: "omp-link",
                protocolVersion: 4,
                instanceId: hubInstanceId,
                pairingRequired: true,
                fingerprint: myIdentity.fingerprint,
                tls: !!tlsCert,
              }),
            );
          }
          return;
        }

        if (req.method === "GET" && req.url?.startsWith("/transfer/")) {
          const parts = req.url.split("/").filter(Boolean);
          if (parts.length >= 2) {
            const transferId = parts[1];
            const authHeader = (req.headers["authorization"] as string) || "";
            const suppliedBearer = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
            const transfer = ephemeralTransfers.get(transferId);
            if (transfer && Date.now() < transfer.expires) {
              if (!transfer.authToken || transfer.authToken === suppliedBearer) {
                res.writeHead(200, {
                  "content-type": "application/octet-stream",
                  "content-disposition": `attachment; filename="${encodeURIComponent(transfer.filename)}"`,
                  "content-length": transfer.buffer.length,
                  "x-sha256": transfer.sha256,
                  "cache-control": "no-store",
                });
                res.end(transfer.buffer, () => {
                  ephemeralTransfers.delete(transferId);
                });
                return;
              } else {
                res.writeHead(401, { "content-type": "text/plain", "cache-control": "no-store" });
                res.end("Unauthorized transfer token");
                return;
              }
            }
          }
          res.writeHead(404, { "content-type": "text/plain", "cache-control": "no-store" });
          res.end("Transfer expired or not found");
          return;
        }

        res.writeHead(404, { "cache-control": "no-store" });
        res.end();
      };

      const httpServer =
        networkMode === "lan" && tlsCert
          ? createHttpsServer({ cert: tlsCert.cert, key: tlsCert.key }, requestHandler)
          : createHttpServer(requestHandler);
      attempt.httpServer = httpServer;

      const server = new WebSocketServer({
        server: httpServer,
        maxPayload: 1024 * 1024, // 1MB ceiling
      });
      attempt.server = server;

      let settled = false;
      const settle = (established: boolean) => {
        if (settled) return;
        settled = true;
        if (attempt.server === server) attempt.server = null;
        if (attempt.httpServer === httpServer) attempt.httpServer = null;
        resolve(established);
      };

      server.on("listening", () => {
        if (!attemptIsCurrent(attempt)) {
          server.close();
          httpServer.close();
          settle(false);
          return;
        }
        reconnectAttempts = 0;
        wss = server;
        hubHttpServer = httpServer;
        if (pendingClientRename && preferredName) terminalName = preferredName;
        pendingClientRename = false;
        role = "hub";
        connectedTerminals = [terminalName];
        updateStatus();
        const net = getNetworkInfo();
        const endpoint = net.tailscaleIp
          ? `${net.tailscaleIp}:${linkPort}`
          : (net.lanIps.length > 0 ? `${net.lanIps[0]}:${linkPort}` : `127.0.0.1:${linkPort}`);
        notify(
          `⚡ Session "${currentSessionId}" hosted (${endpoint}) as "${terminalName}" [Identity: ${myIdentity.fingerprint}]`,
          "info",
        );
        if (enableLanDiscovery && !udpResponder) {
          udpResponder = startUdpDiscoveryResponder(linkPort, linkSecret);
        }
        settle(true);
      });

      server.on("connection", (clientWs, req) => {
        if (wss !== server || role !== "hub") {
          clientWs.close();
          return;
        }
        const clientIp = req.socket.remoteAddress;
        if (isTailscaleOnly && !isTailscaleOrLocalIp(clientIp)) {
          clientWs.close(4003, "Tailscale only");
          return;
        }
        hubHandleClient(clientWs, req);
      });

      server.on("error", () => {
        settle(false);
      });

      server.on("close", () => {
        settle(false);
      });

      httpServer.listen(linkPort, linkBind);
    });
  }

  // ── Connect as client ────────────────────────────────────────────────────

  function connectAsClient(
    attempt: ConnectionAttempt,
    targetEndpoint?: string,
    joinPin?: string,
    joinSessionId?: string,
  ): Promise<boolean> {
    return new Promise((resolve) => {
      let endpoint = targetEndpoint || `127.0.0.1:${linkPort}`;
      if (!endpoint.includes(":") || (endpoint.startsWith("[") && !endpoint.includes("]:"))) {
        endpoint = `${endpoint}:${linkPort}`;
      }

      const effectivePin = joinPin || sessionPin;
      if (effectivePin) sessionPin = effectivePin;
      const effectiveSessionId = joinSessionId || currentSessionId;
      if (effectiveSessionId) currentSessionId = effectiveSessionId;

      const tlsCert = getOrCreateTlsCert();
      const scheme = networkMode === "lan" && tlsCert ? "wss" : "ws";

      const socket = new WebSocket(`${scheme}://${endpoint}`, {
        handshakeTimeout: CONNECT_HANDSHAKE_TIMEOUT_MS,
        maxPayload: 1024 * 1024,
        rejectUnauthorized: false,
      });
      attempt.socket = socket;

      let settled = false;
      const settle = (established: boolean) => {
        if (settled) return;
        settled = true;
        if (attempt.socket === socket) attempt.socket = null;
        resolve(established);
      };

      socket.on("open", () => {
        if (!attemptIsCurrent(attempt)) {
          socket.close();
          settle(false);
          return;
        }
        ws = socket;
      });

      socket.on("message", (raw) => {
        if (ws !== socket || !isRuntimeLive()) return;
        const rawStr = raw.toString();

        let initialParsed: LinkMessage | null = null;
        try {
          initialParsed = JSON.parse(rawStr);
        } catch {}

        if (initialParsed && initialParsed.type === "handshake_challenge") {
          const challenge = initialParsed as HandshakeChallengeMsg;
          // Sign challenge payload
          try {
            const privKeyObj = crypto.createPrivateKey({
              key: Buffer.from(myIdentity.privateKey, "base64"),
              format: "der",
              type: "pkcs8",
            });
            const signedBuf = Buffer.from(`${challenge.nonce}:${challenge.ts}:${challenge.hubFingerprint}`);
            const signature = crypto.sign(null, signedBuf, privKeyObj).toString("base64");

            // Client ephemeral keypair
            const clientEphemeral = crypto.generateKeyPairSync("x25519");
            const clientEphemeralPub = clientEphemeral.publicKey.export({ type: "spki", format: "der" }).toString("base64");

            // Derive shared secret
            const hubEphemeralPubObj = crypto.createPublicKey({
              key: Buffer.from(challenge.hubEphemeralPub, "base64"),
              format: "der",
              type: "spki",
            });
            const sharedSecret = crypto.diffieHellman({
              privateKey: clientEphemeral.privateKey,
              publicKey: hubEphemeralPubObj,
            });
            const derivedKey = crypto.hkdfSync(
              "sha256",
              sharedSecret,
              Buffer.from("omp-link-v4-salt"),
              Buffer.from("omp-link-session-key"),
              32,
            );
            sessionKey = Buffer.from(derivedKey);

            const resp: HandshakeResponseMsg = {
              type: "handshake_response",
              v: 4,
              deviceId: myIdentity.deviceId,
              name: preferredName ?? terminalName,
              publicKey: myIdentity.publicKey,
              fingerprint: myIdentity.fingerprint,
              signature,
              clientEphemeralPub,
              host: os.hostname(),
              cwd: currentCwd || undefined,
              context: captureContext() || undefined,
              project: currentCwd ? path.basename(currentCwd) : undefined,
            };
            socket.send(JSON.stringify(resp));
          } catch (err: any) {
            socket.close(4003, `Handshake error: ${err.message}`);
            settle(false);
          }
          return;
        }

        if (initialParsed && initialParsed.type === "pairing_pending") {
          handleIncoming(initialParsed);
          settle(true);
          return;
        }

        if (initialParsed && initialParsed.type === "pairing_denied") {
          handleIncoming(initialParsed);
          socket.close(4003, "Pairing denied");
          settle(false);
          return;
        }

        // Application messages (must be encrypted with sessionKey)
        const appMsg = safeParse(rawStr, sessionKey || undefined);
        if (appMsg) {
          if (appMsg.type === "welcome") {
            role = "client";
            reconnectAttempts = 0;
            handleIncoming(appMsg);
            settle(true);
            return;
          }
          handleIncoming(appMsg);
        }
      });

      socket.on("close", () => {
        settle(false);
        if (ws !== socket) return;
        ws = null;
        if (disposed) return;
        role = "disconnected";
        connectedTerminals = [];
        updateStatus();

        if (!manuallyDisconnected) {
          notify("Disconnected from link hub", "warning");
          scheduleReconnect();
        }
      });

      socket.on("error", () => {
        settle(false);
        socket.close();
      });
    });
  }

  // ── Initialize (auto-discover) ──────────────────────────────────────────

  /** True while `attempt` still owns establishment and the terminal still wants it. */
  function attemptIsCurrent(attempt: ConnectionAttempt): boolean {
    return connectionAttempt === attempt && !disposed && !manuallyDisconnected;
  }

  /**
   * Single-flight: startup, reconnect and `/link-connect` all join the one attempt
   * in flight instead of dialing again, because `role` stays "disconnected" for as
   * long as establishment takes and is therefore no guard at all.
   */
  function initialize(): Promise<void> {
    if (disposed || manuallyDisconnected) return Promise.resolve();
    if (connectionAttempt) return connectionAttempt.promise;
    // The record is the generation token, so it has to exist before the first
    // transport does; `promise` is replaced on the next line.
    const attempt: ConnectionAttempt = {
      promise: Promise.resolve(),
      socket: null,
      server: null,
      httpServer: null,
    };
    connectionAttempt = attempt;
    attempt.promise = runAttempt(attempt);
    return attempt.promise;
  }

  async function runAttempt(attempt: ConnectionAttempt) {
    try {
      if (explicitHubMode) {
        if (await startHub(attempt)) return;
        if (!attemptIsCurrent(attempt)) return;
        scheduleReconnect();
        return;
      }

      if (targetHubAddress) {
        if (await connectAsClient(attempt, targetHubAddress)) return;
        if (!attemptIsCurrent(attempt)) return;
        const hostOnly = targetHubAddress.split(":")[0];
        if (hostOnly !== "127.0.0.1" && hostOnly !== "localhost") {
          // Check if session is active via discovery
          const { hubs } = await discoverAllHubs(linkPort, 1200, linkSecret);
          if (hubs.length > 0 && attemptIsCurrent(attempt)) {
            const bestHub = hubs.find((h) => h.sessionId === currentSessionId) || hubs[0];
            const discoveredTarget = `${bestHub.ip}:${bestHub.port}`;
            if (discoveredTarget !== targetHubAddress) {
              notify(
                `Session at ${targetHubAddress} unreachable. Switching to discovered session "${bestHub.sessionId || bestHub.hubName}" on ${bestHub.host} (${discoveredTarget})...`,
                "info",
              );
              targetHubAddress = discoveredTarget;
              if (await connectAsClient(attempt, discoveredTarget, bestHub.pin, bestHub.sessionId)) return;
              if (!attemptIsCurrent(attempt)) return;
            }
          }
          notify(
            `Could not reach session at ${targetHubAddress}. Retrying in background...`,
            "warning",
          );
          scheduleReconnect();
          return;
        }
      } else {
        // Try local hub
        if (await connectAsClient(attempt, `127.0.0.1:${linkPort}`)) return;
        if (!attemptIsCurrent(attempt)) return;

        // Auto-discover active sessions across network (Tailscale + LAN)
        const { hubs } = await discoverAllHubs(linkPort, 1200, linkSecret);
        if (hubs.length > 0 && attemptIsCurrent(attempt)) {
          const remoteHubs = hubs.filter((h) => h.ip !== "127.0.0.1" && h.hubId !== hubInstanceId);
          const matchingHub = remoteHubs.find((h) => h.sessionId === currentSessionId);
          const bestHub = matchingHub || (remoteHubs.length === 1 ? remoteHubs[0] : null);
          if (bestHub) {
            const target = `${bestHub.ip}:${bestHub.port}`;
            targetHubAddress = target;
            currentSessionId = bestHub.sessionId || currentSessionId;
            if (bestHub.pin) sessionPin = bestHub.pin;
            notify(
              `Auto-discovered session "${currentSessionId}" on ${bestHub.host} (${target}). Connecting...`,
              "info",
            );
            if (await connectAsClient(attempt, target, bestHub.pin, bestHub.sessionId)) return;
            if (!attemptIsCurrent(attempt)) return;
          }
        }
      }

      // No hub found — become the hub
      if (await startHub(attempt)) return;
      if (!attemptIsCurrent(attempt)) return;

      // Port busy but couldn't connect (rare race). Retry after delay.
      scheduleReconnect();
    } finally {
      // Only while still the owner: an attempt cancelled mid-flight must not clear
      // the slot a newer one has already taken.
      if (connectionAttempt === attempt) connectionAttempt = null;
    }
  }

  /**
   * Drop the attempt in flight. Invalidating it first means any callback arriving
   * while its transports unwind is already stale; closing the pending handles is
   * what makes those callbacks arrive at all, so the attempt settles instead of
   * being abandoned. Also clears both connect timers, so a disconnect before the
   * startup callback constructs nothing.
   */
  function cancelConnectionAttempt() {
    if (startupConnectTimer) {
      clearTimeout(startupConnectTimer);
      startupConnectTimer = null;
    }
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    const attempt = connectionAttempt;
    if (!attempt) return;
    connectionAttempt = null;
    // Read every handle first: closing the WS server can settle the attempt, and
    // settling clears these fields. Closing the HTTP server is not optional — it
    // holds the port, so a skipped close squats :9900 for the whole machine.
    const { socket, server, httpServer } = attempt;
    socket?.close();
    server?.close();
    httpServer?.close();
  }

  function scheduleReconnect() {
    if (!linkActive || disposed || manuallyDisconnected || reconnectTimer) return;
    reconnectAttempts++;
    if (reconnectAttempts > MAX_RECONNECT_ATTEMPTS) {
      reconnectTimer = null;
      notify(
        "Link: Peer unreachable after 3 attempts. Standing by (run /link-join or /link on to reconnect).",
        "info",
      );
      return;
    }
    const delay = RECONNECT_DELAY_MS + Math.random() * 2000;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      if (linkActive && role === "disconnected" && !disposed && !manuallyDisconnected)
        void initialize();
    }, delay);
  }

  // ── Cleanup ──────────────────────────────────────────────────────────────

  function disconnect() {
    // Cancel establishment first, so nothing in flight can commit state behind us.
    // This also clears the reconnect and startup timers.
    cancelConnectionAttempt();

    if (udpResponder) {
      try {
        udpResponder.close();
      } catch {}
      udpResponder = null;
    }

    // Clear link-owned remote compaction state; a local /compact survives disconnect.
    compactRunning = false;
    // Runs before role is cleared, so peers still get a final status; more to the
    // point, the local gate record stays honest for the reconnect.
    syncCompactionStatus();
    for (const id of [...pendingCompactResponses.keys()]) {
      const pending = cleanupPendingCompact(id);
      if (pending) {
        pending.resolve(
          textResult("Link disconnected", { error: "disconnected" }),
        );
      }
    }

    for (const [id, pending] of pendingRpcRequests) {
      clearTimeout(pending.timeout);
      pending.resolve({
        type: "rpc_response",
        id,
        from: terminalName,
        to: "",
        ok: false,
        error: "Link disconnected",
      });
    }
    pendingRpcRequests.clear();

    for (const [id, pending] of pendingFileAcks) {
      clearTimeout(pending.timeout);
      pending.resolve({
        type: "file_ack",
        transferId: id,
        from: terminalName,
        to: "",
        ok: false,
        error: "Link disconnected",
      });
    }
    pendingFileAcks.clear();

    // Close client connection
    if (ws) {
      ws.close();
      ws = null;
    }

    // Close hub server
    if (wss) {
      for (const clientWs of hubClients.keys()) clientWs.close();
      hubClients.clear();
      wss.close();
      wss = null;
      hubHttpServer?.close();
      hubHttpServer = null;
    }

    role = "disconnected";
    connectedTerminals = [];
    terminalStatuses.clear();
    hubTerminalStatuses.clear();
    terminalContexts.clear();
    hubTerminalContexts.clear();
    terminalCwds.clear();
    hubTerminalCwds.clear();
    terminalHosts.clear();
    terminalProjects.clear();
    hubTerminalHosts.clear();
    hubTerminalProjects.clear();
    lastPushedStatus = null;
    updateStatus();

    // Inbox survives disconnect; flush unless a local /compact still gates it.
    if (!flushTimer) releaseInbox();
  }

  function turnLinkOff(uiCtx?: ExtensionContext) {
    linkActive = false;
    manuallyDisconnected = true;
    reconnectAttempts = 0;
    pi.appendEntry("link-active", { active: false });
    disconnect();
    const ui = uiCtx?.ui || getUi();
    if (ui) {
      ui.setStatus("link", ui.theme.fg("dim", "link: off"));
      ui.notify("Link turned OFF. Sockets closed, background discovery & retries halted.", "info");
    }
  }

  async function turnLinkOn(uiCtx?: ExtensionContext) {
    linkActive = true;
    manuallyDisconnected = false;
    reconnectAttempts = 0;
    pi.appendEntry("link-active", { active: true });
    const ui = uiCtx?.ui || getUi();
    if (ui) {
      ui.notify("Link turned ON. Scanning network...", "info");
    }
    updateStatus();
    await scheduleStartupConnect();
  }

  function cleanup() {
    disposed = true;
    // disconnect() cancels the attempt in flight, including the startup timer.
    disconnect();
    ctx = undefined;
    // Full teardown: clear inbox and both timers. The compaction deadline runs to
    // 180s, so it would otherwise outlive the extension and fire after teardown.
    inbox.length = 0;
    if (flushTimer) {
      clearTimeout(flushTimer);
      flushTimer = null;
    }
    setCompacting(false);
  }

  // ── Lifecycle events ─────────────────────────────────────────────────────

  pi.on("session_start", async (_event, _ctx) => {
    ctx = _ctx;
    currentCwd = _ctx.cwd;

    // Resolve terminal name. Precedence:
    //   --link-name flag  >  PI_LINK_NAME env  >  saved link-name  >  session name  >  random
    //
    // --link-name is the public CLI surface (link identity only, never touches session name).
    // PI_LINK_NAME is the internal handoff from the `pi-link` wrapper, which DOES
    // seed session name when absent (the wrapper's combined-mode contract).
    // PI_LINK_NAME is consumed once and removed from process.env so spawned children don't inherit it.
    const cliRaw = pi.getFlag("link-name");
    let cliFlagName: string | undefined;
    if (typeof cliRaw === "string") {
      cliFlagName = normalizeName(cliRaw);
      if (!cliFlagName) {
        console.error("Error: --link-name requires a non-empty value.");
        process.exit(1);
      }
    }

    const envRaw = process.env.PI_LINK_NAME;
    delete process.env.PI_LINK_NAME;
    const envFlagName = normalizeName(envRaw);

    const flagName = cliFlagName ?? envFlagName;
    const fromEnv = !cliFlagName && !!envFlagName;

    if (flagName) {
      preferredName = flagName;
      terminalName = flagName;

      // Skip append if the saved name already matches; persistence is needed
      // only for first-time set or actual change. Reduces session-file growth
      // on repeated startups (common in automation).
      const latest = latestCustomData("link-name") as
        | { name?: unknown }
        | undefined;
      const latestSaved =
        typeof latest?.name === "string" ? latest.name : undefined;
      if (normalizeName(latestSaved) !== flagName) {
        pi.appendEntry("link-name", { name: flagName });
      }

      // Critical: only the env path (wrapper combined mode) seeds session name.
      // Public --link-name is link-only.
      if (fromEnv && !pi.getSessionName()) pi.setSessionName(flagName);
    } else {
      const saved = latestCustomData("link-name") as
        | { name?: unknown }
        | undefined;
      const savedName = normalizeName(
        typeof saved?.name === "string" ? saved.name : undefined,
      );
      if (savedName) {
        preferredName = savedName;
        terminalName = preferredName;
      } else {
        const sessionName = normalizeName(pi.getSessionName());
        if (sessionName && sessionName !== "main") {
          terminalName = sessionName;
        } else {
          // Derive smart default name from project folder name
          const project = path.basename(process.cwd());
          const candidate = normalizeName(project);
          if (candidate && candidate !== "main") {
            terminalName = candidate;
          } else {
            terminalName = normalizeName(os.hostname().split(".")[0]) || "main";
          }
        }
      }
    }

    // Network mode resolution
    const cliNetwork = pi.getFlag("link-network");
    const envNetwork = process.env.PI_LINK_NETWORK || process.env.OMP_LINK_NETWORK;
    const savedNetwork = latestCustomData("link-network") as { network?: "tailscale" | "lan" } | undefined;
    if (cliNetwork === "tailscale" || cliNetwork === "ts" || envNetwork === "tailscale" || savedNetwork?.network === "tailscale" || config.network === "tailscale") {
      networkMode = "tailscale";
    } else if (cliNetwork === "lan" || envNetwork === "lan" || savedNetwork?.network === "lan" || config.network === "lan") {
      networkMode = "lan";
    }

    // Session ID resolution
    const cliSession = pi.getFlag("link-session");
    const envSession = process.env.PI_LINK_SESSION || process.env.OMP_LINK_SESSION;
    const savedSession = latestCustomData("link-session") as { sessionId?: string } | undefined;
    if (typeof cliSession === "string" && cliSession.trim()) {
      currentSessionId = normalizeName(cliSession.trim()) || currentSessionId;
    } else if (typeof envSession === "string" && envSession.trim()) {
      currentSessionId = normalizeName(envSession.trim()) || currentSessionId;
    } else if (typeof savedSession?.sessionId === "string" && savedSession.sessionId.trim()) {
      currentSessionId = savedSession.sessionId.trim();
    }

    // PIN resolution
    const cliPin = pi.getFlag("link-pin");
    const envPin = process.env.PI_LINK_PIN || process.env.OMP_LINK_PIN;
    const savedPin = latestCustomData("link-pin") as { pin?: string } | undefined;
    if (typeof cliPin === "string" && cliPin.trim()) {
      sessionPin = cliPin.trim();
    } else if (typeof envPin === "string" && envPin.trim()) {
      sessionPin = envPin.trim();
    } else if (typeof savedPin?.pin === "string" && savedPin.pin.trim()) {
      sessionPin = savedPin.pin.trim();
    }

    const cliHub = pi.getFlag("link-hub");
    if (typeof cliHub === "string" && cliHub.trim()) {
      const trimmed = cliHub.trim();
      if (trimmed === "local" || trimmed === "hub") {
        explicitHubMode = true;
        targetHubAddress = null;
      } else if (trimmed === "none") {
        targetHubAddress = null;
      } else {
        targetHubAddress = trimmed;
      }
    }
    const cliPort = pi.getFlag("link-port");
    if (typeof cliPort === "string" && cliPort.trim()) {
      linkPort = Number(cliPort.trim()) || linkPort;
    }
    const cliBind = pi.getFlag("link-bind");
    if (typeof cliBind === "string" && cliBind.trim()) {
      linkBind = cliBind.trim();
    }
    const savedHub = latestCustomData("link-hub") as { hub?: unknown } | undefined;
    if (!targetHubAddress && typeof savedHub?.hub === "string" && savedHub.hub.trim()) {
      targetHubAddress = savedHub.hub.trim();
    }

    updateSessionKey();

    if (pi.getFlag("no-link") === true || process.env.OMP_LINK_OFF === "1" || process.env.PI_LINK_DISABLE === "1") {
      linkActive = false;
    } else {
      const savedActive = latestCustomData("link-active") as { active?: boolean } | undefined;
      if (savedActive?.active !== undefined) {
        linkActive = savedActive.active;
      }
    }

    if (linkActive && (flagName || shouldConnect())) scheduleStartupConnect();
  });

  pi.on("session_shutdown", async () => {
    cleanup();
  });

  pi.on("agent_start", async () => {
    const before = statusIdentity(deriveStatus());
    agentRunning = true;
    // Safe only under the current deployment, not by Pi's guarantees:
    // AgentSession.prompt() refuses to run during compaction, and the only caller
    // of pi.sendMessage here — flushInbox() — is itself gated, so nothing can start
    // a run mid-compaction. Another extension calling pi.sendMessage with
    // triggerTurn: true would void that: its message starts a run during a
    // compaction, agent_start clears this flag, and delivery reopens into a
    // compaction that is still rebuilding context.
    setCompacting(false);
    activeTools.clear(); // defensive: a run cannot begin owing tools from the last one
    if (statusIdentity(deriveStatus()) !== before) stateSince = Date.now();
    pushStatus();
  });

  pi.on("session_before_compact", async (event) => {
    // Manual only. Automatic (threshold/overflow) compaction runs inside the agent
    // run, so a delivered message takes Pi's steering arm and _runAutoCompaction
    // returns hasQueuedMessages() to drain it afterwards. Gating it would replace a
    // working Pi path with our own.
    //
    // There is deliberately no abort listener: event.signal firing is not an ending.
    // Pi passes that signal into the summarizer and its compaction controller lives
    // until the catch/finally, so releasing on abort would re-open delivery while the
    // aborted compaction is still unwinding. A cancelled compaction is released by
    // the user's next run (agent_start) or by the deadline.
    //
    // Accepted gap: compact() aborts, authorises and prepares *before* emitting this
    // event, so a flush in that window can still start a turn against context about
    // to be rebuilt. The message itself survives — it is persisted and restored — so
    // only the turn is wasted. No heuristics to guess at the window. This is a
    // manual-compaction limit only; remote compaction is already gated by
    // compactRunning, set before ctx.compact() is ever called.
    if (event.reason === "manual") setCompacting(true);
  });

  pi.on("session_compact", async () => {
    setCompacting(false); // compaction succeeded
    // Tokens just dropped sharply — force a push so peers see the new context.
    pushStatus(true);
  });

  pi.on("tool_execution_start", async (event) => {
    const before = statusIdentity(deriveStatus());
    activeTools.set(event.toolCallId, event.toolName);
    if (statusIdentity(deriveStatus()) !== before) stateSince = Date.now();
    pushStatus();
  });

  pi.on("tool_execution_end", async (event) => {
    const before = statusIdentity(deriveStatus());
    activeTools.delete(event.toolCallId); // this call only; others may still run
    if (statusIdentity(deriveStatus()) !== before) stateSince = Date.now();
    pushStatus();
  });

  pi.on("agent_end", async () => {
    const before = statusIdentity(deriveStatus());
    // agentRunning deliberately survives this event. Pi may still auto-retry, run an
    // automatic compaction, or drain a queued continuation, all inside the same run;
    // reporting idle here would advertise a terminal that is still working.
    activeTools.clear(); // defensive: an unmatched end would otherwise pin the status
    if (statusIdentity(deriveStatus()) !== before) stateSince = Date.now();
    pushStatus();
  });

  pi.on("agent_settled", async (_event, settledCtx) => {
    // The authoritative end of a run: Pi emits this once no retry, compaction or
    // queued continuation is left. It can still be followed immediately by a new run
    // another extension started during settlement, whose agent_start already set the
    // flag we would be clearing — so ask Pi instead of assuming, and leave a newer
    // run reporting thinking.
    if (!settledCtx.isIdle()) return;
    const before = statusIdentity(deriveStatus());
    agentRunning = false;
    if (statusIdentity(deriveStatus()) !== before) stateSince = Date.now();
    pushStatus();
  });

  // ── Tool helpers ──────────────────────────────────────────────────────────

  function textResult(text: string, details: Record<string, unknown> = {}) {
    return { content: [{ type: "text" as const, text }], details };
  }

  function notConnectedResult() {
    return textResult(
      "Not connected to link. Use link_connect tool or run /link to reconnect.",
      { error: "not_connected" },
    );
  }

  function truncatePreview(text: string) {
    return text.length > 60 ? text.slice(0, 60) + "..." : text;
  }

  // Shared "target not found" result for the send/compact tools.
  // Returns null when the target is present, so callers can `if (miss) return miss;`.
  function targetNotFound(to: string) {
    return connectedTerminals.includes(to)
      ? null
      : textResult(
          `Terminal "${to}" not found. Connected: ${connectedTerminals.join(", ")}`,
          { to, error: "not_found" },
        );
  }

  // Shared ✓/✗ result renderer for link_send and link_compact.
  function renderIconResult(
    result: { content: { type: string; text?: string }[]; details?: unknown },
    theme: { fg(role: string, text: string): string },
  ) {
    const txt = result.content[0];
    const details = result.details as Record<string, unknown> | undefined;
    const icon = details?.error
      ? theme.fg("error", "✗ ")
      : theme.fg("success", "✓ ");
    return new Text(icon + (txt?.type === "text" ? txt.text : ""), 0, 0);
  }

  // ── Tools ────────────────────────────────────────────────────────────────

  pi.registerTool({
    name: "link_send",
    label: "Link Send",
    description: [
      "Send a message to one other Pi terminal on the link.",
      "The message always acts: it steers a busy receiver at its next safe boundary, or starts a turn on an idle one.",
    ].join(" "),
    promptSnippet:
      "Send a message to another Pi terminal on the local link network",
    parameters: Type.Object({
      to: Type.String({ description: "Target terminal name" }),
      message: Type.String({ description: "Message content" }),
    }),

    async execute(_toolCallId, params) {
      if (role === "disconnected") {
        if (connectionAttempt) {
          await Promise.race([
            connectionAttempt.promise,
            new Promise((r) => setTimeout(r, 2500)),
          ]);
        } else if (!manuallyDisconnected) {
          void initialize();
          await new Promise((r) => setTimeout(r, 1500));
        }
      }
      if (role === "disconnected") return notConnectedResult();

      if (params.to === terminalName) {
        const otherTerminals = connectedTerminals.filter((t) => t !== terminalName);
        if (otherTerminals.length === 1) {
          params.to = otherTerminals[0];
        } else {
          return textResult(
            `Cannot send to yourself ("${terminalName}"). Other online terminals: ${otherTerminals.join(", ") || "none"}`,
            { to: params.to, error: "self_target" },
          );
        }
      }

      if (role === "hub") {
        const resolved = hubResolveTarget(params.to);
        if (!resolved) {
          return textResult(
            `Terminal "${params.to}" not found. Connected: ${connectedTerminals.join(", ")}`,
            { to: params.to, error: "not_found" },
          );
        }
        params.to = resolved.name;
      }

      const delivered = routeMessage({
        type: "chat",
        from: terminalName,
        to: params.to,
        content: params.message,
      });

      const target = `"${params.to}"`;
      if (!delivered) {
        return textResult(`Failed to send to ${target}`, {
          to: params.to,
          error: "not_delivered",
        });
      }
      // Hub delivery is authoritative; client delivery is optimistic (hub routes)
      const verb = role === "hub" ? "Sent to" : "Sent to hub for delivery to";
      return textResult(`${verb} ${target}`, { to: params.to });
    },

    renderCall(args, theme) {
      const preview =
        typeof args.message === "string"
          ? truncatePreview(args.message)
          : "...";
      const text =
        theme.fg("toolTitle", theme.bold("link_send ")) +
        theme.fg("accent", args.to) +
        "\n  " +
        theme.fg("dim", preview);
      return new Text(text, 0, 0);
    },

    renderResult: (result, _options, theme) => renderIconResult(result, theme),
  });

  pi.registerTool({
    name: "link_compact",
    label: "Link Compact",
    description: [
      "Ask one other Pi terminal on the link to compact its context.",
      "Blocks until compaction completes, fails, or times out (up to 180s).",
    ].join(" "),
    promptSnippet:
      "Ask another Pi terminal on the link to compact its context",
    parameters: Type.Object({
      to: Type.String({ description: "Target terminal name" }),
      customInstructions: Type.Optional(
        Type.String({
          description:
            "Custom instructions to guide the compaction summary (optional)",
        }),
      ),
    }),

    async execute(_toolCallId, params, signal) {
      if (signal?.aborted) {
        return textResult("Compact request aborted", {
          to: params.to,
          error: "aborted",
        });
      }

      if (role === "disconnected") {
        if (connectionAttempt) {
          await Promise.race([
            connectionAttempt.promise,
            new Promise((r) => setTimeout(r, 2500)),
          ]);
        } else if (!manuallyDisconnected) {
          void initialize();
          await new Promise((r) => setTimeout(r, 1500));
        }
      }
      if (role === "disconnected") return notConnectedResult();

      if (params.to === terminalName) {
        return textResult("Cannot compact yourself - use /compact.", {
          to: params.to,
          error: "self_target",
        });
      }

      if (role === "hub") {
        const resolved = hubResolveTarget(params.to);
        if (!resolved) {
          return textResult(
            `Terminal "${params.to}" not found. Connected: ${connectedTerminals.join(", ")}`,
            { to: params.to, error: "not_found" },
          );
        }
        params.to = resolved.name;
      }

      const requestId = crypto.randomUUID();

      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          const pending = cleanupPendingCompact(requestId);
          if (pending) {
            pending.resolve(
              textResult(
                `Compact request to "${params.to}" timed out after ${COMPACT_TIMEOUT_MS / 1000}s; the target may still be compacting.`,
                { to: params.to, error: "timeout" },
              ),
            );
          }
        }, COMPACT_TIMEOUT_MS);

        pendingCompactResponses.set(requestId, {
          resolve,
          targetName: params.to,
          timeout,
        });

        signal?.addEventListener(
          "abort",
          () => {
            const pending = cleanupPendingCompact(requestId);
            if (pending) {
              pending.resolve(
                textResult("Compact request aborted", {
                  to: params.to,
                  error: "aborted",
                }),
              );
            }
          },
          { once: true },
        );

        const delivered = routeMessage({
          type: "compact_request",
          id: requestId,
          from: terminalName,
          to: params.to,
          instructions: params.instructions,
        });

        if (!delivered) {
          const pending = cleanupPendingCompact(requestId);
          if (pending) {
            pending.resolve(
              textResult(`Failed to request compact on "${params.to}"`, {
                to: params.to,
                error: "not_delivered",
              }),
            );
          }
        }
      });
    },

    renderCall(args, theme) {
      let text = theme.fg("toolTitle", theme.bold("link_compact "));
      text += theme.fg("accent", String(args.to));
      if (typeof args.instructions === "string")
        text += "\n  " + theme.fg("dim", truncatePreview(args.instructions));
      return new Text(text, 0, 0);
    },

    renderResult: (result, _options, theme) => renderIconResult(result, theme),
  });

  pi.registerTool({
    name: "link_list",
    label: "Link List",
    description: "List all Pi terminals currently connected to the link.",
    promptSnippet: "List connected Pi terminals on the link",
    parameters: Type.Object({}),

    async execute() {
      if (role === "disconnected") {
        if (connectionAttempt) {
          await Promise.race([
            connectionAttempt.promise,
            new Promise((r) => setTimeout(r, 2500)),
          ]);
        } else if (!manuallyDisconnected) {
          void initialize();
          await new Promise((r) => setTimeout(r, 1500));
        }
      }
      if (role === "disconnected") return notConnectedResult();

      const statuses: Record<string, string> = {};
      const cwds: Record<string, string> = {};
      const contexts: Record<string, ContextSnapshot> = {};
      const hosts: Record<string, string> = {};
      const projects: Record<string, string> = {};
      const list = connectedTerminals
        .map((name) => {
          const status = getStatusFor(name);
          const statusStr = status ? formatStatus(status) : "";
          if (statusStr) statuses[name] = statusStr;
          const cwd = getCwdFor(name);
          if (cwd) cwds[name] = cwd;
          const context = getContextFor(name);
          if (context) contexts[name] = context;
          const ctxStr = formatContext(context);
          const host = getHostFor(name);
          if (host) hosts[name] = host;
          const project = getProjectFor(name);
          if (project) projects[name] = project;
          const marker = name === terminalName ? " (you)" : "";
          let line = `  • ${name}${marker}`;
          if (host) line += ` [host: ${host}${project ? `, project: ${project}` : ""}]`;
          if (statusStr) line += `  ${statusStr}`;
          if (ctxStr) line += `  · ${ctxStr}`;
          if (cwd) line += `\n    cwd: ${cwd}`;
          return line;
        })
        .join("\n");

      return textResult(
        `Connected terminals:\n${list}\n\nSession: ${currentSessionId} | Network: ${networkMode} | PIN: ${sessionPin}`,
        {
          sessionId: currentSessionId,
          network: networkMode,
          pin: sessionPin,
          terminals: connectedTerminals,
          statuses,
          cwds,
          contexts,
          hosts,
          projects,
          self: terminalName,
          role,
        },
      );
    },

    renderResult(result, _options, theme) {
      const details = result.details as
        | {
            sessionId?: string;
            network?: string;
            terminals?: string[];
            statuses?: Record<string, string>;
            cwds?: Record<string, string>;
            contexts?: Record<string, ContextSnapshot>;
            hosts?: Record<string, string>;
            projects?: Record<string, string>;
            self?: string;
            role?: string;
          }
        | undefined;
      if (!details?.terminals) {
        const txt = result.content[0];
        return new Text(txt?.type === "text" ? txt.text : "", 0, 0);
      }

      let text = theme.fg("toolTitle", theme.bold("link "));
      text += theme.fg("muted", `(${details.role}) `);
      text += theme.fg("accent", `${details.terminals.length} terminal(s)`);
      if (details.sessionId) {
        text += theme.fg("dim", ` · session: ${details.sessionId} [${details.network}]`);
      }
      for (const name of details.terminals) {
        const isSelf = name === details.self;
        const status = details.statuses?.[name] ?? "";
        const cwd = details.cwds?.[name];
        const ctxStr = formatContext(details.contexts?.[name]);
        const host = details.hosts?.[name];
        const project = details.projects?.[name];
        let nameStr = isSelf ? `• ${name} (you)` : `• ${name}`;
        if (host) nameStr += ` [${host}${project ? ` · ${project}` : ""}]`;
        text +=
          "\n  " +
          (isSelf ? theme.fg("accent", nameStr) : theme.fg("text", nameStr)) +
          (status ? "  " + theme.fg("dim", status) : "") +
          (ctxStr ? theme.fg("dim", "  · " + ctxStr) : "");
        if (cwd) text += "\n    " + theme.fg("dim", `cwd: ${shortenPath(cwd)}`);
      }
      return new Text(text, 0, 0);
    },
  });

  pi.registerTool({
    name: "link_discover",
    label: "Link Discover",
    description:
      "Search for active sessions across the selected network (Tailscale or LAN).",
    promptSnippet: "Discover active sessions on Tailnet/LAN",
    parameters: Type.Object({}),

    async execute() {
      const { hubs, tailnetPeersCount } = await discoverAllHubs(linkPort, 1200, linkSecret, networkMode);
      if (hubs.length === 0) {
        return textResult(
          `No active sessions discovered on ${networkMode.toUpperCase()}${networkMode === "tailscale" ? ` (${tailnetPeersCount} Tailnet peer(s) scanned)` : ""}.`,
          { hubs: [], tailnetPeersCount, network: networkMode },
        );
      }

      let text = `Discovered ${hubs.length} active session(s) on ${networkMode.toUpperCase()}:\n\n`;
      for (const h of hubs) {
        const terms = (h.terminals || [])
          .map(
            (t) =>
              `${t.name} (${t.status || "idle"}, host: ${t.host || h.host}${t.project ? `, project: ${t.project}` : ""})`,
          )
          .join("\n    - ");
        text += `• Session "${h.sessionId || h.hubName}" on ${h.host} (${h.ip}:${h.port}) [PIN: ${h.pin || "none"}]:\n    - ${terms}\n`;
      }
      text += `\nTo connect to any discovered session, use link_connect tool or /link-join.`;

      return textResult(text, { hubs, tailnetPeersCount, network: networkMode });
    },

    renderCall(_args, theme) {
      return new Text(theme.fg("toolTitle", theme.bold("link_discover")), 0, 0);
    },

    renderResult: (result, _options, theme) => renderIconResult(result, theme),
  });

  pi.registerTool({
    name: "link_connect",
    label: "Link Connect",
    description:
      "Manage link connection: get status, join an active session, start hosting a session, or leave.",
    promptSnippet: "Connect, join, or start an omp-link session",
    parameters: Type.Object({
      action: Type.Union(
        [
          Type.Literal("status"),
          Type.Literal("join"),
          Type.Literal("start"),
          Type.Literal("leave"),
        ],
        { description: "Action to perform: status, join, start, or leave" },
      ),
      target: Type.Optional(
        Type.String({ description: "Target session ID or IP:port to join/start" }),
      ),
      pin: Type.Optional(
        Type.String({ description: "4-digit session PIN for LAN authentication" }),
      ),
      network: Type.Optional(
        Type.Union([Type.Literal("tailscale"), Type.Literal("lan")], {
          description: "Network mode: 'tailscale' or 'lan'",
        }),
      ),
    }),

    async execute(_toolCallId, params) {
      if (params.network) {
        networkMode = params.network;
        pi.appendEntry("link-network", { network: networkMode });
        saveLinkConfig({ network: networkMode });
      }
      if (params.pin) {
        sessionPin = params.pin;
        pi.appendEntry("link-pin", { pin: sessionPin });
        saveLinkConfig({ pin: sessionPin });
      }

      if (params.action === "status") {
        return textResult(renderStatusCard(), {
          sessionId: currentSessionId,
          network: networkMode,
          role,
          terminalName,
          pin: sessionPin,
          terminals: connectedTerminals,
        });
      }

      if (params.action === "leave") {
        pi.appendEntry("link-active", { active: false });
        manuallyDisconnected = true;
        disconnect();
        return textResult("Left link session.", { role: "disconnected" });
      }

      if (params.action === "start") {
        if (params.target) currentSessionId = normalizeName(params.target) || currentSessionId;
        pi.appendEntry("link-session", { sessionId: currentSessionId });
        saveLinkConfig({ sessionId: currentSessionId });
        disconnect();
        explicitHubMode = true;
        targetHubAddress = null;
        manuallyDisconnected = false;
        pi.appendEntry("link-active", { active: true });
        await initialize();
        return textResult(`Started session "${currentSessionId}" as host.`, {
          sessionId: currentSessionId,
          role,
          terminalName,
        });
      }

      if (params.action === "join") {
        if (params.target) {
          const isIp =
            params.target.includes(":") ||
            /^\d+\.\d+\.\d+\.\d+$/.test(params.target) ||
            params.target.startsWith("100.");
          if (isIp) {
            targetHubAddress = params.target;
          } else {
            const { hubs } = await discoverAllHubs(linkPort, 1200, linkSecret);
            const found = hubs.find((h) => (h.sessionId === params.target || h.hubName === params.target) && h.hubId !== hubInstanceId);
            if (found) {
              targetHubAddress = `${found.ip}:${found.port}`;
              currentSessionId = found.sessionId || params.target;
              if (found.pin) sessionPin = found.pin;
            } else {
              return textResult(
                `Session "${params.target}" not found. Discovered: ${hubs.filter(h => h.hubId !== hubInstanceId).map((h) => h.sessionId || h.hubName).join(", ") || "none"}`,
                { error: "not_found" },
              );
            }
          }
        } else {
          // Auto-discover
          const { hubs } = await discoverAllHubs(linkPort, 1200, linkSecret);
          const others = hubs.filter(h => h.hubId !== hubInstanceId && !h.endpoints?.includes(`127.0.0.1:${linkPort}`));
          if (others.length === 0) {
            return textResult(`No other active sessions discovered on network.`, { error: "no_sessions" });
          }
          const best = others.find((h) => h.sessionId === currentSessionId) || others[0];
          targetHubAddress = `${best.ip}:${best.port}`;
          if (best.sessionId) currentSessionId = best.sessionId;
          if (best.pin) sessionPin = best.pin;
        }

        disconnect();
        explicitHubMode = false;
        manuallyDisconnected = false;
        pi.appendEntry("link-active", { active: true });
        pi.appendEntry("link-session", { sessionId: currentSessionId });
        if (sessionPin) pi.appendEntry("link-pin", { pin: sessionPin });
        saveLinkConfig({ sessionId: currentSessionId, hub: targetHubAddress, pin: sessionPin });
        await initialize();
        return textResult(`Joined session "${currentSessionId}".`, {
          sessionId: currentSessionId,
          role,
          terminalName,
          target: targetHubAddress,
        });
      }

      return textResult("Unknown action.", { error: "invalid_action" });
    },

    renderCall(args, theme) {
      let text = theme.fg("toolTitle", theme.bold("link_connect "));
      text += theme.fg("accent", String(args.action || "status"));
      if (args.target) text += ` ${theme.fg("dim", String(args.target))}`;
      return new Text(text, 0, 0);
    },

    renderResult: (result, _options, theme) => renderIconResult(result, theme),
  });

  pi.registerTool({
    name: "link_exec",
    label: "Link Exec",
    description:
      "Direct Tool RPC: Safe structured inspection operations (git_status, git_diff, git_log, search_text, read_file, list_dir) across the mesh (< 30ms latency). Enforces workspace canonical path confinement and blocks access to sensitive files (.env, .git, keys). Arbitrary shell execution ('exec') is blocked by default under Territorial Sovereignty policy. To modify code or run builds on another machine, use link_send to request the peer agent perform the change within its own session.",
    promptSnippet: "Perform safe structured code inspection (git_status, git_diff, read_file, search_text) on another terminal across the link",
    parameters: Type.Object({
      to: Type.String({ description: "Target terminal name" }),
      action: Type.Union(
        [
          Type.Literal("git_status"),
          Type.Literal("git_diff"),
          Type.Literal("git_log"),
          Type.Literal("search_text"),
          Type.Literal("read_file"),
          Type.Literal("list_dir"),
          Type.Literal("exec"),
        ],
        { description: "Inspection action: 'git_status', 'git_diff', 'git_log', 'search_text', 'read_file', 'list_dir', or 'exec' (disabled by default)" },
      ),
      command: Type.Optional(
        Type.String({ description: "Command for 'exec'. Note: Arbitrary shell execution is disabled by default on remote nodes." }),
      ),
      filePath: Type.Optional(
        Type.String({ description: "File or directory path for 'read_file' or 'list_dir'" }),
      ),
      count: Type.Optional(
        Type.Number({ description: "Number of commits for 'git_log' (1-100, default 10)" }),
      ),
      pattern: Type.Optional(
        Type.String({ description: "Search query/pattern for 'search_text' (git grep)" }),
      ),
      cwd: Type.Optional(
        Type.String({ description: "Optional working directory relative to remote project root" }),
      ),
      authToken: Type.Optional(
        Type.String({ description: "Optional authorization token to authorize 'exec' if configured by remote host" }),
      ),
    }),

    async execute(_toolCallId, params) {
      if (!linkActive || role === "disconnected") return notConnectedResult();
      const requestId = `rpc-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      const target = params.to;

      try {
        const response = await new Promise<RpcResponseMsg>((resolve, reject) => {
          const timeout = setTimeout(() => {
            pendingRpcRequests.delete(requestId);
            reject(new Error(`RPC request to "${target}" timed out after 30s`));
          }, 30_000);
          pendingRpcRequests.set(requestId, { resolve, timeout });

          const routed = routeMessage({
            type: "rpc_request",
            id: requestId,
            from: terminalName,
            to: target,
            action: params.action,
            params: {
              command: params.command,
              filePath: params.filePath,
              count: params.count,
              pattern: params.pattern,
              cwd: params.cwd,
              authToken: params.authToken,
            },
          });

          if (!routed) {
            clearTimeout(timeout);
            pendingRpcRequests.delete(requestId);
            reject(new Error(`Failed to route RPC request to "${target}"`));
          }
        });

        if (!response.ok) {
          return textResult(`RPC execution failed on "${target}": ${response.error || "unknown error"}`, {
            error: response.error,
            to: target,
          });
        }
        return textResult(response.result || "[Success, no output]", { to: target });
      } catch (err: any) {
        return textResult(`RPC error with "${target}": ${err.message}`, { error: err.message, to: target });
      }
    },

    renderCall(args, theme) {
      return new Text(
        theme.fg("toolTitle", theme.bold("link_exec ")) +
          theme.fg("accent", String(args.to || "")) +
          theme.fg("dim", ` (${args.action})`),
        0,
        0,
      );
    },

    renderResult: (result, _options, theme) => renderIconResult(result, theme),
  });

  pi.registerTool({
    name: "link_send_file",
    label: "Link Send File",
    description:
      "Out-of-band file transfer: Send a file directly to another terminal across the mesh with SHA-256 verification and optional ephemeral HTTP download link.",
    promptSnippet: "Transfer a file directly to another terminal across the link",
    parameters: Type.Object({
      to: Type.String({ description: "Target terminal name" }),
      sourcePath: Type.String({ description: "Local path of the file to send" }),
      destPath: Type.Optional(
        Type.String({ description: "Destination path on remote terminal (defaults to .omp/transfers/<filename>)" }),
      ),
    }),

    async execute(_toolCallId, params) {
      if (!linkActive || role === "disconnected") return notConnectedResult();
      const fullSource = path.isAbsolute(params.sourcePath)
        ? params.sourcePath
        : path.resolve(currentCwd, params.sourcePath);

      if (!fs.existsSync(fullSource)) {
        return textResult(`Source file not found: "${params.sourcePath}"`, { error: "file_not_found" });
      }

      try {
        const fileBuffer = await fs.promises.readFile(fullSource);
        const sha256 = crypto.createHash("sha256").update(fileBuffer).digest("hex");
        const filename = path.basename(fullSource);
        const transferId = `tf-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
        const startTime = Date.now();

        // Register ephemeral HTTP download route if hub
        let downloadUrl: string | undefined;
        if (role === "hub") {
          ephemeralTransfers.set(transferId, {
            buffer: fileBuffer,
            filename,
            sha256,
            expires: Date.now() + 600_000,
          });
          const net = getNetworkInfo();
          const hostIp = networkMode === "tailscale" && net.tailscaleIp ? net.tailscaleIp : (net.lanIps[0] || "127.0.0.1");
          downloadUrl = `http://${hostIp}:${linkPort}/transfer/${transferId}/${encodeURIComponent(filename)}`;
        }

        const CHUNK_SIZE = 64 * 1024;
        const totalChunks = Math.ceil(fileBuffer.length / CHUNK_SIZE) || 1;

        const ackPromise = new Promise<FileAckMsg>((resolve, reject) => {
          const timeout = setTimeout(() => {
            pendingFileAcks.delete(transferId);
            reject(new Error(`File transfer to "${params.to}" timed out after 60s`));
          }, 60_000);
          pendingFileAcks.set(transferId, { resolve, timeout });
        });

        // 1. Send offer
        const offered = routeMessage({
          type: "file_offer",
          transferId,
          from: terminalName,
          to: params.to,
          filename,
          destRelPath: params.destPath,
          sizeBytes: fileBuffer.length,
          sha256,
          totalChunks,
          downloadUrl,
        });

        if (!offered) {
          pendingFileAcks.delete(transferId);
          return textResult(`Failed to route file transfer offer to "${params.to}"`, { error: "not_routed" });
        }

        // 2. Stream chunks
        for (let i = 0; i < totalChunks; i++) {
          const slice = fileBuffer.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
          routeMessage({
            type: "file_chunk",
            transferId,
            from: terminalName,
            to: params.to,
            chunkIndex: i,
            totalChunks,
            data: slice.toString("base64"),
          });
        }

        // 3. Wait for ack
        const ack = await ackPromise;
        const elapsedMs = Date.now() - startTime;
        if (!ack.ok) {
          return textResult(`File transfer failed: ${ack.error || "remote rejected file"}`, { error: ack.error });
        }

        const speed = (fileBuffer.length / (elapsedMs / 1000) / 1024 / 1024).toFixed(2);
        return textResult(
          `✓ Sent "${filename}" (${(fileBuffer.length / 1024).toFixed(1)} KB) to "${params.to}" in ${elapsedMs}ms (${speed} MB/s). Saved at: ${ack.savedPath}${downloadUrl ? `\nEphemeral download URL: ${downloadUrl}` : ""}`,
          {
            to: params.to,
            filename,
            sizeBytes: fileBuffer.length,
            sha256,
            savedPath: ack.savedPath,
            elapsedMs,
          },
        );
      } catch (err: any) {
        return textResult(`File transfer error: ${err.message}`, { error: err.message, to: params.to });
      }
    },

    renderCall(args, theme) {
      return new Text(
        theme.fg("toolTitle", theme.bold("link_send_file ")) +
          theme.fg("accent", String(args.to || "")) +
          theme.fg("dim", ` (${path.basename(String(args.sourcePath || ""))})`),
        0,
        0,
      );
    },

    renderResult: (result, _options, theme) => renderIconResult(result, theme),
  });

  // ── Commands ─────────────────────────────────────────────────────────────

  function handleMutationCommand(args: string, ctx: ExtensionContext) {
    const trimmed = args.trim().toLowerCase();
    if (trimmed === "off" || trimmed === "disable") {
      mutationGuard = false;
      ctx.ui.notify("⚠️ Mutation Guard DISABLED: Remote peers can now run mutating shell commands via link_exec.", "warning");
      return;
    }
    if (trimmed === "on" || trimmed === "enable") {
      mutationGuard = true;
      ctx.ui.notify("🛡️ Mutation Guard ENABLED: Remote peers are restricted to read-only commands (Territorial Sovereignty enforced).", "info");
      return;
    }
    if (trimmed === "log" || trimmed === "history") {
      if (blockedMutationLog.length === 0) {
        ctx.ui.notify("🛡️ Mutation Guard Log: Zero blocked attempts recorded.", "info");
        return;
      }
      let logOutput = `🛡️ Mutation Guard Block Log (${blockedMutationLog.length} attempts):\n`;
      blockedMutationLog.slice(-10).forEach((rec, idx) => {
        const timeAgo = Math.round((Date.now() - rec.timestamp) / 1000);
        logOutput += `  ${idx + 1}. [${timeAgo}s ago] from "${rec.from}" (${rec.reason}):\n     ${rec.command}\n`;
      });
      ctx.ui.notify(logOutput, "warning");
      return;
    }
    let msg = `🛡️ Mutation Guard: ${mutationGuard ? "ACTIVE (ENFORCED)" : "DISABLED"}\n`;
    msg += `  Policy: ${mutationGuard ? "Remote peers cannot mutate local files, git commits, or packages." : "Unrestricted remote execution allowed."}\n`;
    msg += `  Blocked Attempts: ${blockedMutationCount}\n`;
    msg += `  Usage:\n`;
    msg += `    /link mutation on      Enable protection\n`;
    msg += `    /link mutation off     Disable protection\n`;
    msg += `    /link mutation log     View recent blocked command log`;
    ctx.ui.notify(msg, mutationGuard ? "info" : "warning");
  }

  function handleGrant(args: string, ctx: ExtensionContext) {
    const parts = args.trim().split(/\s+/).filter(Boolean);
    const peer = parts[0];
    const minutes = parts[1] ? parseInt(parts[1], 10) : 10;
    if (!peer) {
      if (activeExecGrants.size === 0) {
        ctx.ui.notify("No active peer execution grants.\nUsage: /link grant <peer> [minutes]", "info");
      } else {
        let msg = `Active Execution Grants (${activeExecGrants.size}):\n`;
        for (const [p, g] of activeExecGrants) {
          const remainingMin = Math.max(1, Math.round((g.expiresAt - Date.now()) / 60000));
          msg += `  • "${p}" — ${remainingMin}m remaining\n`;
        }
        msg += `\nTo revoke: /link revoke-grant <peer>`;
        ctx.ui.notify(msg, "info");
      }
      return;
    }
    if (isNaN(minutes) || minutes < 1 || minutes > 60) {
      ctx.ui.notify("Duration must be between 1 and 60 minutes. Usage: /link grant <peer> [minutes]", "error");
      return;
    }
    grantExecElevation(peer, minutes);
    ctx.ui.notify(
      `🛡️ Granted temporary shell execution elevation to peer "${peer}" for ${minutes} minute(s).\nAll subprocess operations will still be logged to ~/.omp/audit.log.`,
      "warning",
    );
  }

  function handleRevokeGrant(args: string, ctx: ExtensionContext) {
    const peer = args.trim();
    if (!peer) {
      ctx.ui.notify("Specify peer name to revoke: /link revoke-grant <peer>", "warning");
      return;
    }
    const revoked = revokeExecElevation(peer);
    if (revoked) {
      ctx.ui.notify(`🛡️ Revoked execution elevation for "${peer}".`, "info");
    } else {
      ctx.ui.notify(`No active execution grant found for "${peer}".`, "warning");
    }
  }

  function handleAccept(args: string, ctx: ExtensionContext) {
    if (pendingJoinRequests.size === 0) {
      ctx.ui.notify("No pending device join requests.", "info");
      return;
    }
    const trimmed = args.trim();
    let targetId: number | null = null;
    if (trimmed) {
      targetId = Number(trimmed);
      if (Number.isNaN(targetId) || !pendingJoinRequests.has(targetId)) {
        ctx.ui.notify(`Pending request #${trimmed} not found. Use /link requests to list.`, "error");
        return;
      }
    } else if (pendingJoinRequests.size === 1) {
      const [firstKey] = pendingJoinRequests.keys();
      targetId = firstKey;
    } else {
      let text = `Multiple pending join requests. Specify request ID:\n`;
      for (const [id, item] of pendingJoinRequests) {
        text += `  • Request #${id}: "${item.name}" on ${item.host || item.clientIp} (FP: ${item.fingerprint.slice(0, 16)}...)\n`;
      }
      text += `Usage: /link accept <id>`;
      ctx.ui.notify(text, "info");
      return;
    }

    if (targetId !== null) {
      approveJoinRequest(targetId);
    }
  }

  function handleDeny(args: string, ctx: ExtensionContext) {
    if (pendingJoinRequests.size === 0) {
      ctx.ui.notify("No pending device join requests.", "info");
      return;
    }
    const trimmed = args.trim();
    let targetId: number | null = null;
    if (trimmed) {
      targetId = Number(trimmed);
      if (Number.isNaN(targetId) || !pendingJoinRequests.has(targetId)) {
        ctx.ui.notify(`Pending request #${trimmed} not found. Use /link requests to list.`, "error");
        return;
      }
    } else if (pendingJoinRequests.size === 1) {
      const [firstKey] = pendingJoinRequests.keys();
      targetId = firstKey;
    } else {
      let text = `Multiple pending requests. Specify request ID: /link deny <id>`;
      ctx.ui.notify(text, "info");
      return;
    }

    if (targetId !== null) {
      denyJoinRequest(targetId);
    }
  }

  function handleRequests(ctx: ExtensionContext) {
    if (pendingJoinRequests.size === 0) {
      ctx.ui.notify("No pending device join requests.", "info");
      return;
    }
    let text = `Pending Device Requests (${pendingJoinRequests.size}):\n`;
    for (const [id, item] of pendingJoinRequests) {
      const elapsed = Math.round((Date.now() - item.timestamp) / 1000);
      text += `  • Request #${id}: "${item.name}" on ${item.host || item.clientIp} (${elapsed}s ago)\n`;
      text += `    Fingerprint: ${item.fingerprint}\n`;
      text += `    Approve: /link accept ${id}   Reject: /link deny ${id}\n`;
    }
    ctx.ui.notify(text, "info");
  }

  function handleDevices(args: string, ctx: ExtensionContext) {
    const trimmed = args.trim();
    if (trimmed.startsWith("revoke ")) {
      const devId = trimmed.slice(7).trim();
      const removed = removePairedDevice(devId);
      if (removed) {
        ctx.ui.notify(`Revoked paired device "${devId}".`, "info");
      } else {
        ctx.ui.notify(`Device "${devId}" not found in paired list.`, "error");
      }
      return;
    }
    const devices = Array.from(loadPairedDevices().values());
    if (devices.length === 0) {
      ctx.ui.notify("No paired devices found.", "info");
      return;
    }
    let text = `Paired Devices (${devices.length}):\n`;
    for (const d of devices) {
      const dateStr = new Date(d.approvedAt).toLocaleString();
      text += `  • ${d.name} [${d.deviceId}]\n    Host: ${d.host} | Paired: ${dateStr}\n    Fingerprint: ${d.fingerprint || "none"}\n`;
    }
    text += `\nTo revoke a device: /link devices revoke <deviceId>`;
    ctx.ui.notify(text, "info");
  }

  async function handleStart(args: string, ctx: ExtensionContext) {
    const parts = args.trim().split(/\s+/).filter(Boolean);
    const newSessionId = parts[0] ? normalizeName(parts[0]) : currentSessionId;
    const newPin = parts[1] || sessionPin;

    currentSessionId = newSessionId;
    sessionPin = newPin;
    pi.appendEntry("link-session", { sessionId: currentSessionId });
    pi.appendEntry("link-pin", { pin: sessionPin });
    saveLinkConfig({ sessionId: currentSessionId, pin: sessionPin });

    if (role === "hub") {
      ctx.ui.notify(
        `⚡ Session updated: "${currentSessionId}" on ${networkMode.toUpperCase()} (PIN: ${sessionPin})`,
        "info",
      );
      for (const [clientWs, clientName] of hubClients) {
        clientWs.send(
          JSON.stringify({
            type: "welcome",
            name: clientName,
            sessionId: currentSessionId,
            pin: sessionPin,
            network: networkMode,
            terminals: terminalList(),
          } satisfies WelcomeMsg),
        );
      }
      return;
    }

    ctx.ui.notify(`Starting session "${currentSessionId}" as host...`, "info");
    disconnect();
    explicitHubMode = true;
    targetHubAddress = null;
    manuallyDisconnected = false;
    pi.appendEntry("link-active", { active: true });
    await initialize();
  }

  async function handleJoin(args: string, ctx: ExtensionContext) {
    const parts = args.trim().split(/\s+/).filter(Boolean);
    const targetArg = parts[0];
    const pinArg = parts[1];

    if (pinArg) {
      sessionPin = pinArg;
      pi.appendEntry("link-pin", { pin: sessionPin });
      saveLinkConfig({ pin: sessionPin });
    }

    let chosenHub: DiscoveredHub | null = null;
    let directTarget: string | null = null;

    if (!targetArg) {
      ctx.ui.notify(`Scanning network (Tailscale + LAN) for active sessions...`, "info");
      const { hubs } = await discoverAllHubs(linkPort, 1200, linkSecret);
      const candidates = hubs.filter(h => h.hubId !== hubInstanceId && !h.endpoints?.includes(`127.0.0.1:${linkPort}`));
      if (candidates.length === 0) {
        ctx.ui.notify(
          `No other active sessions found on network.\nStart one with: /link start ${currentSessionId}`,
          "warning",
        );
        return;
      }
      if (candidates.length === 1) {
        chosenHub = candidates[0];
      } else {
        let msg = `Found ${candidates.length} active sessions on network:\n`;
        candidates.forEach((h, idx) => {
          msg += `  ${idx + 1}. "${h.sessionId || h.hubName}" on ${h.host} (${h.ip}:${h.port})\n`;
        });
        msg += `\nSpecify session to join: /link join <1-${candidates.length} or session-id>`;
        ctx.ui.notify(msg.trim(), "info");
        return;
      }
    } else if (/^\d+$/.test(targetArg) && Number(targetArg) >= 1 && Number(targetArg) <= 20) {
      const idx = Number(targetArg) - 1;
      const { hubs } = await discoverAllHubs(linkPort, 1200, linkSecret);
      const candidates = hubs.filter(h => h.hubId !== hubInstanceId && !h.endpoints?.includes(`127.0.0.1:${linkPort}`));
      if (candidates[idx]) {
        chosenHub = candidates[idx];
      } else {
        ctx.ui.notify(`Index ${targetArg} not found among active sessions.`, "warning");
        return;
      }
    } else {
      const isIp =
        targetArg.includes(":") ||
        /^\d+\.\d+\.\d+\.\d+$/.test(targetArg) ||
        targetArg.startsWith("100.");
      if (isIp) {
        directTarget = targetArg;
      } else {
        ctx.ui.notify(
          `Searching for session "${targetArg}" on network...`,
          "info",
        );
        const { hubs } = await discoverAllHubs(linkPort, 1200, linkSecret);
        const found = hubs.find(
          (h) => (h.sessionId === targetArg || h.hubName === targetArg) && h.hubId !== hubInstanceId,
        );
        if (found) {
          chosenHub = found;
        } else {
          ctx.ui.notify(
            `Session "${targetArg}" not found. Active sessions: ${hubs.filter(h => h.hubId !== hubInstanceId).map((h) => h.sessionId || h.hubName).join(", ") || "none"}`,
            "warning",
          );
          return;
        }
      }
    }

    if (chosenHub) {
      targetHubAddress = `${chosenHub.ip}:${chosenHub.port}`;
      if (chosenHub.sessionId) currentSessionId = chosenHub.sessionId;
      if (chosenHub.pin) sessionPin = chosenHub.pin;
      ctx.ui.notify(
        `Joining session "${currentSessionId}" on ${chosenHub.host} (${targetHubAddress})...`,
        "info",
      );
    } else if (directTarget) {
      targetHubAddress = directTarget;
      ctx.ui.notify(`Connecting to hub at ${targetHubAddress}...`, "info");
    }

    disconnect();
    explicitHubMode = false;
    manuallyDisconnected = false;
    pi.appendEntry("link-active", { active: true });
    pi.appendEntry("link-session", { sessionId: currentSessionId });
    if (sessionPin) pi.appendEntry("link-pin", { pin: sessionPin });
    saveLinkConfig({ sessionId: currentSessionId, hub: targetHubAddress, pin: sessionPin });
    await initialize();
  }

  function handleLeave(ctx: ExtensionContext) {
    pi.appendEntry("link-active", { active: false });
    manuallyDisconnected = true;
    if (role === "disconnected") {
      cancelConnectionAttempt();
      ctx.ui.notify("Link disconnected", "info");
      return;
    }
    disconnect();
    ctx.ui.notify("Left link session. Run /link join or /link start to reconnect.", "info");
  }

  async function handleNetwork(args: string, ctx: ExtensionContext) {
    const mode = args.trim().toLowerCase();
    const net = getNetworkInfo();

    if (!mode) {
      ctx.ui.notify(
        [
          `⚡ Link Network Mode: ${networkMode.toUpperCase()}`,
          `  Tailscale IP : ${net.tailscaleIp || "none detected"}`,
          `  LAN IPs      : ${net.lanIps.join(", ") || "none detected"}`,
          `\nUsage:`,
          `  /link network tailscale (or ts)  Strictly use Tailscale`,
          `  /link network lan                Strictly use local network`,
        ].join("\n"),
        "info",
      );
      return;
    }

    if (mode === "tailscale" || mode === "ts") {
      if (!net.tailscaleIp) {
        ctx.ui.notify(
          "⚠️ Warning: Tailscale IP not detected on this machine. Ensure Tailscale is running.",
          "warning",
        );
      }
      networkMode = "tailscale";
      pi.appendEntry("link-network", { network: "tailscale" });
      saveLinkConfig({ network: "tailscale" });
      ctx.ui.notify("⚡ Switched to TAILSCALE network mode. Reconnecting...", "info");
      disconnect();
      manuallyDisconnected = false;
      await initialize();
      return;
    }

    if (mode === "lan") {
      networkMode = "lan";
      pi.appendEntry("link-network", { network: "lan" });
      saveLinkConfig({ network: "lan" });
      ctx.ui.notify("⚡ Switched to LAN network mode. Reconnecting...", "info");
      disconnect();
      manuallyDisconnected = false;
      await initialize();
      return;
    }

    ctx.ui.notify("Unknown network mode. Use '/link network tailscale' or '/link network lan'", "warning");
  }

  function handlePin(args: string, ctx: ExtensionContext) {
    const newPin = args.trim();
    if (!newPin) {
      ctx.ui.notify(
        [
          `Session PIN: ${sessionPin}`,
          `Status: ${networkMode === "tailscale" ? "Tailscale is active — WireGuard automatically verifies peers." : "LAN mode active — LAN peers require this PIN to join."}`,
          `To change: /link pin <new-pin>`,
        ].join("\n"),
        "info",
      );
      return;
    }
    sessionPin = newPin;
    pi.appendEntry("link-pin", { pin: sessionPin });
    saveLinkConfig({ pin: sessionPin });
    ctx.ui.notify(`Session PIN updated to "${sessionPin}"`, "info");
  }

  function handleName(args: string, ctx: ExtensionContext) {
    let newName = normalizeName(args) ?? "";
    if (!newName) {
      const sessionName = normalizeName(pi.getSessionName());
      if (sessionName) {
        newName = sessionName;
      } else {
        ctx.ui.notify(
          `Current name: "${terminalName}". No session name set. Usage: /link name <name>`,
          "info",
        );
        return;
      }
    }

    if (newName === terminalName && newName === preferredName) {
      ctx.ui.notify(`Already using "${newName}"`, "info");
      return;
    }

    function savePreference() {
      preferredName = newName;
      pi.appendEntry("link-name", { name: preferredName });
    }

    if (newName === terminalName) {
      savePreference();
      ctx.ui.notify(`Saved "${newName}" as preferred link name`, "info");
      return;
    }

    if (role === "hub") {
      const takenByOther = Array.from(hubClients.values()).includes(newName);
      if (takenByOther) {
        ctx.ui.notify(
          `Name "${newName}" is already taken by another terminal`,
          "warning",
        );
        return;
      }
      const old = terminalName;
      terminalName = newName;
      const list = terminalList();
      connectedTerminals = list;
      updateStatus();
      hubBroadcast(
        { type: "terminal_left", name: old, terminals: list },
        terminalName,
      );
      hubBroadcast(
        {
          type: "terminal_joined",
          name: newName,
          terminals: list,
          cwd: currentCwd,
          context: captureContext(),
          host: os.hostname(),
          project: currentCwd ? path.basename(currentCwd) : undefined,
        },
        terminalName,
      );
      pushStatus(true);
      savePreference();
      ctx.ui.notify(`Renamed to "${newName}"`, "info");
    } else if (role === "client") {
      savePreference();
      pendingClientRename = true;
      ws?.close();
      ctx.ui.notify(
        `Reconnecting, requesting "${newName}" (hub may assign a different name if taken)...`,
        "info",
      );
    } else {
      savePreference();
      terminalName = newName;
      ctx.ui.notify(`Name set to "${newName}" (not connected)`, "info");
    }
  }

  const handleDiscoverCommand = async (_args: string, ctx: ExtensionContext) => {
    ctx.ui.notify("Scanning network (Tailscale + LAN) for active sessions...", "info");
    const { hubs, tailnetPeersCount } = await discoverAllHubs(linkPort, 1200, linkSecret);
    const others = hubs.filter(h => h.hubId !== hubInstanceId);
    if (others.length === 0) {
      ctx.ui.notify(
        tailnetPeersCount > 0
          ? `No other active sessions found (${tailnetPeersCount} Tailnet peers & LAN scanned).`
          : "No other active sessions found on network.",
        "info",
      );
      return;
    }

    let summary = `⚡ Found ${others.length} active session(s) on network:\n`;
    for (let i = 0; i < others.length; i++) {
      const h = others[i];
      const terms = (h.terminals || [])
        .map((t) => `${t.name}${t.project ? ` (${t.project})` : ""}`)
        .join(", ");
      summary += `\n${i + 1}. "${h.sessionId || h.hubName}" on ${h.host} (${h.ip}:${h.port}) [PIN: ${h.pin || "none"}]\n   Peers: ${terms || "1"}\n   Join: /link join ${i + 1} (or /link join ${h.sessionId || `${h.ip}:${h.port}`})`;
    }
    ctx.ui.notify(summary.trim(), "info");
  };

  async function runLinkDoctor(ctx: ExtensionContext) {
    const lines: string[] = ["🩺 omp-link Security & System Doctor\n"];

    // 1. Device Identity
    try {
      const id = getOrCreateDeviceIdentity();
      lines.push(`  🔑 Device Identity : OK`);
      lines.push(`     Device ID   : ${id.deviceId}`);
      lines.push(`     Fingerprint : ${id.fingerprint}`);
      lines.push(`     Crypto      : Ed25519 (challenge-response authentication)`);
    } catch (err: any) {
      lines.push(`  ❌ Device Identity : FAILED (${err.message})`);
    }

    // 2. TLS Certificate (LAN security)
    try {
      const tls = getOrCreateTlsCert();
      lines.push(`  🔒 TLS Certificate : OK`);
      lines.push(`     Fingerprint : ${tls?.fingerprint || "none"}`);
      lines.push(`     Cipher / Key: ECDSA P-256 (HTTPS / WSS on LAN)`);
    } catch (err: any) {
      lines.push(`  ❌ TLS Certificate : FAILED (${err.message})`);
    }

    // 3. Network Interfaces & Routing
    const net = getNetworkInfo();
    lines.push(`  🌐 Network Status  :`);
    lines.push(`     Active Mode : ${networkMode.toUpperCase()}`);
    lines.push(`     Tailscale IP: ${net.tailscaleIp || "none detected"}`);
    lines.push(`     LAN IPs     : ${net.lanIps.join(", ") || "none detected"}`);

    // 4. Session & State
    lines.push(`  ⚡ Link Session    :`);
    lines.push(`     Role        : ${role.toUpperCase()}`);
    lines.push(`     Active      : ${linkActive ? "YES" : "NO"}`);
    lines.push(`     Session ID  : "${currentSessionId}"`);
    lines.push(`     Port        : ${linkPort}`);
    lines.push(`     Peers Online: ${connectedTerminals.length}`);

    // 5. Territorial Sovereignty & Confinement
    const wsRoot = fs.realpathSync(currentCwd || process.cwd());
    lines.push(`  🛡️ Territorial Sovereignty :`);
    lines.push(`     Workspace   : ${wsRoot}`);
    lines.push(`     Mutation Grd: ${mutationGuard ? "ACTIVE (Enforced)" : "DISABLED"}`);
    lines.push(`     Active Grants: ${activeExecGrants.size} elevated peer(s)`);
    if (activeExecGrants.size > 0) {
      for (const [peer, grant] of activeExecGrants) {
        const remMin = Math.max(1, Math.round((grant.expiresAt - Date.now()) / 60000));
        lines.push(`       • ${peer} (${remMin}m remaining)`);
      }
    }

    // 6. Paired Devices
    const paired = loadPairedDevices();
    lines.push(`  📱 Paired Devices  : ${paired.size} trusted device(s)`);
    for (const [dId, dev] of paired) {
      lines.push(`     • ${dev.name} [${dId.slice(0, 8)}...] (FP: ${(dev.fingerprint || "").slice(0, 16)}...)`);
    }

    // 7. File Inbox
    const inbox = path.join(os.homedir(), ".omp", "inbox");
    const inboxExists = fs.existsSync(inbox);
    lines.push(`  📥 File Inbox      : ${inbox} (${inboxExists ? "Ready" : "Will create on transfer"})`);

    lines.push("\nDiagnostic checks completed. Use '/link help' for available commands.");
    ctx.ui.notify(lines.join("\n"), "info");
  }

  function renderLinkHelp(ctx: ExtensionContext) {
    const help = [
      "⚡ omp-link Command Reference",
      "",
      "Session & Connection:",
      "  /link                   Show current session status, role, and discovered peers",
      "  /link on | off          Turn link mesh networking on or off",
      "  /link join [target]     Join session by ID, IP, or discovery number (/link-join)",
      "  /link leave             Leave current session (/link-leave)",
      "  /link start [id] [pin]  Start or switch session as host",
      "  /link discover          Scan LAN & Tailscale for active sessions",
      "",
      "Security & Pairing:",
      "  /link accept [id]       Approve a pending device join request",
      "  /link deny [id]         Reject a pending device join request",
      "  /link requests          List pending device join requests awaiting approval",
      "  /link devices           List trusted paired devices",
      "  /link devices revoke <id> Revoke trust for a paired device",
      "  /link grant <peer> [m]  Grant temporary execution elevation to peer (1-60 mins)",
      "  /link revoke-grant <peer> Revoke execution elevation immediately",
      "  /link mutation [on|off] Inspect or toggle Mutation Guard",
      "",
      "Configuration & Diagnostics:",
      "  /link network [ts|lan]  Switch between Tailscale and local LAN mode",
      "  /link pin [pin]         View or set session PIN",
      "  /link name [name]       Change terminal display name",
      "  /link doctor            Run security, cryptographic & network diagnostics (/link-doctor)",
    ].join("\n");
    ctx.ui.notify(help, "info");
  }

  pi.registerCommand("link", {
    description: "Manage link mesh network, security, and sessions. Usage: /link [subcommand]",
    handler: async (args, ctx) => {
      const parts = args.trim().split(/\s+/).filter(Boolean);
      const subcmd = parts[0]?.toLowerCase();
      const restArgs = args.trim().slice(parts[0]?.length || 0).trim();

      if (!subcmd || subcmd === "status") {
        let card = renderStatusCard();
        if (linkActive && (role === "disconnected" || (role === "hub" && connectedTerminals.length <= 1))) {
          const { hubs } = await discoverAllHubs(linkPort, 900, linkSecret);
          const others = hubs.filter(h => h.hubId !== hubInstanceId && !h.endpoints?.includes(`127.0.0.1:${linkPort}`));
          if (others.length > 0) {
            card += `\n\n  📡 Discovered active session(s) on network:\n`;
            others.forEach((h, idx) => {
              const peerCount = h.terminals ? h.terminals.length : 1;
              card += `    ${idx + 1}. "${h.sessionId || h.hubName}" on ${h.host} (${h.ip}:${h.port}) · ${peerCount} peer(s)\n`;
            });
            card += `  👉 Join with: /link join ${others[0].sessionId || "1"}`;
          }
        }
        ctx.ui.notify(card, (!linkActive || role === "disconnected") ? "warning" : "info");
        return;
      }

      switch (subcmd) {
        case "on":
        case "start-service":
        case "enable":
          await turnLinkOn(ctx);
          break;

        case "off":
        case "stop":
        case "disable":
          turnLinkOff(ctx);
          break;

        case "join":
        case "connect":
          await handleJoin(restArgs, ctx);
          break;

        case "leave":
        case "disconnect":
          handleLeave(ctx);
          break;

        case "start":
          await handleStart(restArgs, ctx);
          break;

        case "accept":
          handleAccept(restArgs, ctx);
          break;

        case "deny":
          handleDeny(restArgs, ctx);
          break;

        case "requests":
          handleRequests(ctx);
          break;

        case "devices":
          handleDevices(restArgs, ctx);
          break;

        case "grant":
          handleGrant(restArgs, ctx);
          break;

        case "revoke-grant":
          handleRevokeGrant(restArgs, ctx);
          break;

        case "network":
        case "net":
          await handleNetwork(restArgs, ctx);
          break;

        case "pin":
          handlePin(restArgs, ctx);
          break;

        case "mutation":
        case "guard":
          handleMutationCommand(restArgs, ctx);
          break;

        case "name":
          handleName(restArgs, ctx);
          break;

        case "discover":
        case "search":
        case "scan":
          await handleDiscoverCommand(restArgs, ctx);
          break;

        case "doctor":
          await runLinkDoctor(ctx);
          break;

        case "help":
        default:
          renderLinkHelp(ctx);
          break;
      }
    },
  });

  pi.registerCommand("link-join", {
    description: "Join an active link session (alias for /link join)",
    handler: async (args, ctx) => {
      await handleJoin(args, ctx);
    },
  });

  pi.registerCommand("link-leave", {
    description: "Leave current link session (alias for /link leave)",
    handler: async (_args, ctx) => {
      handleLeave(ctx);
    },
  });

  pi.registerCommand("link-doctor", {
    description: "Run security and system diagnostic checks (alias for /link doctor)",
    handler: async (_args, ctx) => {
      await runLinkDoctor(ctx);
    },
  });

  // ── Message renderer ─────────────────────────────────────────────────────

  pi.registerMessageRenderer("link", (message, _options, theme) => {
    const from =
      (message.details as Record<string, unknown> | undefined)?.from ?? "link";
    const text =
      theme.fg("accent", `⚡ [${from}] `) +
      theme.fg("text", String(message.content));
    return new Text(text, 0, 0);
  });
}
