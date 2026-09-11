#!/usr/bin/env node

// omp-link CLI launcher.
//
// With no recognized command it launches OMP/Pi with the omp-link extension
// loaded and forwards every argument untouched. With a recognized command it
// runs that command locally. The command set, help text, arity rules and exit
// codes all come from src/command-registry.mjs — this file never invents a
// verb or a help line of its own.

import { chmodSync, existsSync, lstatSync, readFileSync, readdirSync, readlinkSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { execFileSync, execSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import * as https from "node:https";
import * as dgram from "node:dgram";

import {
  COMMANDS,
  EXIT,
  GLOBAL_FLAGS,
  REMOVED_COMMANDS,
  findCommand,
  getVersion,
  parseInvocation,
  renderHelp,
} from "../src/command-registry.mjs";

const REPO_DIR = dirname(dirname(fileURLToPath(import.meta.url)));
const VERSION = getVersion();

const HUB_PORT = 9900;
const UDP_DISCOVERY_PORT = 9901;
const LOOPBACK_PROBE_TIMEOUT_MS = 800;
const REMOTE_PROBE_TIMEOUT_MS = 1200;
const UDP_SCAN_WINDOW_MS = 900;
const TAILSCALE_STATUS_TIMEOUT_MS = 3000;
/** Mirrors ABSOLUTE_TIMEOUT_MS in src/transfer-receiver.ts: a staging dir idle past it cannot be live. */
const ORPHAN_STAGING_IDLE_MS = 120_000;
const MAX_STATUS_BODY_BYTES = 64 * 1024;

// ── Environment resolution ───────────────────────────────────────────────────

function resolveAgentBin() {
  if (process.env.OMP_BIN && existsSync(process.env.OMP_BIN)) return process.env.OMP_BIN;
  if (process.env.PI_BIN && existsSync(process.env.PI_BIN)) return process.env.PI_BIN;

  const candidates = [
    "omp",
    "pi",
    join(homedir(), ".local", "bin", "omp"),
    join(homedir(), ".local", "bin", "pi"),
    "/usr/local/bin/omp",
    "/opt/homebrew/bin/omp",
    "/usr/local/bin/pi",
    "/opt/homebrew/bin/pi",
    join(homedir(), ".bun", "bin", "omp"),
    join(homedir(), ".bun", "bin", "pi"),
  ];

  for (const c of candidates) {
    try {
      execSync(`command -v "${c}"`, { stdio: "ignore" });
      return c;
    } catch {}
  }
  return null;
}

/** Same rule as getOmpDir() in src/identity.ts, reimplemented because this file must run under bare node. */
function resolveOmpDir() {
  if (process.env.OMP_DIR) return process.env.OMP_DIR;
  const ompDir = join(homedir(), ".omp");
  if (existsSync(ompDir)) return ompDir;
  const piDir = join(homedir(), ".pi");
  if (existsSync(piDir)) return piDir;
  return ompDir;
}

function resolveTailscaleBin() {
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

function getTailnetPeers() {
  const bin = resolveTailscaleBin();
  if (!bin) return [];
  try {
    const stdout = execFileSync(bin, ["status", "--json"], {
      encoding: "utf-8",
      timeout: TAILSCALE_STATUS_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const status = JSON.parse(stdout);
    const peers = [];
    const selfIp = status.Self?.TailscaleIPs?.find((ip) => ip.startsWith("100."));
    if (selfIp) peers.push({ host: status.Self.HostName || "localhost", ip: selfIp, isSelf: true });
    for (const p of Object.values(status.Peer || {})) {
      if (!p?.Online) continue;
      const ipv4 = p.TailscaleIPs?.find((ip) => ip.startsWith("100."));
      if (ipv4) peers.push({ host: p.HostName, ip: ipv4, isSelf: false });
    }
    return peers;
  } catch {
    return [];
  }
}

// ── Hub probing (HTTPS; the v5 hub speaks TLS only) ──────────────────────────

/**
 * `/status` is unauthenticated, and everything in it gets printed to a terminal. Keep only
 * bounded printable ASCII so a hostile listener cannot smuggle newlines or ANSI escapes and
 * forge output that looks like it came from this tool. Mirrors src/discovery.ts.
 */
function sanitizeStatusPayload(data) {
  const printable = (value, maxLength) => {
    if (typeof value !== "string") return undefined;
    const trimmed = value.trim();
    if (!trimmed || trimmed.length > maxLength) return undefined;
    return /^[\x20-\x7E]+$/.test(trimmed) ? trimmed : undefined;
  };
  const fingerprint = (value) => {
    if (typeof value !== "string") return undefined;
    const upper = value.trim().toUpperCase();
    return /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(upper) ? upper : undefined;
  };
  return {
    service: "omp-link",
    protocolVersion: Number(data.protocolVersion) || null,
    roomId: printable(data.roomId, 64),
    principalId: printable(data.principalId, 128),
    spkiFingerprint: fingerprint(data.spkiFingerprint || data.certificateFingerprint),
    transport: printable(data.transport, 16),
  };
}

/**
 * GET /status over HTTPS. The hub presents a self-signed device certificate,
 * so the chain is deliberately not verified here and the result is reported as
 * UNVERIFIED. Discovery is not trust: pinning happens during pairing inside the
 * agent, never in this CLI. NODE_TLS_REJECT_UNAUTHORIZED is never touched.
 */
function probeHubStatus(host, port = HUB_PORT, timeoutMs = REMOTE_PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const req = https.request(
      {
        host,
        port,
        path: "/status",
        method: "GET",
        agent: false,
        rejectUnauthorized: false,
        servername: undefined,
        timeout: timeoutMs,
      },
      (res) => {
        let tlsFingerprint = null;
        let tlsVersion = null;
        try {
          tlsFingerprint = res.socket?.getPeerCertificate?.()?.fingerprint256 || null;
          tlsVersion = res.socket?.getProtocol?.() || null;
        } catch {}

        let body = "";
        res.setEncoding("utf-8");
        res.on("data", (chunk) => {
          if (body.length < MAX_STATUS_BODY_BYTES) body += chunk;
        });
        res.on("end", () => {
          if (res.statusCode !== 200) {
            done({ reachable: false, error: `HTTP ${res.statusCode}` });
            return;
          }
          let data;
          try {
            data = JSON.parse(body);
          } catch {
            done({ reachable: false, error: "malformed /status payload" });
            return;
          }
          if (data?.service !== "omp-link") {
            done({ reachable: false, error: "listener is not an omp-link hub" });
            return;
          }
          done({
            reachable: true,
            host,
            port,
            status: sanitizeStatusPayload(data),
            tlsFingerprint,
            tlsVersion,
            error: null,
          });
        });
        res.on("error", (err) => done({ reachable: false, error: err.message }));
      },
    );

    req.on("timeout", () => {
      req.destroy();
      done({ reachable: false, error: "timeout" });
    });
    req.on("error", (err) => done({ reachable: false, error: err.code || err.message }));
    req.end();
  });
}

/** LAN UDP sweep, same wire strings as src/discovery.ts. */
function udpScan(timeoutMs = UDP_SCAN_WINDOW_MS) {
  return new Promise((resolve) => {
    const found = new Map();
    let socket;
    try {
      socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
    } catch {
      resolve([]);
      return;
    }

    const finish = () => {
      try {
        socket.close();
      } catch {}
      resolve([...found.values()]);
    };

    socket.on("error", finish);
    socket.on("message", (msg, rinfo) => {
      const text = msg.toString().trim();
      if (!text.startsWith("OMP_LINK_HUB_V5:")) return;
      const port = Number(text.slice("OMP_LINK_HUB_V5:".length)) || HUB_PORT;
      found.set(`${rinfo.address}:${port}`, { host: rinfo.address, port });
    });

    socket.bind(0, () => {
      try {
        socket.setBroadcast(true);
      } catch {}
      const payload = Buffer.from("OMP_LINK_DISCOVER");
      for (const target of ["255.255.255.255"]) {
        try {
          socket.send(payload, UDP_DISCOVERY_PORT, target);
        } catch {}
      }
      setTimeout(finish, timeoutMs);
    });
  });
}

// ── Local ownership evidence ─────────────────────────────────────────────────

/**
 * Can this process bind the port right now? A cheap, dependency-free answer to "is anything
 * listening", used when `lsof` is unavailable. Binds loopback only and closes immediately.
 */
function isPortBindable(port) {
  try {
    execFileSync(process.execPath, [
      "-e",
      `const n=require("node:net");const s=n.createServer();`
      + `s.once("error",()=>process.exit(1));`
      + `s.listen(${port},"127.0.0.1",()=>s.close(()=>process.exit(0)));`,
    ], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/**
 * Who is listening on a TCP port, and can we prove it belongs to this user?
 * Returns a result object; `provable: false` always means "do not touch it".
 */
function inspectPortOwner(port) {
  let out;
  try {
    out = execFileSync("lsof", ["-nP", `-iTCP:${port}`, "-sTCP:LISTEN", "-t"], {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch (err) {
    if (err?.code === "ENOENT") {
      // No lsof (common on minimal Linux installs). We cannot attribute the socket to a user,
      // so nothing becomes stoppable — but "is anything there at all" is answerable by trying
      // to bind it ourselves, which is more useful than reporting unknown.
      return {
        listening: isPortBindable(port) ? false : null,
        provable: false,
        pids: [],
        reason: "lsof is not installed, so no process could be attributed to this port",
      };
    }
    return { listening: false, provable: true, pids: [], reason: null };
  }

  const pids = out.split(/\s+/).filter(Boolean).map(Number).filter((p) => Number.isInteger(p) && p > 0);
  if (pids.length === 0) return { listening: false, provable: true, pids: [], reason: null };

  const me = userInfo().username;
  const owners = [];
  for (const pid of pids) {
    let user = null;
    let command = null;
    try {
      const psOut = execFileSync("ps", ["-o", "user=,comm=", "-p", String(pid)], {
        encoding: "utf-8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim();
      const match = psOut.match(/^(\S+)\s+(.*)$/);
      if (match) {
        user = match[1];
        command = match[2];
      }
    } catch {}
    owners.push({ pid, user, command, mine: user !== null && user === me });
  }

  const unknown = owners.filter((o) => o.user === null);
  if (unknown.length > 0) {
    return {
      listening: true,
      provable: false,
      pids,
      owners,
      reason: `cannot read the owner of PID ${unknown.map((o) => o.pid).join(", ")}`,
    };
  }
  const foreign = owners.filter((o) => !o.mine);
  if (foreign.length > 0) {
    return {
      listening: true,
      provable: false,
      pids,
      owners,
      reason: `PID ${foreign.map((o) => `${o.pid} (user ${o.user})`).join(", ")} is not owned by ${me}`,
    };
  }
  return { listening: true, provable: true, pids, owners, reason: null };
}

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code === "EPERM";
  }
}

// ── Output helpers ───────────────────────────────────────────────────────────

let jsonMode = false;

function emit(text) {
  if (!jsonMode) console.log(text);
}

function emitJson(payload) {
  console.log(JSON.stringify(payload, null, 2));
}

async function confirm(question, flags) {
  if (flags.yes === true) return true;
  if (flags.noInput === true) return false;
  if (!process.stdin.isTTY) return false;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question(`${question} [y/N] `);
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

// ── Commands ─────────────────────────────────────────────────────────────────

async function runStatus(flags) {
  const ompDir = resolveOmpDir();
  const configPath = join(ompDir, "link.json");
  let config = null;
  try {
    if (existsSync(configPath)) config = JSON.parse(readFileSync(configPath, "utf-8"));
  } catch {}

  const local = await probeHubStatus("127.0.0.1", HUB_PORT, LOOPBACK_PROBE_TIMEOUT_MS);

  if (flags.json === true) {
    emitJson({
      version: VERSION,
      ompDir,
      config,
      localHub: local.reachable
        ? { ...local.status, tlsFingerprint: local.tlsFingerprint, tlsVersion: local.tlsVersion, verified: false }
        : { reachable: false, error: local.error },
    });
    return EXIT.OK;
  }

  const rooms = Array.isArray(config?.rooms) ? config.rooms : [];
  const current = rooms.find((r) => r && r.roomId === config?.currentRoomId) || null;

  emit(`omp-link v${VERSION}`);
  emit(`  State dir : ${ompDir}${existsSync(ompDir) ? "" : "  (missing)"}`);
  emit(`  Room      : ${current ? `"${current.label}" at ${current.endpoint}` : "(none remembered)"}`);
  emit(`  Known     : ${rooms.length} remembered room(s)`);
  if (local.reachable) {
    emit(`  Local hub : listening on 127.0.0.1:${HUB_PORT}`);
    emit(`    room            ${local.status.roomId || "(unnamed)"}`);
    emit(`    protocol        v${local.status.protocolVersion}`);
    emit(`    TLS             ${local.tlsVersion || "unknown"}`);
    emit(`    SPKI            ${local.status.spkiFingerprint || "(absent)"} (unverified)`);
  } else {
    emit(`  Local hub : none (${local.error})`);
  }
  if (flags.verbose === true) {
    emit("");
    emit("  [verbose]");
    emit(`    config file     ${configPath}${existsSync(configPath) ? "" : " (absent)"}`);
    emit(`    terminal name   ${config?.terminalName || "(hostname)"}`);
    emit(`    network mode    ${config?.network || "lan"}`);
    for (const room of rooms) {
      if (!room || typeof room !== "object") continue;
      emit(`    room ${String(room.roomId).slice(0, 8)}…  "${room.label}" at ${room.endpoint}`);
      emit(`      host pin      ${room.hubFingerprint || "(none)"}`);
    }
  }
  emit("");
  emit("This is the terminal view. Live roster, peers and pairing live inside the agent: /link status");
  return EXIT.OK;
}

async function runScan(flags) {
  if (!jsonMode) emit("Probing loopback, LAN broadcast and Tailnet for omp-link hubs...\n");

  const candidates = new Map();
  candidates.set(`127.0.0.1:${HUB_PORT}`, { host: "127.0.0.1", port: HUB_PORT, source: "loopback" });

  for (const peer of getTailnetPeers()) {
    const key = `${peer.ip}:${HUB_PORT}`;
    if (!candidates.has(key)) {
      candidates.set(key, { host: peer.ip, port: HUB_PORT, source: peer.isSelf ? "tailscale (self)" : "tailscale", name: peer.host });
    }
  }
  for (const hub of await udpScan()) {
    const key = `${hub.host}:${hub.port}`;
    if (!candidates.has(key)) candidates.set(key, { host: hub.host, port: hub.port, source: "lan-udp" });
  }

  const probes = await Promise.all(
    [...candidates.values()].map(async (candidate) => {
      const timeout = candidate.source === "loopback" ? LOOPBACK_PROBE_TIMEOUT_MS : REMOTE_PROBE_TIMEOUT_MS;
      const result = await probeHubStatus(candidate.host, candidate.port, timeout);
      return { candidate, result };
    }),
  );
  const hubs = probes.filter(({ result }) => result.reachable);

  if (flags.json === true) {
    emitJson({
      version: VERSION,
      probed: probes.length,
      verified: false,
      hubs: hubs.map(({ candidate, result }) => ({
        host: candidate.host,
        port: candidate.port,
        source: candidate.source,
        peerName: candidate.name ?? null,
        roomId: result.status.roomId ?? null,
        protocolVersion: result.status.protocolVersion ?? null,
        spkiFingerprint: result.status.spkiFingerprint ?? null,
        tlsFingerprint: result.tlsFingerprint,
        tlsVersion: result.tlsVersion,
      })),
    });
    return EXIT.OK;
  }

  if (hubs.length === 0) {
    emit(`No omp-link hub answered /status (${probes.length} endpoint(s) probed).`);
    emit("Start one from inside the agent: /link create <name>");
    return EXIT.OK;
  }

  emit(`${hubs.length} reachable hub(s) — UNVERIFIED, discovery is not trust:\n`);
  for (const { candidate, result } of hubs) {
    emit(`  ${candidate.host}:${candidate.port}  [${candidate.source}${candidate.name ? `: ${candidate.name}` : ""}]`);
    emit(`    room              ${result.status.roomId || "(unnamed)"}`);
    emit(`    protocol          v${result.status.protocolVersion}`);
    emit(`    TLS               ${result.tlsVersion || "unknown"} (certificate chain NOT validated)`);
    emit(`    SPKI (unverified) ${result.status.spkiFingerprint || "(absent)"}`);
    emit(`    join inside agent /link join ${candidate.host}:${candidate.port}`);
    emit("");
  }
  emit("These fingerprints are claims by an unauthenticated endpoint. Compare them out of band");
  emit("during pairing (/link accept <id> <code>); nothing here establishes trust.");
  return EXIT.OK;
}

function runShared(flags) {
  const ompDir = resolveOmpDir();
  const auditPath = join(ompDir, "audit.log");
  const limit = Math.max(1, Math.min(500, Number.parseInt(String(flags.limit ?? "20"), 10) || 20));

  const SHARE_TYPES = new Set([
    "pairing_approved",
    "pairing_denied",
    "pairing_rejected_invalid_sas",
    "pairing_rejected_missing_sas",
    "grant_created",
    "grant_used",
    "grant_revoked",
    "grant_expired",
    "exec_executed",
    "exec_blocked",
    "file_transfer_received",
    "permissions_updated",
    "device_revoked",
    "authorization_denied",
  ]);

  if (!existsSync(auditPath)) {
    if (flags.json === true) {
      emitJson({ auditLog: auditPath, exists: false, entries: [] });
      return EXIT.OK;
    }
    emit(`No audit log at ${auditPath}. Nothing has been shared from this machine yet.`);
    return EXIT.OK;
  }

  const records = [];
  for (const line of readFileSync(auditPath, "utf-8").split("\n")) {
    if (!line) continue;
    try {
      const record = JSON.parse(line);
      if (SHARE_TYPES.has(record.type)) records.push(record);
    } catch {}
  }
  const entries = records.slice(-limit);

  if (flags.json === true) {
    emitJson({ auditLog: auditPath, exists: true, total: records.length, shown: entries.length, entries });
    return EXIT.OK;
  }

  emit(`Sharing receipt — ${entries.length} of ${records.length} security event(s) from ${auditPath}\n`);
  if (entries.length === 0) {
    emit("  (no sharing or authorization decisions recorded)");
    return EXIT.OK;
  }
  for (const record of entries) {
    const when = new Date(record.timestamp || 0).toISOString().replace("T", " ").slice(0, 19);
    // permissions_updated / device_revoked key the device as `target`, not `principalId`.
    const who = record.principalId || record.peerPrincipalId || record.from || record.device || record.target || "(unknown peer)";
    const what = [
      record.workspaceId && `workspace=${record.workspaceId}`,
      record.action && `action=${record.action}`,
      record.command && `command=${String(record.command).slice(0, 60)}`,
      record.filename && `file=${record.filename}`,
      record.reason && `reason=${record.reason}`,
    ]
      .filter(Boolean)
      .join(" ");
    emit(`  ${when}  ${record.type}`);
    emit(`    peer ${who}${what ? `\n    ${what}` : ""}`);
  }
  emit("");
  emit("Revoke a device and all of its grants from inside the agent: /link revoke <device>");
  return EXIT.OK;
}

async function runDoctor(flags) {
  const ompDir = resolveOmpDir();
  const identityDir = join(ompDir, "identity");
  const nodeMajor = Number.parseInt(process.versions.node.split(".")[0], 10);
  const agentBin = resolveAgentBin();
  const tailscaleBin = resolveTailscaleBin();
  const local = await probeHubStatus("127.0.0.1", HUB_PORT, LOOPBACK_PROBE_TIMEOUT_MS);
  const tcpOwner = inspectPortOwner(HUB_PORT);

  const identityFiles = ["device-cert.pem", "device-key.pem"].map((name) => {
    const file = join(identityDir, name);
    let mode = null;
    try {
      mode = existsSync(file) ? (statSync(file).mode & 0o777).toString(8) : null;
    } catch {}
    return { name, path: file, exists: mode !== null, mode };
  });

  const symlinks = [
    join(homedir(), ".local", "bin", "omp-link"),
    join(homedir(), ".local", "bin", "pi-link"),
    join(homedir(), ".omp", "agent", "extensions", "omp-link"),
    join(homedir(), ".pi", "agent", "extensions", "omp-link"),
  ].map((path) => {
    let state = "absent";
    let target = null;
    try {
      if (lstatSync(path).isSymbolicLink()) {
        target = readlinkSafe(path);
        state = target && existsSync(path) ? "ok" : "dangling";
      } else {
        state = "not-a-symlink";
      }
    } catch {}
    return { path, state, target };
  });

  const report = {
    version: VERSION,
    repoDir: REPO_DIR,
    node: process.versions.node,
    nodeSupported: nodeMajor >= 18,
    platform: `${process.platform} ${process.arch}`,
    ompDir,
    ompDirExists: existsSync(ompDir),
    agentBin,
    tailscaleBin,
    identityFiles,
    symlinks,
    localHub: local.reachable
      ? {
          reachable: true,
          roomId: local.status.roomId ?? null,
          protocolVersion: local.status.protocolVersion ?? null,
          tlsVersion: local.tlsVersion,
          spkiFingerprint: local.status.spkiFingerprint ?? null,
          certificateChainValidated: false,
        }
      : { reachable: false, error: local.error },
    tcpPort: { port: HUB_PORT, ...tcpOwner },
  };

  if (flags.json === true) {
    emitJson(report);
    return report.nodeSupported ? EXIT.OK : EXIT.UNAVAILABLE;
  }

  emit(`omp-link doctor — measured values only\n`);
  emit(`  version           ${report.version}`);
  emit(`  repo              ${report.repoDir}`);
  emit(`  node              ${report.node}${report.nodeSupported ? "" : "  (UNSUPPORTED: needs >= 18)"}`);
  emit(`  platform          ${report.platform}`);
  emit(`  state dir         ${report.ompDir}${report.ompDirExists ? "" : "  (missing)"}`);
  emit(`  agent binary      ${report.agentBin || "(not found: install omp or set OMP_BIN)"}`);
  emit(`  tailscale         ${report.tailscaleBin || "(not found)"}`);
  emit("");
  emit("  identity:");
  for (const file of identityFiles) {
    emit(`    ${file.name}${" ".repeat(Math.max(1, 18 - file.name.length))}${file.exists ? `mode ${file.mode}` : "absent (created on first use)"}`);
  }
  emit("");
  emit("  install links:");
  for (const link of symlinks) emit(`    ${link.state.padEnd(13)} ${link.path}${link.target ? ` -> ${link.target}` : ""}`);
  emit("");
  emit(`  tcp ${HUB_PORT}:`);
  if (report.tcpPort.listening === false) {
    emit("    nothing listening");
  } else if (report.tcpPort.listening === null) {
    emit(`    unknown (${report.tcpPort.reason})`);
  } else {
    for (const owner of report.tcpPort.owners || []) {
      emit(`    pid ${owner.pid} user ${owner.user || "?"} cmd ${owner.command || "?"}${owner.mine ? " (this user)" : ""}`);
    }
    if (!report.tcpPort.provable) emit(`    ownership NOT proven: ${report.tcpPort.reason}`);
  }
  if (local.reachable) {
    emit(`    /status answered: room ${local.status.roomId || "(unnamed)"}, protocol v${local.status.protocolVersion}, ${local.tlsVersion || "TLS?"}`);
    emit(`    certificate chain NOT validated by this probe (self-signed by design)`);
  } else {
    emit(`    /status did not answer (${local.error})`);
  }
  emit("");
  emit("  Note: the hub terminates TLS and routes every message. There is no client-to-client");
  emit("  end-to-end encryption; see SECURITY.md section 1.");
  return report.nodeSupported ? EXIT.OK : EXIT.UNAVAILABLE;
}

function readlinkSafe(path) {
  try {
    return readlinkSync(path);
  } catch {
    return null;
  }
}

/** Collect the link-owned leftovers this CLI is allowed to touch. */
function collectCleanupTargets() {
  const targets = [];
  const ompDir = resolveOmpDir();

  for (const configPath of [join(ompDir, "link.json"), join(homedir(), ".omp", "link.json"), join(homedir(), ".pi", "link.json")]) {
    if (targets.some((t) => t.path === configPath)) continue;
    try {
      if (!existsSync(configPath)) continue;
      const config = JSON.parse(readFileSync(configPath, "utf-8"));
      if (typeof config.hub === "string" && config.hub) {
        targets.push({
          kind: "cached-hub",
          path: configPath,
          detail: `cached hub "${config.hub}"`,
          needsProbe: config.hub,
        });
      }
    } catch {}
  }

  const inboxRoot = join(ompDir, "inbox");
  if (existsSync(inboxRoot)) {
    const now = Date.now();
    const walk = (dir, depth) => {
      let entries;
      try {
        entries = readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const full = join(dir, entry.name);
        const owner = /^rx-(\d+)-/.exec(entry.name);
        if (!owner) {
          if (depth < 2) walk(full, depth + 1);
          continue;
        }
        const pid = Number(owner[1]);
        if (pidAlive(pid)) continue;
        let idleMs = 0;
        try {
          idleMs = now - statSync(full).mtimeMs;
        } catch {
          continue;
        }
        if (idleMs <= ORPHAN_STAGING_IDLE_MS) continue;
        targets.push({
          kind: "orphan-staging",
          path: full,
          detail: `owner pid ${pid} is gone, idle ${Math.round(idleMs / 1000)}s`,
        });
      }
    };
    walk(inboxRoot, 0);
  }

  const ownedLinks = [
    join(homedir(), ".local", "bin", "omp-link"),
    join(homedir(), ".local", "bin", "pi-link"),
    join(homedir(), ".omp", "agent", "extensions", "omp-link"),
    join(homedir(), ".omp", "extensions", "omp-link"),
    join(homedir(), ".pi", "agent", "extensions", "omp-link"),
    join(homedir(), ".pi", "extensions", "omp-link"),
    join(homedir(), ".omp", "agent", "skills", "omp-link"),
    join(homedir(), ".pi", "agent", "skills", "omp-link"),
    join(homedir(), ".omp", "agent", "extensions", "pi-link"),
    join(homedir(), ".pi", "agent", "extensions", "pi-link"),
    join(homedir(), ".omp", "extensions", "pi-link"),
    join(homedir(), ".pi", "extensions", "pi-link"),
  ];
  for (const path of ownedLinks) {
    try {
      if (!lstatSync(path).isSymbolicLink()) continue;
      if (existsSync(path)) continue;
      targets.push({ kind: "dead-symlink", path, detail: "symlink target no longer exists" });
    } catch {}
  }

  return targets;
}

async function runCleanup(flags) {
  const apply = flags.apply === true;
  const targets = collectCleanupTargets();

  // A cached hub entry is only stale when nothing answers at that endpoint.
  for (const target of targets) {
    if (target.kind !== "cached-hub") continue;
    const endpoint = String(target.needsProbe).replace(/^wss?:\/\//, "");
    const [host, port] = endpoint.split(":");
    const probe = await probeHubStatus(host || "127.0.0.1", Number(port) || HUB_PORT, REMOTE_PROBE_TIMEOUT_MS);
    target.stale = !probe.reachable;
    target.detail = probe.reachable
      ? `cached hub "${target.needsProbe}" is live — kept`
      : `cached hub "${target.needsProbe}" does not answer (${probe.error})`;
  }
  const actionable = targets.filter((t) => t.kind !== "cached-hub" || t.stale === true);

  const owner = inspectPortOwner(HUB_PORT);
  const hubProbe = owner.listening ? await probeHubStatus("127.0.0.1", HUB_PORT, LOOPBACK_PROBE_TIMEOUT_MS) : { reachable: false };
  const portTarget = {
    port: HUB_PORT,
    listening: owner.listening,
    isOmpLinkHub: hubProbe.reachable === true,
    ownershipProven: owner.provable === true && owner.listening === true,
    pids: owner.pids || [],
    reason:
      owner.listening === false
        ? "nothing is listening"
        : owner.provable !== true
          ? owner.reason
          : hubProbe.reachable !== true
            ? "the listener did not answer /status as an omp-link hub"
            : null,
  };
  const stoppable = portTarget.listening === true && portTarget.isOmpLinkHub && portTarget.ownershipProven;

  if (flags.json === true) {
    const performed = apply ? await applyCleanup(actionable) : [];
    emitJson({
      mode: apply ? "apply" : "preview",
      targets: actionable.map((t) => ({ kind: t.kind, path: t.path, detail: t.detail })),
      skipped: targets.filter((t) => !actionable.includes(t)).map((t) => ({ kind: t.kind, path: t.path, detail: t.detail })),
      port: { ...portTarget, stoppable },
      performed,
    });
    return EXIT.OK;
  }

  emit(apply ? "omp-link cleanup — applying\n" : "omp-link cleanup — preview only, nothing will be changed\n");

  if (actionable.length === 0) {
    emit("  No link-owned leftovers found.");
  } else {
    for (const target of actionable) {
      const verb = target.kind === "cached-hub" ? "clear" : "remove";
      emit(`  [${target.kind}] ${verb} ${target.path}`);
      emit(`      ${target.detail}`);
    }
  }
  for (const kept of targets.filter((t) => !actionable.includes(t))) {
    emit(`  [keep] ${kept.path}`);
    emit(`      ${kept.detail}`);
  }

  emit("");
  emit(`  tcp ${HUB_PORT}:`);
  if (portTarget.listening === false) {
    emit("      nothing listening — nothing to reclaim");
  } else if (!stoppable) {
    emit(`      REFUSING to stop it: ${portTarget.reason}`);
    emit("      This CLI never signals a process it cannot prove is an omp-link hub owned by you.");
  } else {
    emit(`      omp-link hub on pid ${portTarget.pids.join(", ")} (owned by ${userInfo().username})`);
    emit(`      room "${hubProbe.status?.roomId || "(unnamed)"}", protocol v${hubProbe.status?.protocolVersion}`);
    emit("      Stopping it drops every peer joined to this machine.");
    if (!apply) emit("      Re-run with --apply --yes to stop it.");
  }

  if (!apply) {
    emit("");
    emit("  Nothing was changed. Re-run with --apply to act on the items above.");
    return EXIT.OK;
  }

  const performed = await applyCleanup(actionable);
  for (const entry of performed) {
    emit(`  ${entry.ok ? "done" : "failed"}: ${entry.kind} ${entry.path}${entry.error ? ` (${entry.error})` : ""}`);
  }

  if (stoppable) {
    const agreed = await confirm(`  Stop the omp-link hub on pid ${portTarget.pids.join(", ")}?`, flags);
    if (!agreed) {
      emit(
        flags.noInput === true
          ? "  Skipped stopping the hub: --no-input was given and --yes was not."
          : "  Skipped stopping the hub.",
      );
      return EXIT.REFUSED;
    }
    for (const pid of portTarget.pids) {
      try {
        process.kill(pid, "SIGTERM");
        emit(`  done: sent SIGTERM to pid ${pid}`);
      } catch (err) {
        emit(`  failed: could not signal pid ${pid} (${err.message})`);
      }
    }
  }

  return EXIT.OK;
}

/**
 * Invariant 17's `atomicWriteSecureFile`, re-implemented because this file must run under bare
 * `node` and cannot import the TypeScript helper. `link.json` has a second writer — `saveConfig`
 * inside a live terminal — so a plain `writeFileSync` here is observable truncated by a reader
 * and either write can silently drop the other's content.
 */
function atomicWriteSecureFileSync(filePath, content) {
  const tmpPath = `${filePath}.tmp.${randomBytes(6).toString("hex")}`;
  try {
    writeFileSync(tmpPath, content, { mode: 0o600 });
    try {
      chmodSync(tmpPath, 0o600);
    } catch {}
    renameSync(tmpPath, filePath);
  } catch (err) {
    try {
      rmSync(tmpPath, { force: true });
    } catch {}
    throw err;
  }
}

async function applyCleanup(targets) {
  const performed = [];
  for (const target of targets) {
    try {
      if (target.kind === "cached-hub") {
        const config = JSON.parse(readFileSync(target.path, "utf-8"));
        delete config.hub;
        atomicWriteSecureFileSync(target.path, `${JSON.stringify(config, null, 2)}\n`);
      } else if (target.kind === "orphan-staging") {
        rmSync(target.path, { recursive: true, force: true });
      } else if (target.kind === "dead-symlink") {
        rmSync(target.path, { force: true });
      }
      performed.push({ kind: target.kind, path: target.path, ok: true, error: null });
    } catch (err) {
      performed.push({ kind: target.kind, path: target.path, ok: false, error: err.message });
    }
  }
  return performed;
}

/**
 * `update` runs three steps that execute code: `git pull` (hooks, filters), `npm install` (every
 * dependency's lifecycle scripts) and `setup.sh`. None of them inherit the ambient environment.
 * Mirrors `safeGitExecFile` in src/inspection.ts (invariant 16), re-implemented because this file
 * runs under bare `node` and cannot import the TypeScript helper.
 *
 * Two deliberate differences from `safeGitExecFile`: the directory of the running `node` is kept
 * on PATH (an nvm/volta install has no npm anywhere else, and dropping it would break update on
 * a normal machine), and the user's own git config is left alone — `GIT_CONFIG_GLOBAL=/dev/null`
 * is right for read-only inspection but would strip the credential helper this pull may need.
 * What is dropped is what another process can inject into this one.
 */
const SAFE_ENV = (() => {
  const env = { ...process.env };
  const injected = [
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "NODE_OPTIONS",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_EXEC_PATH",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
  ];
  for (const key of Object.keys(env)) {
    if (injected.includes(key) || key.startsWith("GIT_CONFIG")) delete env[key];
  }
  env.PATH = [
    ...new Set([dirname(process.execPath), "/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]),
  ].join(":");
  return env;
})();

/** Remote-controlled text — a remote URL, a commit subject — printed to a terminal. */
function plainLine(value, maxLength = 160) {
  const stripped = String(value).replace(/[^\x20-\x7E]/g, "");
  return stripped.length > maxLength ? `${stripped.slice(0, maxLength - 3)}...` : stripped;
}

/** A git query whose output this command reads. Returns null when git refuses. */
function gitCapture(args) {
  try {
    return execFileSync("git", args, {
      cwd: REPO_DIR,
      encoding: "utf-8",
      env: SAFE_ENV,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    return null;
  }
}

async function runUpdate(flags) {
  if (!existsSync(join(REPO_DIR, ".git"))) {
    emit(`No git checkout at ${REPO_DIR}. Extract the new version and run ./setup.sh.`);
    return EXIT.UNAVAILABLE;
  }
  if (flags.json === true) {
    emitJson({ error: "update streams subprocess output and does not support --json" });
    return EXIT.USAGE;
  }

  // Say where the code is about to come from before fetching any of it. An update is the one
  // command here that runs whatever the remote hands back, so the remote is part of the prompt.
  const remoteUrl = gitCapture(["remote", "get-url", "origin"]);
  if (!remoteUrl) {
    console.error(`${REPO_DIR} has no 'origin' remote. Add one, or update by hand.`);
    return EXIT.UNAVAILABLE;
  }
  const branch = gitCapture(["rev-parse", "--abbrev-ref", "HEAD"]) || "HEAD";
  emit(`Updating omp-link in ${REPO_DIR}`);
  emit(`  remote origin: ${plainLine(remoteUrl)}`);
  emit(`  current HEAD:  ${plainLine(gitCapture(["rev-parse", "--short", "HEAD"]) || "unknown")} (${plainLine(branch, 64)})`);
  emit("");

  // `git pull --rebase --autostash` rewrites the working tree. On a dirty checkout it can stop
  // mid-rebase and leave the local work in a stash, so it is never done without consent.
  let dirty = "";
  try {
    dirty = execFileSync("git", ["status", "--porcelain"], {
      cwd: REPO_DIR,
      encoding: "utf-8",
      env: SAFE_ENV,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (err) {
    console.error(`Cannot read the git status of ${REPO_DIR}: ${err.message}`);
    return EXIT.ERROR;
  }
  if (dirty) {
    const changed = dirty.split("\n");
    emit(`${REPO_DIR} has ${changed.length} uncommitted change(s):`);
    for (const line of changed.slice(0, 10)) emit(`  ${plainLine(line.trim())}`);
    if (changed.length > 10) emit(`  ... and ${changed.length - 10} more`);
    emit("");
    emit("  Updating runs `git pull --rebase --autostash`, which rebases these changes and can");
    emit("  stop mid-conflict with your work in a stash.");
    const agreed = await confirm("  Update anyway?", flags);
    if (!agreed) {
      emit(
        flags.noInput === true
          ? "  Refused: the checkout is dirty, --no-input was given and --yes was not."
          : "  Nothing was changed. Commit or stash your work first, then re-run.",
      );
      return EXIT.REFUSED;
    }
    emit("");
  }

  // Fetch first: the pull is then a local fast-forward of commits already shown below.
  emit("Fetching origin...");
  try {
    execFileSync("git", ["fetch", "--quiet", "origin"], { cwd: REPO_DIR, stdio: "inherit", env: SAFE_ENV });
  } catch (err) {
    console.error(`Fetch failed: ${err.message}`);
    return EXIT.ERROR;
  }

  const upstream =
    gitCapture(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"]) ||
    (gitCapture(["rev-parse", "--verify", "--quiet", `origin/${branch}`]) ? `origin/${branch}` : null);
  const incoming = upstream ? gitCapture(["log", "--oneline", "--no-decorate", "--no-color", `HEAD..${upstream}`]) : null;

  if (!upstream || incoming === null) {
    emit(`  Cannot list what would be pulled: no upstream branch resolves for '${plainLine(branch, 64)}'.`);
    const agreed = await confirm("  Pull anyway, without seeing the incoming commits?", flags);
    if (!agreed) {
      emit("  Nothing was changed.");
      return EXIT.REFUSED;
    }
  } else if (incoming === "") {
    emit(`  Already up to date with ${plainLine(upstream, 64)}. Re-running the installer.`);
  } else {
    const commits = incoming.split("\n");
    emit(`  Incoming: HEAD..${plainLine(upstream, 64)} — ${commits.length} commit(s)`);
    for (const line of commits.slice(0, 20)) emit(`    ${plainLine(line)}`);
    if (commits.length > 20) emit(`    ... and ${commits.length - 20} more`);
    emit("");
    emit("  Applying them runs their code: git hooks, every dependency lifecycle script that");
    emit("  `npm install` triggers, and setup.sh.");
    const agreed = await confirm("  Apply?", flags);
    if (!agreed) {
      emit(
        flags.noInput === true
          ? "  Refused: there are incoming commits, --no-input was given and --yes was not."
          : "  Nothing was changed.",
      );
      return EXIT.REFUSED;
    }
  }

  emit("");
  try {
    execFileSync("git", ["pull", "--rebase", "--autostash"], { cwd: REPO_DIR, stdio: "inherit", env: SAFE_ENV });
    execFileSync("npm", ["install", "--silent"], { cwd: REPO_DIR, stdio: "inherit", env: SAFE_ENV });
    const setupScript = join(REPO_DIR, "setup.sh");
    if (existsSync(setupScript)) execFileSync("bash", [setupScript], { stdio: "inherit", env: SAFE_ENV });
    // getVersion() caches at first call, so it still holds the pre-update number here.
    let installed = "unknown";
    try {
      installed = JSON.parse(readFileSync(join(REPO_DIR, "package.json"), "utf-8")).version || "unknown";
    } catch {}
    emit(`omp-link updated (now v${installed}).`);
    return EXIT.OK;
  } catch (err) {
    console.error(`Update failed: ${err.message}`);
    return EXIT.ERROR;
  }
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);
// `omp-link --json status` is a command, not a launcher invocation: find the first token that
// is not a flag (or a flag spelling of one of our verbs, like `--version`).
const head = argv.find((token) => !token.startsWith("-") || findCommand(token) !== null);
const known = head === undefined ? null : findCommand(head);
const removed = head !== undefined && Object.prototype.hasOwnProperty.call(REMOVED_COMMANDS, head.trim().toLowerCase());

if (!known && !removed) {
  // Not one of our verbs: this is a launcher invocation. Forward everything.
  const agentBin = resolveAgentBin();
  if (!agentBin) {
    console.error("Neither 'omp' nor 'pi' was found on PATH.");
    console.error("Install Oh My Pi (curl -fsSL https://omp.sh/install | sh) or set OMP_BIN.");
    process.exit(EXIT.UNAVAILABLE);
  }
  const child = spawn(agentBin, argv, { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code ?? EXIT.OK));
} else {
  const invocation = parseInvocation(argv, { surface: "cli" });
  jsonMode = invocation.flags.json === true;

  if (invocation.error) {
    console.error(invocation.error);
    process.exit(EXIT.USAGE);
  }

  const { command, positionals, flags } = invocation;
  let code = EXIT.OK;

  switch (command) {
    case "help":
      if (flags.json === true) {
        const only = positionals[0] ? findCommand(positionals[0]) : null;
        emitJson({
          version: VERSION,
          globalFlags: GLOBAL_FLAGS,
          commands: only ? [only] : COMMANDS,
          removed: REMOVED_COMMANDS,
        });
      } else {
        console.log(renderHelp(positionals[0]));
      }
      break;
    case "version":
      if (flags.json === true) emitJson({ version: VERSION });
      else console.log(VERSION);
      break;
    case "status":
      code = await runStatus(flags);
      break;
    case "scan":
      code = await runScan(flags);
      break;
    case "shared":
      code = runShared(flags);
      break;
    case "doctor":
      code = await runDoctor(flags);
      break;
    case "cleanup":
      code = await runCleanup(flags);
      break;
    case "update":
      code = await runUpdate(flags);
      break;
    default:
      console.error(`"${command}" is registered but not implemented in the CLI. This is a bug.`);
      code = EXIT.ERROR;
  }

  process.exit(code);
}
