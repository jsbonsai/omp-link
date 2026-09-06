#!/usr/bin/env node

// omp-link CLI — multi-machine coordination mesh for Oh My Pi and Pi
//
// Usage:
//   omp-link <name> [--global|-g] [flags...]
//                                Resume or create a named session, connected to link.
//   omp-link hub [name] [flags...]
//                                Start a session in hub mode, binding to Tailscale/LAN.
//   omp-link join [ip] [name] [flags...]
//                                Join an active hub on Tailnet/LAN.
//   omp-link find [--json]      Scan Tailnet & LAN for active hubs.
//   omp-link update             Pull latest changes from git and refresh extensions.
//   omp-link clean              Clean lingering processes and stale hub config.
//   omp-link --status [--json]  Show terminals connected to the running hub right now.
//   omp-link --list [--global|-g] List sessions in current cwd (or everywhere).
//   omp-link --version          Print the installed omp-link version.

import { readdir, stat } from "fs/promises";
import { createReadStream, existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { createInterface } from "readline";
import { join } from "path";
import { homedir, networkInterfaces } from "os";
import { spawn, execSync } from "child_process";
import dgram from "dgram";

// ── Link Config & Network Discovery ─────────────────────────────────────────

function getLinkConfigFiles() {
  return [
    join(homedir(), ".omp", "link.json"),
    join(homedir(), ".pi", "link.json"),
  ];
}

function loadSavedHub() {
  for (const file of getLinkConfigFiles()) {
    if (existsSync(file)) {
      try {
        const data = JSON.parse(readFileSync(file, "utf-8"));
        if (data && typeof data.hub === "string" && data.hub.trim()) {
          return data.hub.trim();
        }
      } catch {}
    }
  }
  return null;
}

function saveHubToConfig(hubAddress) {
  for (const file of getLinkConfigFiles()) {
    try {
      const dir = join(file, "..");
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
      let data = {};
      if (existsSync(file)) {
        try {
          data = JSON.parse(readFileSync(file, "utf-8"));
        } catch {}
      }
      if (hubAddress && hubAddress !== "none" && hubAddress !== "clear") {
        data.hub = hubAddress;
      } else {
        delete data.hub;
      }
      writeFileSync(file, JSON.stringify(data, null, 2) + "\n", "utf-8");
    } catch {}
  }
}

function getQuickNetworkInfo() {
  const nets = networkInterfaces();
  let tailscaleIp = null;
  let lanIp = null;
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === "IPv4" && !net.internal) {
        if (net.address.startsWith("100.")) {
          const second = parseInt(net.address.split(".")[1], 10);
          if (second >= 64 && second <= 127) {
            tailscaleIp = net.address;
          }
        } else if (!lanIp) {
          lanIp = net.address;
        }
      }
    }
  }
  return { tailscaleIp, lanIp };
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

function getTailnetPeers(includeSelf = true) {
  const bin = resolveTailscaleBin();
  if (!bin) return [];
  try {
    const stdout = execSync(`"${bin}" status --json`, {
      encoding: "utf-8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const status = JSON.parse(stdout);
    const peers = [];
    if (includeSelf && status.Self) {
      const ipv4 = status.Self.TailscaleIPs?.find((ip) => ip.startsWith("100."));
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
      for (const p of Object.values(status.Peer)) {
        if (p && p.Online) {
          const ipv4 = p.TailscaleIPs?.find((ip) => ip.startsWith("100."));
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

async function discoverTailnetHubs(port = 9900, timeoutMs = 800) {
  const peers = getTailnetPeers(true);
  if (peers.length === 0) return { peersCount: 0, hubs: [] };
  const results = await Promise.all(
    peers.map(async (peer) => {
      try {
        const res = await fetch(`http://${peer.ip}:${port}/status`, {
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (res.ok) {
          const payload = await res.json();
          if (payload && payload.hub && Array.isArray(payload.terminals)) {
            return {
              hubId: payload.hubId,
              host: peer.host,
              ip: peer.ip,
              port,
              hubName: payload.hub,
              dns: peer.dns,
              os: peer.os,
              terminals: payload.terminals,
              source: "tailscale",
              endpoints: [`${peer.ip}:${port}`],
            };
          }
        }
      } catch {}
      return null;
    }),
  );
  return { peersCount: peers.length, hubs: results.filter(Boolean) };
}

function discoverLanHubs(port = 9900, timeoutMs = 400, secret) {
  return new Promise((resolve) => {
    const found = new Map();
    let socket = null;
    const timer = setTimeout(() => {
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
        clearTimeout(timer);
        try { socket?.close(); } catch {}
        resolve(Array.from(found.values()));
      });
      socket.bind(0, () => {
        try {
          socket?.setBroadcast(true);
          const req = Buffer.from(secret ? `PI_LINK_DISCOVER:${secret}` : "PI_LINK_DISCOVER");
          socket?.send(req, 9901, "255.255.255.255");
        } catch {}
      });
    } catch {
      clearTimeout(timer);
      resolve([]);
    }
  });
}

async function discoverAllHubs(port = 9900, timeoutMs = 900, secret) {
  const [tailnetRes, lanHubs] = await Promise.all([
    discoverTailnetHubs(port, timeoutMs),
    discoverLanHubs(port, Math.min(timeoutMs, 500), secret),
  ]);

  const hubMap = new Map();

  function registerHub(hub, payload) {
    const hubId = hub.hubId || payload?.hubId;
    let existing = null;
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
      if (existing.ip === "127.0.0.1" && hub.ip !== "127.0.0.1") {
        existing.ip = hub.ip;
        existing.port = hub.port;
        existing.source = hub.source;
      } else if (hub.source === "lan" && existing.source === "tailscale") {
        existing.ip = hub.ip;
        existing.port = hub.port;
        existing.source = "lan";
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
      const payload = await res.json();
      if (payload && payload.hub && Array.isArray(payload.terminals)) {
        registerHub(
          {
            hubId: payload.hubId,
            host: payload.host || "localhost",
            ip: "127.0.0.1",
            port,
            hubName: payload.hub,
            terminals: payload.terminals,
            source: "local",
          },
          payload,
        );
      }
    }
  } catch {}

  await Promise.all(
    lanHubs.map(async (lan) => {
      try {
        const res = await fetch(`http://${lan.ip}:${lan.port}/status`, {
          signal: AbortSignal.timeout(400),
        });
        if (res.ok) {
          const payload = await res.json();
          if (payload && payload.hub && Array.isArray(payload.terminals)) {
            registerHub(
              {
                hubId: payload.hubId,
                host: payload.host || lan.host,
                ip: lan.ip,
                port: lan.port,
                hubName: payload.hub,
                terminals: payload.terminals,
                source: "lan",
              },
              payload,
            );
          }
        }
      } catch {}
    }),
  );

  return { hubs: Array.from(hubMap.values()), tailnetPeersCount: tailnetRes.peersCount };
}

// Canonicalize a link/session name: trim + collapse internal whitespace.
// Must match the extension's normalizeName (index.ts).
function normalizeName(s) {
  return s.trim().replace(/\s+/g, " ");
}

// ── Pi config resolution ───────────────────────────────────────────────────
// Match Pi's session-dir lookup order so list/resolve/<name> see what Pi sees.
// Custom sessionDir → flat layout; default → <agentDir>/sessions/<encoded-cwd>.

// Match Pi's expandTildePath: only `~` and `~/...`.
function expandTilde(p) {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

function readSessionDirFromSettings(settingsPath) {
  if (!existsSync(settingsPath)) return undefined;
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(settingsPath, "utf-8"));
  } catch (err) {
    console.error(`pi-link: ignored ${settingsPath}: ${err.message}`);
    return undefined;
  }
  const value = parsed?.sessionDir;
  if (typeof value !== "string" || value.trim() === "") return undefined;
  return value;
}

// PI_CODING_AGENT_DIR also relocates global settings.json to <agentDir>/settings.json.
function resolveAgentDir() {
  const env = process.env.PI_CODING_AGENT_DIR || process.env.OMP_AGENT_DIR;
  if (env) return expandTilde(env);
  const scriptName = process.argv[1] ? process.argv[1].split(/[/\\]/).pop() : "";
  const preferOmp = scriptName && scriptName.includes("omp");
  const ompDir = join(homedir(), ".omp", "agent");
  const piDir = join(homedir(), ".pi", "agent");
  if (preferOmp) {
    if (existsSync(ompDir)) return ompDir;
    if (existsSync(piDir)) return piDir;
    return ompDir;
  }
  if (existsSync(piDir)) return piDir;
  if (existsSync(ompDir)) return ompDir;
  return piDir;
}

// Returns { dir, isCustom }. isCustom drives layout in scanSessions:
// true → flat <dir>/*.jsonl, false → <dir>/<encoded-cwd>/*.jsonl.
function resolveSessionDir(cwd, agentDir) {
  const env = process.env.PI_CODING_AGENT_SESSION_DIR;
  if (env) return { dir: expandTilde(env), isCustom: true };

  const projectDir = readSessionDirFromSettings(join(cwd, ".pi", "settings.json"));
  if (projectDir) return { dir: expandTilde(projectDir), isCustom: true };

  const globalDir = readSessionDirFromSettings(join(agentDir, "settings.json"));
  if (globalDir) return { dir: expandTilde(globalDir), isCustom: true };

  return { dir: join(agentDir, "sessions"), isCustom: false };
}

// Reads a session JSONL file and returns its display name, cwd, id, link
// status, and message count. Returns null when `scopeCwd` is given and the
// session's header names a different cwd.
//
// Name precedence: latest valid `link-name` custom entry wins as the
// authoritative pi-link name. `session_info.name` is only a fallback for
// sessions that never set a link-name. Historical link-names are not aliases.
//
// A scoped scan only ever keeps sessions from `scopeCwd`, so a session whose
// header names another cwd is abandoned there instead of being read to EOF for
// a name that would be filtered out anyway. Pi writes that header as the first
// complete line of the file, before any history.
//
// Only `undefined` means unscoped: a normalized scope is the empty string at
// POSIX root, which is a real scope and must not read as "no scope".
async function getSessionMeta(filePath, scopeCwd) {
  let linkName;
  let sessionName;
  let cwd;
  let id;
  let hasLinkName = false;
  let messages = 0;
  const input = createReadStream(filePath, "utf-8");
  const rl = createInterface({ input, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line) continue;
    try {
      const entry = JSON.parse(line);
      if (entry.type === "session") {
        if (typeof entry.cwd === "string") {
          if (scopeCwd !== undefined && normalizePath(entry.cwd) !== scopeCwd) {
            rl.close();
            input.destroy();
            return null;
          }
          cwd = entry.cwd;
        }
        if (typeof entry.id === "string") id = entry.id;
      } else if (entry.type === "session_info" && typeof entry.name === "string") {
        sessionName = normalizeName(entry.name) || undefined;
      } else if (entry.type === "custom" && entry.customType === "link-name") {
        hasLinkName = true;
        if (entry.data && typeof entry.data.name === "string") {
          const n = normalizeName(entry.data.name);
          if (n) linkName = n;
        }
      } else if (entry.type === "message" || entry.type === "user" || entry.type === "assistant") {
        messages++;
      }
    } catch {
      // skip malformed lines (incl. partial last line of active sessions)
    }
  }
  return { name: linkName ?? sessionName, cwd, id, hasLinkName, messages };
}

function normalizePath(p) {
  let s = p.replace(/[/\\]+/g, "/").replace(/\/+$/, "");
  if (process.platform === "win32") s = s.toLowerCase();
  return s;
}

// Replace $HOME with ~ in display paths. Comparison is normalized
// (case-insensitive on Windows) but display preserves original casing.
function displayPath(p) {
  if (!p) return p;
  const home = homedir();
  const normP = normalizePath(p);
  const normHome = normalizePath(home);
  if (normP === normHome) return "~";
  if (normP.startsWith(normHome + "/")) return "~" + p.slice(home.length).replace(/\\/g, "/");
  return p;
}

const useAnsi =
  !!process.stdout.isTTY &&
  process.env.NO_COLOR === undefined &&
  process.env.TERM !== "dumb";
const bold = (s) => (useAnsi ? `\x1b[1m${s}\x1b[22m` : s);
const dim = (s) => (useAnsi ? `\x1b[2m${s}\x1b[22m` : s);

// What `--status` prints for a field the hub could not report. Declared here,
// above the dispatcher: the mode handlers are hoisted functions, but a `const`
// read from one would still be in its temporal dead zone when dispatch runs.
const UNKNOWN = "?";

function relTime(d) {
  const sec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}d ago`;
  return d.toISOString().slice(0, 10);
}

async function loadSessionRecord(filePath, scopeCwd) {
  try {
    const meta = await getSessionMeta(filePath, scopeCwd);
    if (!meta) return null; // known-foreign: not even worth a stat
    const stats = await stat(filePath);
    return { ...meta, modified: stats.mtime, path: filePath };
  } catch {
    return null;
  }
}

// Returns meta + mtime + path for every readable session in `dir`, or only
// those from `scopeCwd` when it is given. Custom layout is flat
// (<dir>/*.jsonl); default layout has one subdir level per encoded cwd
// (<dir>/<sub>/*.jsonl). Errors on individual files/dirs are silently skipped
// — active or partially-written sessions are tolerated.
async function scanSessions(dir, isCustom, scopeCwd) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }

  const tasks = [];
  if (isCustom) {
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".jsonl")) continue;
      tasks.push(loadSessionRecord(join(dir, entry.name), scopeCwd));
    }
  } else {
    for (const sub of entries) {
      if (!sub.isDirectory()) continue;
      const subPath = join(dir, sub.name);
      let files;
      try { files = await readdir(subPath); } catch { continue; }
      for (const file of files) {
        if (!file.endsWith(".jsonl")) continue;
        tasks.push(loadSessionRecord(join(subPath, file), scopeCwd));
      }
    }
  }

  return (await Promise.all(tasks)).filter((s) => s !== null);
}

// Find sessions whose current display name matches `targetName`, restricted to
// `scopeCwd` when given and searched across every cwd when not. Falls back to
// `session_info.name` for sessions without a link-name (so `pi-link <name>`
// can attach link to a previously-unlinked named session).
//
// The cwd predicate is applied here as well as in the scan: a session whose
// header carries no cwd is not rejected early, and must still be left out of a
// scoped result.
async function findSessionsByName(targetName, dir, isCustom, scopeCwd) {
  return (await scanSessions(dir, isCustom, scopeCwd))
    .filter((s) => s.name === targetName)
    .filter((s) => scopeCwd === undefined || (s.cwd && normalizePath(s.cwd) === scopeCwd))
    .map((s) => ({ path: s.path, cwd: s.cwd || "?", modified: s.modified }))
    .sort((a, b) => b.modified.getTime() - a.modified.getTime());
}

// List pi-link sessions (those with at least one link-name entry), restricted
// to `scopeCwd` when given and covering every cwd when not.
async function listSessions({ dir, isCustom, scopeCwd }) {
  return (await scanSessions(dir, isCustom, scopeCwd))
    .filter((s) => s.hasLinkName)
    .filter((s) => scopeCwd === undefined || (s.cwd && normalizePath(s.cwd) === scopeCwd))
    .map((s) => ({
      name: s.name || "(unnamed)",
      cwd: s.cwd || "?",
      id: s.id ? s.id.slice(0, 8) : "?",
      messages: s.messages,
      modified: s.modified,
      path: s.path,
    }))
    .sort((a, b) => b.modified.getTime() - a.modified.getTime());
}

// Renders a plain-text table. Widths are computed from unstyled cells; ANSI
// styles are applied after padding so column alignment is preserved when piped
// or styled. Mark a column with `dim: true` to render its cells dim.
function renderTable(rows, columns) {
  const widths = columns.map((c) => Math.max(c.header.length, ...rows.map((r) => String(c.get(r)).length)));
  const padCell = (text, i) => (i === columns.length - 1 ? text : text.padEnd(widths[i]));
  const styleBody = (text, i) => (columns[i].dim ? dim(text) : text);
  const headerLine = columns.map((c, i) => bold(padCell(c.header, i))).join("  ");
  const bodyLines = rows.map((r) =>
    columns.map((c, i) => styleBody(padCell(String(c.get(r)), i), i)).join("  "),
  );
  return [headerLine, ...bodyLines].join("\n");
}

// ── CLI ────────────────────────────────────────────────────────────────────

const rawArgs = process.argv.slice(2);

// Reject Pi flags that pi-link manages, plus --link-name (which exists at the
// `pi` level for link-only naming, but the wrapper's combined-mode contract
// conflicts with it). Called from Phase 4 (mode entry) and Phase 5 (after
// launcher name), so it fires on both `pi-link --session foo` and
// `pi-link foo --session bar` with the friendly message.
function rejectManagedFlag(token) {
  const key = token.split("=")[0];
  if (key === "--link-name") {
    console.error(
      "Error: --link-name is not accepted by the pi-link wrapper.\n" +
      "  Use 'pi-link <name>' for combined link+session,\n" +
      "  or run 'pi --link-name <name>' directly to set link name without session resolution.",
    );
    process.exit(1);
  }
  if (["--session", "--continue", "-c", "--resume", "-r", "--fork", "--no-session", "--session-dir"].includes(key)) {
    console.error(`Error: ${key} is managed by pi-link. Remove it.`);
    process.exit(1);
  }
}

function printCandidates(name, matches) {
  console.error(`Multiple sessions named "${name}":\n`);
  for (const m of matches) {
    console.error(`  ${m.modified.toISOString().slice(0, 19)}  cwd: ${m.cwd}`);
    console.error(`  ${m.path}\n`);
  }
  console.error(`Use: pi --session <path> --link`);
  process.exit(1);
}

function fail(msg) {
  console.error(`Error: ${msg}`);
  process.exit(1);
}

function printHelp() {
  console.error("Usage: omp-link <name> [--global|-g] [flags...]");
  console.error("       omp-link hub [name] [flags...]");
  console.error("       omp-link join [hub-ip] [name] [flags...]");
  console.error("       omp-link find [--json]");
  console.error("       omp-link --list [--global|-g]");
  console.error("       omp-link --status [--json]");
  console.error("       omp-link --resolve <name> [--global|-g]");
  console.error("       omp-link config [hub <ip|clear>]");
  console.error("       omp-link --version");
  console.error("");
  console.error("Multi-machine coordination:");
  console.error("  hub          Start as the main hub endpoint (binds to Tailscale/LAN)");
  console.error("  join [ip]    Join a hub (auto-discovers Tailnet & LAN if ip omitted)");
  console.error("  find         Search for active hubs & sessions on Tailnet & LAN");
  console.error("  config       Inspect or set link configuration");
  console.error("");
  console.error("Maintenance and cleanup:");
  console.error("  update       Pull latest changes from git and refresh extensions");
  console.error("  clean        Terminate lingering processes on port 9900/9901 & reset cached hub");
  console.error("");
  console.error("Status and session commands:");
  console.error("  --status     Query active terminals across all connected machines");
  console.error("  --list       List saved sessions in current cwd (or everywhere with -g)");
}

function printVersion() {
  try {
    const pkg = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf-8"),
    );
    console.log(pkg.version ?? "unknown");
  } catch {
    console.log("unknown");
  }
}

function describeMode(mode) {
  switch (mode) {
    case "help": return "--help";
    case "version": return "--version";
    case "list": return "--list";
    case "status": return "--status";
    case "resolve": return "--resolve";
    case "hub": return "hub";
    case "join": return "join";
    case "find": return "find";
    case "config": return "config";
    case "launcher": return "session name";
    default: return mode;
  }
}

// ── Parser ─────────────────────────────────────────────────────────────────
//
// Single sequential pass populates `state`; dispatcher reads it. Phases:
//   1. Global flags (--global, --help, --version, --)
//   2. Mode-selecting flags (--list, --resolve, --resolve=<name>)
//   3. Mode-specific extra-token rejection
//   4. Command / launcher mode entry (hub, join, config, or session name)
//   5. Passthrough with orphan-positional rejection

const state = {
  mode: null, // null | "help" | "version" | "list" | "status" | "resolve" | "launcher" | "hub" | "join" | "config"
  resolveName: null,
  launcherName: null,
  hubTarget: null,
  configAction: null,
  configValue: null,
  global: false,
  json: false,
  saveHub: false,
  piPassthrough: [],
};

function setMode(mode) {
  if (state.mode !== null && state.mode !== mode) {
    fail(`cannot combine ${describeMode(state.mode)} and ${describeMode(mode)}`);
  }
  state.mode = mode;
}

let lastWasFlag = false;

for (let i = 0; i < rawArgs.length; i++) {
  const a = rawArgs[i];

  // Phase 1: global flags / scope-affecting tokens.
  if (a === "--save" || a === "-s") {
    state.saveHub = true;
    continue;
  }
  if (a === "--global" || a === "-g") {
    state.global = true;
    lastWasFlag = false;
    continue;
  }
  if (a === "--help" || a === "-h") {
    setMode("help"); // errors if combined with another mode
    continue;
  }
  if (a === "--version") {
    setMode("version"); // errors if combined with another mode
    continue;
  }
  if (a === "--") {
    // `--` only meaningful in launcher mode (separates pi flags from positionals).
    if (state.mode !== "launcher") {
      fail(`-- is only valid after a session name`);
    }
    for (let j = i + 1; j < rawArgs.length; j++) {
      state.piPassthrough.push(rawArgs[j]);
    }
    i = rawArgs.length;
    break;
  }

  // `--json` modifies --status and find only. Claimed before a mode exists so order does
  // not matter, but never in launcher mode, where it belongs to pi.
  if (a === "--json" && (state.mode === null || state.mode === "status" || state.mode === "find")) {
    state.json = true;
    continue;
  }

  // Phase 2: mode-selecting flags.
  if (a === "--list") {
    setMode("list");
    continue;
  }
  // Selects the wrapper's own mode only before a session name has been seen.
  // After that it is pi's flag, exactly like `--json` above — intercepting it
  // unconditionally would break `pi-link foo --status`.
  if (a === "--status" && state.mode !== "launcher") {
    setMode("status");
    continue;
  }
  if (a.startsWith("--resolve=")) {
    setMode("resolve");
    if (state.resolveName !== null) fail(`--resolve specified more than once`);
    state.resolveName = a.slice("--resolve=".length);
    continue;
  }
  if (a === "--resolve") {
    setMode("resolve");
    if (state.resolveName !== null) fail(`--resolve specified more than once`);
    const next = rawArgs[i + 1];
    if (next === undefined || next.startsWith("-")) {
      fail(`--resolve requires a name argument.\n  Usage: pi-link --resolve <name> [--global|-g]`);
    }
    state.resolveName = next;
    i++; // consume the value
    continue;
  }

  // Phase 3: mode-specific extra-token rejection.
  if (state.mode === "help") {
    fail(`--help does not accept arguments: ${a}`);
  }
  if (state.mode === "version") {
    fail(`--version does not accept arguments: ${a}`);
  }
  if (state.mode === "list") {
    fail(`--list does not accept argument: ${a}\n  Usage: pi-link --list [--global|-g]`);
  }
  if (state.mode === "status") {
    fail(`--status does not accept arguments: ${a}\n  Usage: pi-link --status [--json]`);
  }
  if (state.mode === "find") {
    fail(`find does not accept arguments: ${a}\n  Usage: omp-link find [--json]`);
  }
  if (state.mode === "resolve") {
    fail(`--resolve accepts exactly one name; got extra: ${a}`);
  }

  // Phase 4: command / launcher mode entry. state.mode === null here, no name set yet.
  if (state.mode === null) {
    if (a === "update" || a === "upgrade") {
      state.mode = "update";
      continue;
    }

    if (a === "clean" || a === "kill" || a === "reset") {
      state.mode = "clean";
      continue;
    }

    if (a === "find" || a === "search" || a === "discover") {
      state.mode = "find";
      continue;
    }

    if (a === "hub") {
      state.mode = "hub";
      const next = rawArgs[i + 1];
      if (next !== undefined && !next.startsWith("-")) {
        state.launcherName = next;
        i++;
      } else {
        const cwdProject = process.cwd().split(/[/\\]/).pop();
        state.launcherName = cwdProject && cwdProject !== "main" ? cwdProject : "hub";
      }
      continue;
    }

    if (a === "join") {
      state.mode = "join";
      const next = rawArgs[i + 1];
      if (next !== undefined && !next.startsWith("-")) {
        if (next === "lan" || next === "tailnet" || next === "ts" || next.includes(".") || next.includes(":")) {
          state.hubTarget = next;
          i++;
          const nextNext = rawArgs[i + 1];
          if (nextNext !== undefined && !nextNext.startsWith("-")) {
            state.launcherName = nextNext;
            i++;
          }
        } else {
          // next is a session name!
          state.launcherName = next;
          i++;
        }
      }
      if (!state.launcherName) {
        const cwdProject = process.cwd().split(/[/\\]/).pop();
        state.launcherName = cwdProject && cwdProject !== "main" ? cwdProject : "worker";
      }
      continue;
    }

    if (a === "config") {
      state.mode = "config";
      const next = rawArgs[i + 1];
      if (next !== undefined && !next.startsWith("-")) {
        state.configAction = next;
        i++;
        const nextVal = rawArgs[i + 1];
        if (nextVal !== undefined && !nextVal.startsWith("-")) {
          state.configValue = nextVal;
          i++;
        }
      }
      continue;
    }

    rejectManagedFlag(a);
    if (a.startsWith("-")) {
      fail(`Unknown argument: ${a}\n  Usage: omp-link <name> [--global|-g] [pi flags...]`);
    }
    if (a === "list" || a === "resolve") {
      fail(`'omp-link ${a}' was removed. Use 'omp-link --${a}'.`);
    }
    state.mode = "launcher";
    state.launcherName = a;
    continue;
  }

  // Phase 5: launcher / hub / join mode. Tokens go to passthrough or get rejected.
  if (state.mode === "launcher" || state.mode === "hub" || state.mode === "join") {
    rejectManagedFlag(a);
    if (a.startsWith("-")) {
      state.piPassthrough.push(a);
      lastWasFlag = !a.includes("=");
      continue;
    }
    if (lastWasFlag) {
      state.piPassthrough.push(a);
      lastWasFlag = false;
      continue;
    }
    fail(`Unexpected argument after session name: ${a}\n  Use -- to pass positional arguments to pi.`);
  }
}

// ── Post-parse validation ──────────────────────────────────────────────────

if (state.mode === "resolve") {
  if (state.resolveName === null) {
    fail(`--resolve requires a name argument.\n  Usage: omp-link --resolve <name> [--global|-g]`);
  }
  const normalized = normalizeName(state.resolveName);
  if (!normalized) {
    fail(`--resolve requires a non-empty name argument.\n  Usage: omp-link --resolve <name> [--global|-g]`);
  }
  state.resolveName = normalized;
}
// `--status` reads one running hub, so a cwd scope is meaningless rather than
// merely unused: silently ignoring `-g` would imply a filter that cannot exist.
if (state.mode === "status" && state.global) {
  fail(`cannot combine --status and --global`);
}
if (state.json && state.mode !== "status" && state.mode !== "find") {
  fail(`--json is only valid with --status or find`);
}
if (state.mode === "launcher" || state.mode === "hub" || state.mode === "join") {
  const normalized = normalizeName(state.launcherName || "main");
  if (!normalized) {
    fail(`session name cannot be empty.\n  Usage: omp-link <name> [--global|-g] [pi flags...]`);
  }
  state.launcherName = normalized;
}

// ── Dispatch ───────────────────────────────────────────────────────────────

switch (state.mode) {
  case null:
  case "help":
    printHelp();
    process.exit(0);
    break; // unreachable; present to satisfy no-fallthrough lints
  case "version":
    printVersion();
    process.exit(0);
    break; // unreachable; present to satisfy no-fallthrough lints
  case "list":
    await runList(state);
    break;
  case "status":
    await runStatus(state);
    break;
  case "resolve":
    await runResolve(state);
    break;
  case "config":
    runConfig(state);
    process.exit(0);
  case "find":
    await runFind(state);
    process.exit(0);
  case "clean":
    await runClean(state);
    process.exit(0);
  case "update":
    await runUpdate(state);
    process.exit(0);
  case "hub":
  case "join":
  case "launcher":
    await runLauncher(state);
    break;
  default:
    fail(`internal error: unknown mode ${state.mode}`);
}

// ── Mode handlers ──────────────────────────────────────────────────────────

// A local operation scans only its own cwd; `--global` scans every cwd.
function localScope(state) {
  return state.global ? undefined : normalizePath(process.cwd());
}

async function runList(state) {
  const { dir, isCustom } = resolveSessionDir(process.cwd(), resolveAgentDir());
  const sessions = await listSessions({ dir, isCustom, scopeCwd: localScope(state) });
  if (sessions.length === 0) {
    console.log(state.global ? "No pi-link sessions found." : "No pi-link sessions found in this cwd.");
    console.log("Start one: pi-link <name>");
    return;
  }
  const columns = state.global
    ? [
      { header: "NAME", get: (s) => s.name },
      { header: "CWD", get: (s) => displayPath(s.cwd) },
      { header: "MODIFIED", get: (s) => relTime(s.modified), dim: true },
      { header: "MESSAGES", get: (s) => s.messages, dim: true },
      { header: "ID", get: (s) => s.id, dim: true },
    ]
    : [
      { header: "NAME", get: (s) => s.name },
      { header: "MODIFIED", get: (s) => relTime(s.modified), dim: true },
      { header: "MESSAGES", get: (s) => s.messages, dim: true },
      { header: "ID", get: (s) => s.id, dim: true },
    ];
  console.log(renderTable(sessions, columns));
  if (process.stdout.isTTY) {
    console.log("");
    console.log(dim("Resume: pi-link <name>"));
  }
}

// ── Status (live hub query) ────────────────────────────────────────────────
//
// `--list` reads saved history; `--status` asks the hub who is connected now.
// The two answer different questions, so they share no code path.

// Mirrors the extension's formatTokens so both renderings of one number agree.
function formatTokens(n) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${Math.round(n / 1000)}K`;
  return `${n}`;
}

// `92K/272K (34%)`, or `?/272K` when the hub has a window but no token count.
// Only reached for a validated payload, so `c` is null or a well-typed snapshot;
// a non-positive window is still possible and still means nothing to report.
function formatContext(c) {
  if (!c || c.window <= 0) return UNKNOWN;
  const window = formatTokens(c.window);
  if (typeof c.tokens !== "number") return `${UNKNOWN}/${window}`;
  return `${formatTokens(c.tokens)}/${window} (${Math.round((c.tokens / c.window) * 100)}%)`;
}

function formatAge(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h`;
}

// `status` and `sinceSeconds` are an optional pair: the hub omits them for a
// terminal it has registered but not yet heard from. Absence means unknown, so
// it must render as unknown — printing `idle` there would be an invention, and
// acting on it is the misreporting this command exists to end.
function formatTerminalStatus(entry) {
  if (typeof entry.status !== "string") return UNKNOWN;
  return `${entry.status} (${formatAge(entry.sinceSeconds)})`;
}

function failUnsupported() {
  console.error("Link hub does not support /status \u2014 update pi-link and restart terminals.");
  process.exit(1);
}

function failNoHub(port, host = "127.0.0.1") {
  console.error(`No link hub running on ${host}:${port}.`);
  process.exit(2);
}

// The frozen contract, checked before any field is read. Anything else on the
// port — a different service, a newer hub, a truncated proxy — must produce the
// unsupported message, never a stack trace. Unknown extra fields stay allowed.
function isContextField(c) {
  if (c === null) return true;
  if (!c || typeof c !== "object") return false;
  return (c.tokens === null || typeof c.tokens === "number") && typeof c.window === "number";
}

function isTerminalEntry(entry, index) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
  if (typeof entry.name !== "string") return false;
  // Hub first, then clients — the ordering the renderer relies on.
  if (entry.role !== (index === 0 ? "hub" : "client")) return false;
  // `status` and `sinceSeconds` are one optional pair: both or neither.
  //
  // The value is checked for shape, not vocabulary. `idle`/`thinking`/
  // `compacting`/`tool:<name>` are today's kinds, but that set has already grown
  // once (`compacting` arrived after 0.3.0) and the CLI never branches on it — it
  // only prints it. Freezing the list here would make a newer hub's fifth kind
  // reject the whole payload, and only while some terminal happened to be in that
  // state: an intermittent failure telling the user to update. An empty string is
  // still rejected, because it renders as a blank cell with a bare duration.
  const hasStatus = "status" in entry;
  if (hasStatus !== ("sinceSeconds" in entry)) return false;
  if (hasStatus && (typeof entry.status !== "string" || entry.status === "" || typeof entry.sinceSeconds !== "number")) {
    return false;
  }
  if ("cwd" in entry && typeof entry.cwd !== "string") return false;
  return "context" in entry && isContextField(entry.context);
}

function isStatusPayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return false;
  if (typeof payload.hub !== "string" || typeof payload.port !== "number") return false;
  // A hub always reports itself, so an empty list is not this contract.
  if (!Array.isArray(payload.terminals) || payload.terminals.length === 0) return false;
  if (!payload.terminals.every(isTerminalEntry)) return false;
  return payload.terminals[0].name === payload.hub;
}

async function runStatus(state) {
  let host = "127.0.0.1";
  let port = process.env.PI_LINK_PORT ?? 9900;
  const savedHub = loadSavedHub();
  const hubTarget = process.env.PI_LINK_HUB || savedHub;
  if (hubTarget && hubTarget !== "lan" && hubTarget !== "none" && hubTarget !== "local") {
    const parts = hubTarget.split(":");
    if (parts[0]) host = parts[0];
    if (parts[1]) port = Number(parts[1]) || port;
  }
  const deadline = AbortSignal.timeout(3000);
  let response;
  try {
    response = await fetch(`http://${host}:${port}/status`, { signal: deadline });
  } catch {
    failNoHub(port, host);
  }

  if (!response.ok) failUnsupported();

  let body;
  try {
    body = await response.text();
  } catch {
    if (deadline.aborted) failNoHub(port, host);
    failUnsupported();
  }

  let payload;
  try {
    payload = JSON.parse(body);
  } catch {
    failUnsupported();
  }
  if (!isStatusPayload(payload)) failUnsupported();

  if (state.json) {
    process.stdout.write(body);
    return;
  }

  console.log(
    renderTable(payload.terminals, [
      { header: "NAME", get: (e) => e.name },
      { header: "HOST", get: (e) => e.host || "local" },
      { header: "PROJECT", get: (e) => e.project || (e.cwd ? e.cwd.split(/[/\\]/).pop() : UNKNOWN) },
      { header: "STATUS", get: (e) => formatTerminalStatus(e) },
      { header: "CONTEXT", get: (e) => formatContext(e.context) },
      { header: "CWD", get: (e) => (e.cwd ? displayPath(e.cwd) : UNKNOWN), dim: true },
    ]),
  );
}

async function runFind(state) {
  const port = Number(process.env.PI_LINK_PORT) || 9900;
  console.log("⚡ Searching for active pi-link hubs on Tailnet & LAN...");
  const { hubs, tailnetPeersCount } = await discoverAllHubs(port, 1000);

  if (state.json) {
    process.stdout.write(JSON.stringify(hubs, null, 2) + "\n");
    return;
  }

  if (hubs.length === 0) {
    console.log(`\nNo active hubs found.`);
    if (tailnetPeersCount > 0) {
      console.log(`  Scanned ${tailnetPeersCount} online Tailnet peers + LAN broadcast.`);
    } else {
      console.log(`  Scanned LAN broadcast (Tailscale CLI not found or 0 online peers).`);
    }
    console.log(`\nTo start a hub on this machine:`);
    console.log(`  omp-link hub [session-name]`);
    return;
  }

  console.log(`\nFound ${hubs.length} active pi-link hub(s):\n`);
  const rows = [];
  for (const h of hubs) {
    const termCount = h.terminals ? h.terminals.length : 1;
    const projectList = (h.terminals || [])
      .map((t) => t.project || (t.cwd ? t.cwd.split(/[/\\]/).pop() : null))
      .filter(Boolean);
    const uniqueProjects = Array.from(new Set(projectList)).join(", ") || "(none)";

    rows.push({
      HOST: h.host,
      ENDPOINT: `${h.ip}:${h.port}`,
      SOURCE: h.source === "tailscale" ? "Tailscale" : "LAN",
      HUB: h.hubName,
      ONLINE: `${termCount} terminal${termCount === 1 ? "" : "s"}`,
      PROJECTS: uniqueProjects,
    });
  }

  console.log(
    renderTable(rows, [
      { header: "HOST", get: (r) => r.HOST },
      { header: "ENDPOINT", get: (r) => r.ENDPOINT },
      { header: "SOURCE", get: (r) => r.SOURCE, dim: true },
      { header: "HUB", get: (r) => r.HUB },
      { header: "ONLINE", get: (r) => r.ONLINE },
      { header: "PROJECTS", get: (r) => r.PROJECTS, dim: true },
    ]),
  );

  console.log("\nTo join a discovered hub:");
  for (const h of hubs) {
    console.log(`  omp-link join ${h.ip} [session-name]`);
  }
}

async function runClean(state) {
  console.log("⚡ Cleaning up omp-link processes, legacy links, and configuration...");
  let killed = 0;
  for (const port of [9900, 9901]) {
    try {
      const out = execSync(`lsof -ti :${port}`, { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).trim();
      if (out) {
        const pids = out.split(/\s+/).filter(Boolean);
        for (const p of pids) {
          const pid = parseInt(p, 10);
          if (pid && pid !== process.pid) {
            try {
              process.kill(pid, "SIGTERM");
              killed++;
              console.log(`  ✓ Sent SIGTERM to PID ${pid} on port ${port}`);
            } catch {}
          }
        }
      }
    } catch {}
  }

  saveHubToConfig(null);
  console.log("  ✓ Cleared cached hub target from config");

  // Remove legacy extension symlinks
  const legacyLinks = [
    join(homedir(), ".omp", "agent", "extensions", "pi-link"),
    join(homedir(), ".pi", "agent", "extensions", "pi-link"),
  ];
  for (const linkPath of legacyLinks) {
    try {
      if (existsSync(linkPath)) {
        rmSync(linkPath, { recursive: true, force: true });
        console.log(`  ✓ Removed legacy extension link: ${linkPath}`);
      }
    } catch {}
  }

  if (killed > 0) {
    console.log(`✓ Successfully cleaned up ${killed} process(es). Ports 9900/9901 are now free.\n`);
  } else {
    console.log("✓ No lingering processes on port 9900/9901. Ready to go.\n");
  }
}

async function runUpdate(state) {
  const repoDir = join(new URL("..", import.meta.url).pathname);
  console.log(`⚡ Checking for updates in ${repoDir}...`);

  const isGit = existsSync(join(repoDir, ".git"));
  if (isGit) {
    try {
      console.log("Fetching latest changes from git...");
      execSync("git pull --rebase --autostash", { cwd: repoDir, stdio: "inherit" });
      console.log("Installing/refreshing dependencies...");
      execSync("npm install --silent", { cwd: repoDir, stdio: "inherit" });
      const setupScript = join(repoDir, "setup.sh");
      if (existsSync(setupScript)) {
        execSync(`bash "${setupScript}"`, { stdio: "inherit" });
      }
      console.log("✓ omp-link successfully updated!\n");
    } catch (err) {
      console.error(`Update failed: ${err.message}`);
      process.exit(1);
    }
  } else {
    console.log("ℹ️  This installation was extracted from a zip/tarball (no .git directory found).");
    console.log("To enable one-command automatic updates, clone directly from git:");
    console.log("  git clone <your-repo-url> ~/.omp-link && ~/.omp-link/setup.sh\n");
    console.log("Alternatively, unzip the new version into this directory and re-run ./setup.sh.");
  }
}

function runConfig(state) {
  const savedHub = loadSavedHub();
  if (state.configAction === "hub") {
    if (state.configValue) {
      if (state.configValue === "clear" || state.configValue === "none" || state.configValue === "reset") {
        saveHubToConfig(null);
        console.log("✓ Cleared saved hub address.");
      } else {
        saveHubToConfig(state.configValue);
        console.log(`✓ Saved default hub: ${state.configValue}`);
      }
      return;
    }
    console.log(`Configured hub: ${savedHub || "(none — running as local hub / auto-discovery)"}`);
    return;
  }

  const net = getQuickNetworkInfo();
  console.log("⚡ Link Configuration:");
  console.log(`  Saved Hub Target : ${savedHub || "(none — running as local hub / auto-discovery)"}`);
  console.log(`  Tailscale IPv4   : ${net.tailscaleIp || "(not detected)"}`);
  console.log(`  Local LAN IPv4   : ${net.lanIp || "(not detected)"}`);
  console.log(`  Default Port     : ${process.env.PI_LINK_PORT || 9900}`);
  console.log("");
  console.log("Commands:");
  console.log("  omp-link config hub <ip>    Set default hub target");
  console.log("  omp-link config hub clear   Clear default hub target");
}

async function runResolve(state) {
  const name = state.resolveName; // already normalized
  const { dir, isCustom } = resolveSessionDir(process.cwd(), resolveAgentDir());
  const matches = await findSessionsByName(name, dir, isCustom, localScope(state));
  if (matches.length === 1) {
    process.stdout.write(matches[0].path);
    return; // exit 0
  }
  if (matches.length > 1) {
    printCandidates(name, matches); // exits 1
  }
  console.error(`No session named "${name}" found${state.global ? "" : " in this cwd"}.`);
  if (!state.global) console.error("Use --global to search other cwds.");
  process.exit(2);
}

function resolveAgentBin() {
  if (process.env.PI_BIN) return process.env.PI_BIN;
  if (process.env.OMP_BIN) return process.env.OMP_BIN;
  const scriptName = process.argv[1] ? process.argv[1].split(/[/\\]/).pop() : "";
  const preferOmp = scriptName && scriptName.includes("omp");

  const commonDirs = [
    join(homedir(), ".local", "bin"),
    join(homedir(), ".bun", "bin"),
    join(homedir(), ".cargo", "bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
  ];

  const searchOrder = preferOmp ? ["omp", "pi"] : ["pi", "omp"];

  for (const bin of searchOrder) {
    try {
      const p = execSync(`which ${bin}`, { stdio: ["ignore", "pipe", "ignore"], encoding: "utf-8" }).trim();
      if (p && existsSync(p)) return p;
    } catch {}

    for (const dir of commonDirs) {
      const candidate = join(dir, bin);
      if (existsSync(candidate)) return candidate;
    }
  }

  return null;
}

async function runLauncher(state) {
  const name = state.launcherName; // already normalized
  const { dir, isCustom } = resolveSessionDir(process.cwd(), resolveAgentDir());
  const matches = await findSessionsByName(name, dir, isCustom, localScope(state));
  if (matches.length > 1) {
    printCandidates(name, matches);
  }

  const piArgs = [];
  if (matches.length === 1) {
    console.error(`Resuming session: ${matches[0].path}`);
    piArgs.push("--session", matches[0].path);
  } else {
    if (!state.global) {
      console.error(`No "${name}" found in this cwd. Use --global to search other cwds.`);
    }
    console.error(`Starting new session: "${name}"`);
  }

  // Ensure extension is loaded if not already installed/symlinked in agent directory
  const repoRoot = join(new URL("..", import.meta.url).pathname);
  const extIndexPath = join(repoRoot, "index.ts");
  const agentDir = resolveAgentDir();
  const linkedExt = join(agentDir, "extensions", "pi-link");
  if (!existsSync(linkedExt) && existsSync(extIndexPath)) {
    piArgs.unshift("--extension", extIndexPath);
  }

  if (state.mode === "hub") {
    const net = getQuickNetworkInfo();
    console.error(`⚡ Hub starting on port ${process.env.PI_LINK_PORT || 9900}`);
    if (net.tailscaleIp) console.error(`   Tailscale : ${net.tailscaleIp}:${process.env.PI_LINK_PORT || 9900}`);
    if (net.lanIp) console.error(`   LAN       : ${net.lanIp}:${process.env.PI_LINK_PORT || 9900}`);
    piArgs.push("--link-hub=local");
    delete process.env.PI_LINK_HUB;
  } else if (state.mode === "join") {
    if (!state.hubTarget) {
      const saved = loadSavedHub();
      let useSaved = false;
      if (saved) {
        try {
          const target = saved.includes(":") ? saved : `${saved}:9900`;
          const res = await fetch(`http://${target}/status`, {
            signal: AbortSignal.timeout(400),
          });
          if (res.ok) useSaved = true;
        } catch {}
      }

      if (useSaved) {
        state.hubTarget = saved;
      } else {
        const port = Number(process.env.PI_LINK_PORT) || 9900;
        console.error("⚡ Searching Tailnet & LAN for active hubs...");
        const { hubs } = await discoverAllHubs(port, 1000);
        if (hubs.length === 1) {
          const h = hubs[0];
          console.error(`✓ Discovered hub "${h.hubName}" on ${h.host} (${h.ip}:${h.port}). Joining...`);
          state.hubTarget = `${h.ip}:${h.port}`;
        } else if (hubs.length > 1) {
          console.error(`Found ${hubs.length} active hubs on your network:`);
          hubs.forEach((h, idx) => {
            console.error(`  [${idx + 1}] ${h.host} (${h.ip}:${h.port}) — hub "${h.hubName}" (${h.source})`);
          });
          console.error("\nSpecify which hub to join:");
          console.error(`  omp-link join ${hubs[0].ip} [session-name]`);
          process.exit(0);
        } else if (saved) {
          console.error(`No live hubs discovered. Retrying configured hub: ${saved}...`);
          state.hubTarget = saved;
        } else {
          console.error("No active hubs found on Tailnet or LAN.\n  Start one with: omp-link hub\n  Or specify an IP: omp-link join <ip>");
          process.exit(1);
        }
      }
    }

    if (state.hubTarget === "lan") {
      console.error(`⚡ Joining hub via LAN auto-discovery...`);
      piArgs.push("--link-hub=none");
    } else if (state.hubTarget === "tailnet" || state.hubTarget === "ts") {
      const port = Number(process.env.PI_LINK_PORT) || 9900;
      console.error("⚡ Searching Tailnet for active hubs...");
      const { hubs } = await discoverTailnetHubs(port, 1000);
      if (hubs.length > 0) {
        const h = hubs[0];
        console.error(`✓ Discovered hub "${h.hubName}" on ${h.host} (${h.ip}:${h.port}). Joining...`);
        if (state.saveHub) {
          saveHubToConfig(`${h.ip}:${h.port}`);
          console.error(`  ✓ Saved hub to config (~/.omp/link.json)`);
        }
        piArgs.push(`--link-hub=${h.ip}:${h.port}`);
        process.env.PI_LINK_HUB = `${h.ip}:${h.port}`;
      } else {
        console.error("No active hubs found on Tailnet.");
        process.exit(1);
      }
    } else {
      console.error(`⚡ Joining hub at ${state.hubTarget}...`);
      if (state.saveHub) {
        saveHubToConfig(state.hubTarget);
        console.error(`  ✓ Saved hub to config (~/.omp/link.json)`);
      }
      piArgs.push(`--link-hub=${state.hubTarget}`);
      process.env.PI_LINK_HUB = state.hubTarget;
    }
  } else {
    const saved = loadSavedHub();
    if (!process.env.PI_LINK_HUB && saved) {
      console.error(`⚡ Using configured hub: ${saved}`);
    }
  }

  piArgs.push("--link", ...state.piPassthrough);

  const agentBin = resolveAgentBin();
  if (!agentBin) {
    console.error(`\n❌ Error: Neither 'omp' nor 'pi' binary was found in your PATH or common directories.`);
    console.error(`\nTo install Oh My Pi (omp):`);
    console.error(`  curl -fsSL https://omp.sh/install | sh`);
    console.error(`  # or via Homebrew: brew install can1357/tap/omp`);
    console.error(`  # or via Bun:      bun install -g @oh-my-pi/pi-coding-agent\n`);
    console.error(`If omp is installed at a custom location, specify it with:`);
    console.error(`  export OMP_BIN=/path/to/omp\n`);
    process.exit(1);
  }
  const isWin = process.platform === "win32";
  const cmd = isWin ? "cmd.exe" : agentBin;
  const cmdArgs = isWin ? ["/d", "/c", agentBin, ...piArgs] : piArgs;

  // PI_LINK_NAME is the internal handoff to the pi-link extension on the Pi side.
  // The extension consumes and deletes it on startup; never expose this as a public API.
  const child = spawn(cmd, cmdArgs, {
    stdio: "inherit",
    env: { ...process.env, PI_LINK_NAME: name },
  });
  child.once("exit", (code, signal) => {
    if (code !== null) process.exit(code);
    process.exit(signal === "SIGINT" ? 130 : 1);
  });
  child.once("error", (err) => {
    console.error(`Failed to start ${agentBin}: ${err.message}`);
    process.exit(1);
  });
}
