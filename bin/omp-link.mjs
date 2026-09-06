#!/usr/bin/env node

// omp-link CLI — multi-machine coordination mesh for Oh My Pi and Pi
// All link networking and sessions are controlled via /slash commands inside OMP/Pi:
//   /link                   View link status, session ID, PIN, and online peers
//   /link-start [id] [pin]  Host a new link session
//   /link-join [id|ip]      Discover and join an active session
//   /link-leave             Leave the current link session
//   /link-network <ts|lan>  Switch network mode (Tailscale vs LAN)

import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { join } from "path";
import { homedir, networkInterfaces, hostname } from "os";
import { spawn, execSync } from "child_process";
import dgram from "dgram";

const VERSION = "0.5.0";
const rawArgs = process.argv.slice(2);
const first = rawArgs[0];

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

function getQuickNetworkInfo() {
  const nets = networkInterfaces();
  let tailscaleIp = null;
  const lanIps = [];
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
        }
      }
    }
  }
  return { hostname: hostname(), tailscaleIp, lanIps };
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
    const stdout = execSync(`"${bin}" status --json`, {
      encoding: "utf-8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const status = JSON.parse(stdout);
    const peers = [];
    if (status.Self) {
      const ipv4 = status.Self.TailscaleIPs?.find((ip) => ip.startsWith("100."));
      if (ipv4) {
        peers.push({
          host: status.Self.HostName || "localhost",
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

async function runFind() {
  console.log("⚡ Probing for active OMP Link sessions on Tailscale & LAN...\n");
  const peers = getTailnetPeers();
  const foundSessions = [];

  // Check Tailscale peers
  if (peers.length > 0) {
    const tsResults = await Promise.all(
      peers.map(async (p) => {
        try {
          const res = await fetch(`http://${p.ip}:9900/status`, {
            signal: AbortSignal.timeout(800),
          });
          if (res.ok) {
            const data = await res.json();
            return { ...data, ip: p.ip, source: "tailscale" };
          }
        } catch {}
        return null;
      }),
    );
    for (const r of tsResults.filter(Boolean)) foundSessions.push(r);
  }

  // Check LAN
  const net = getQuickNetworkInfo();
  try {
    const res = await fetch(`http://127.0.0.1:9900/status`, {
      signal: AbortSignal.timeout(300),
    });
    if (res.ok) {
      const data = await res.json();
      if (!foundSessions.some((s) => s.hubId === data.hubId)) {
        foundSessions.push({ ...data, ip: "127.0.0.1", source: "local" });
      }
    }
  } catch {}

  if (foundSessions.length === 0) {
    console.log("No active sessions discovered.");
    console.log("To start a session, open OMP and type: /link-start [session-name]\n");
    return;
  }

  console.log(`Found ${foundSessions.length} active session(s):\n`);
  for (const s of foundSessions) {
    const terms = (s.terminals || []).map((t) => t.name).join(", ");
    console.log(`  • Session : "${s.sessionId || s.hub}"`);
    console.log(`    Host    : ${s.host} (${s.ip}:9900) [via ${s.source}]`);
    console.log(`    PIN     : ${s.pin || "(none)"}`);
    console.log(`    Peers   : ${s.terminals?.length || 1} online (${terms})`);
    console.log(`    Join In : /link-join ${s.sessionId || s.ip}\n`);
  }
}

async function runClean() {
  console.log("⚡ Cleaning up omp-link processes and configuration...");
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
              process.kill(pid, "SIGKILL");
              killed++;
              console.log(`  ✓ Terminated PID ${pid} on port ${port}`);
            } catch {}
          }
        }
      }
    } catch {}
  }

  // Clear stale configs
  for (const f of [
    join(homedir(), ".omp", "link.json"),
    join(homedir(), ".pi", "link.json"),
  ]) {
    try {
      if (existsSync(f)) {
        const data = JSON.parse(readFileSync(f, "utf-8"));
        delete data.hub;
        writeFileSync(f, JSON.stringify(data, null, 2) + "\n");
        console.log(`  ✓ Reset cached hub in ${f}`);
      }
    } catch {}
  }

  // Remove legacy extension symlinks
  for (const linkPath of [
    join(homedir(), ".omp", "agent", "extensions", "pi-link"),
    join(homedir(), ".pi", "agent", "extensions", "pi-link"),
  ]) {
    try {
      if (existsSync(linkPath)) {
        rmSync(linkPath, { recursive: true, force: true });
        console.log(`  ✓ Removed legacy extension link: ${linkPath}`);
      }
    } catch {}
  }

  if (killed > 0) {
    console.log(`✓ Ports 9900/9901 released (${killed} process(es) terminated).\n`);
  } else {
    console.log("✓ No lingering processes found on ports 9900/9901.\n");
  }
}

async function runUpdate() {
  const repoDir = join(new URL("..", import.meta.url).pathname);
  console.log(`⚡ Updating omp-link in ${repoDir}...`);
  if (existsSync(join(repoDir, ".git"))) {
    try {
      execSync("git pull --rebase --autostash", { cwd: repoDir, stdio: "inherit" });
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
    console.log("No .git folder found. Extract new version and run ./setup.sh");
  }
}

function printHelp() {
  console.log(`omp-link v${VERSION} — Multi-machine coordination mesh for Oh My Pi & Pi

Usage:
  omp-link [omp-options...]    Launch OMP (with omp-link extension auto-loaded)

All session coordination is handled seamlessly via slash commands inside your chat:
  /link                   View current session status, peers, network, and PIN
  /link-start [id] [pin]  Host a new link session (Tailscale or LAN)
  /link-join [id|ip]      Discover and join an active session
  /link-leave             Leave the current link session
  /link-network <ts|lan>  Switch network mode between Tailscale and LAN
  /link-pin [pin]         View or update session PIN

Maintenance commands:
  omp-link clean          Release ports 9900/9901 and reset stale configs
  omp-link update         Pull latest version from GitHub and refresh extensions
  omp-link find           Scan network for live link sessions
  omp-link --version      Print version
`);
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

if (first === "clean" || first === "reset" || first === "kill") {
  await runClean();
  process.exit(0);
}

if (first === "update" || first === "upgrade") {
  await runUpdate();
  process.exit(0);
}

if (first === "find" || first === "discover" || first === "search") {
  await runFind();
  process.exit(0);
}

if (first === "--help" || first === "-h" || first === "help") {
  printHelp();
  process.exit(0);
}

if (first === "--version" || first === "-v") {
  console.log(VERSION);
  process.exit(0);
}

// Default: launch OMP directly!
const agentBin = resolveAgentBin();
if (!agentBin) {
  console.error(`❌ Error: Neither 'omp' nor 'pi' CLI binary was found.`);
  console.error(`Install Oh My Pi via: curl -fsSL https://omp.sh/install | sh`);
  process.exit(1);
}

// Forward directly to OMP with all user arguments
const child = spawn(agentBin, rawArgs, { stdio: "inherit" });
child.on("exit", (code) => process.exit(code ?? 0));
