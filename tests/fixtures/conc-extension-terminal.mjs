// Concurrency fixture: one real sibling terminal, driven through the extension surface.
//
// Local hub succession lives in `index.ts` (`attemptLocalSuccession`), not in `LinkNode`, and it
// is hardcoded to `127.0.0.1:9900` because that is what remote peers pinned. Nothing about it can
// be observed in-process: the invariant is "exactly one of N surviving terminals ends up hosting",
// which needs N real processes sharing one OMP_DIR (one device certificate = sibling admission).
//
// The extension is loaded with a minimal ExtensionAPI double. The `link_status` tool is the
// oracle: it is the structured state report the extension itself publishes, so this fixture never
// has to guess a role from rendered text.
//
// stdout protocol (one token per line):
//   ARMED                          registered and waiting on the shared start barrier
//   HOSTING | JOINED               reached its initial role
//   HUB_LOST:<cycle>               the hub this terminal was joined to went away
//   FINAL:<cycle>:<role>:<peers>   state after succession cycle <cycle> settled
//   PEERS:<cycle>:<n>:<names>      roster size, printed on change
//   RELEASED | TIMEOUT:<state>:<role>:<cycle>

import { existsSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import loadLinkExtension from "../../index.js";
import { waitForBarrier } from "./conc-barrier.mjs";

const role = process.env.OMP_LINK_ROLE;
const barrierFile = process.env.OMP_LINK_BARRIER_FILE;
const name = process.env.OMP_LINK_NAME || "terminal";
const roomLabel = process.env.OMP_LINK_ROOM || "race-room";
const settleMs = Number(process.env.OMP_LINK_SETTLE_MS || 9000);
/** Written by the parent once it has observed the whole round; until then survivors stay up. */
const releaseFile = process.env.OMP_LINK_RELEASE_FILE;

if (!process.env.OMP_DIR || (role !== "host" && role !== "join")) {
  console.log("FIXTURE_MISCONFIGURED");
  process.exit(2);
}

const commands = new Map();
const tools = new Map();

/** Just enough ExtensionAPI for the lifecycle paths: registration, flags, and outbound messages. */
const pi = {
  registerFlag() {},
  getFlag(flag) {
    return flag === "link-name" ? name : undefined;
  },
  registerCommand(verb, spec) {
    commands.set(verb, spec.handler);
  },
  registerTool(spec) {
    tools.set(spec.name, spec);
  },
  registerMessageRenderer() {},
  sendMessage(msg) {
    // Succession announces itself here; keep it visible but out of the token stream.
    console.log(`# sendMessage ${JSON.stringify(String(msg?.content ?? "")).slice(0, 160)}`);
  },
  on() {},
};

const ctx = {
  ui: {
    notify(message) {
      console.log(`# notify ${JSON.stringify(String(message).split("\n")[0]).slice(0, 160)}`);
    },
    setStatus() {},
    async confirm() {
      return true;
    },
  },
};

loadLinkExtension(pi);

const runLink = commands.get("link");
const status = async () => (await tools.get("link_status").execute()).details;

console.log("ARMED");
await waitForBarrier(barrierFile);

if (role === "host") {
  await runLink(`create ${roomLabel}`, ctx);
  const s = await status();
  if (s.role !== "hub") {
    console.log(`HOST_FAILED:${s.state}:${s.role}`);
    process.exit(3);
  }
  console.log("HOSTING");
  // Held open until the parent kills this process: that kill is the event under test.
  await delay(settleMs);
  console.log("HOST_NOT_KILLED");
  process.exit(4);
}

// A joiner races the host's startup, so a first refusal is expected rather than fatal.
const joinDeadline = Date.now() + 6000;
let joined = false;
while (Date.now() < joinDeadline) {
  await runLink("join 127.0.0.1:9900", ctx);
  if ((await status()).usable) {
    joined = true;
    break;
  }
  await delay(120);
}
if (!joined) {
  console.log("JOIN_FAILED");
  process.exit(5);
}
console.log("JOINED");

// From here this terminal only reports what each succession race did to it. It must NOT exit as
// soon as it settles: a survivor that drops its socket the instant it reconnects makes the new
// hub's roster read empty, which would hide a real routing failure. The parent releases every
// survivor once it has seen the whole run.
//
// The loop is cycle-aware on purpose. Terminals close one at a time in real use, so the parent
// kills each successive winner and the same processes race again with one fewer contender.
const deadline = Date.now() + settleMs;
let cycle = 0;
let connected = true;
let lastPeers = -1;
while (Date.now() < deadline) {
  const s = await status();
  if (connected && !s.usable) {
    connected = false;
    lastPeers = -1;
    console.log(`HUB_LOST:${cycle}`);
  } else if (!connected && s.usable) {
    connected = true;
    cycle++;
    console.log(`FINAL:${cycle}:${s.role}:${s.peers.length}`);
  }
  if (connected && s.peers.length !== lastPeers) {
    lastPeers = s.peers.length;
    console.log(`PEERS:${cycle}:${lastPeers}:${s.peers.map((p) => p.name).join(",")}`);
  }
  if (releaseFile && existsSync(releaseFile)) {
    console.log("RELEASED");
    process.exit(0);
  }
  await delay(100);
}

const last = await status();
console.log(`TIMEOUT:${last.state}:${last.role}:cycle${cycle}`);
process.exit(6);
