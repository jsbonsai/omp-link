// Concurrency fixture: N processes call startHub() on ONE port at the same instant.
//
// `EADDRINUSE` is the documented, advertised path (README: a second terminal joins the sibling's
// hub instead of starting a second room), and it is the one path that cannot be exercised in
// process: the winner has to be a different process from the losers. Every process here shares
// one OMP_DIR, i.e. one device certificate, which is what makes the losers siblings of the winner
// and lets them join without pairing.
//
// stdout protocol:
//   ARMED                 registered on the start barrier; the parent releases it when all are
//   WON:<port> | LOST:<code>
//   SURVIVED              still alive one tick after the failed listen settled
//   JOINED:<state>:<authenticated>
//   PEERS:<n>             winner's roster size, printed on change
//   RELEASED

import { existsSync } from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { LinkNode } from "../../src/link-node.js";
import { setCustomAuditLogPath } from "../../src/audit.js";
import { waitForBarrier } from "./conc-barrier.mjs";

const stateDir = process.env.OMP_LINK_TEST_DIR;
const port = Number(process.env.OMP_LINK_TEST_PORT);
const barrierFile = process.env.OMP_LINK_BARRIER_FILE;
const name = process.env.OMP_LINK_NAME || "racer";
const releaseFile = process.env.OMP_LINK_RELEASE_FILE;
const settleMs = Number(process.env.OMP_LINK_SETTLE_MS || 8000);

if (!stateDir || !Number.isInteger(port) || port <= 0) {
  console.log("FIXTURE_MISCONFIGURED");
  process.exit(2);
}

setCustomAuditLogPath(path.join(stateDir, "audit.log"));

const node = new LinkNode({
  port,
  bindHost: "127.0.0.1",
  networkMode: "loopback",
  customOmpDir: stateDir,
  terminalName: name,
  sessionId: "start-race",
});

console.log("ARMED");
await waitForBarrier(barrierFile);

let won = false;
try {
  await node.startHub();
  won = true;
  console.log(`WON:${node.port}`);
} catch (err) {
  console.log(`LOST:${err?.code || err?.message || "UNKNOWN"}`);
}

// A fatal wss "error" re-emit lands on a later tick, so surviving the await proves nothing.
await delay(250);
console.log("SURVIVED");

if (!won) {
  // The loser must still be a usable terminal: it joins the process that won the port.
  try {
    const outcome = await node.connectToHub(`wss://127.0.0.1:${port}`, node.identity.fingerprint);
    console.log(`JOINED:${outcome.state}:${node.isAuthenticated}`);
  } catch (err) {
    console.log(`JOIN_FAILED:${err instanceof Error ? err.message : String(err)}`);
  }
}

// Hold the whole set together until the parent has observed the round: a loser that exits at once
// would make the winner's roster read empty for reasons that have nothing to do with the race.
const deadline = Date.now() + settleMs;
let lastPeers = -1;
while (Date.now() < deadline) {
  if (won) {
    const peers = node.getConnectedTerminalsList().length - 1;
    if (peers !== lastPeers) {
      lastPeers = peers;
      console.log(`PEERS:${peers}`);
    }
  }
  if (releaseFile && existsSync(releaseFile)) {
    console.log("RELEASED");
    await node.stop();
    process.exit(0);
  }
  await delay(80);
}

console.log("NOT_RELEASED");
await node.stop();
process.exit(7);
