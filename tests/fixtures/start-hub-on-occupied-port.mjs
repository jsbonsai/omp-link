// R1 fixture: hosting on a port already taken must be a rejected promise, never a dead process.
//
// `ws` forwards the underlying HTTPS server's "error" to the WebSocketServer, and an unhandled
// wss "error" terminates the process on a later tick. Neither a try/catch around listen() nor
// the promise executor can observe that, so this runs as its own process and reports its own
// exit code. Deliberately installs NO uncaughtException handler: swallowing the crash here
// would hide exactly the defect under test.

import path from "node:path";
import { LinkNode } from "../../src/link-node.js";
import { setCustomAuditLogPath } from "../../src/audit.js";

const stateDir = process.env.OMP_LINK_TEST_DIR;
const port = Number(process.env.OMP_LINK_TEST_PORT);

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
  terminalName: "crash-probe",
  sessionId: "crash-isolation",
});

let outcome;
try {
  await node.startHub();
  // The port was supposed to be held by the parent: a successful start means the scenario
  // never happened, which must not be reported as a pass.
  outcome = `STARTED:${node.port}`;
} catch (err) {
  outcome = `REJECTED:${err?.code || err?.message || "UNKNOWN"}`;
}
console.log(outcome);
console.log(`ROLE_AFTER_REJECT:${node.role}`);

// The fatal wss "error" re-emit lands on a later tick, so surviving the await proves nothing.
// Idle here first; if the process dies, SURVIVED never reaches stdout.
await new Promise((resolve) => setTimeout(resolve, 300));
console.log("SURVIVED");

// Still usable afterwards: the failed attempt must not have left half-open servers or a
// stale role behind. Retry on an ephemeral port.
node.port = 0;
try {
  await node.startHub();
  console.log(`RESTARTED:${node.role}:${node.port > 0}`);
} catch (err) {
  console.log(`RESTART_FAILED:${err?.code || err?.message || "UNKNOWN"}`);
}
await node.stop();
process.exit(0);
