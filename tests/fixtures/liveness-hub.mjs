// Liveness fixture: a real hub that holds until the parent kills or freezes it.
//
// The interesting failure is SIGSTOP, not SIGKILL: a frozen hub leaves every client socket
// established, so a client with no keepalive keeps reporting a room it can no longer reach and
// never fires `onHubDisconnected` — which is the callback local hub succession hangs off.
//
// stdout protocol:
//   PORT:<port>
//   FP:<spki fingerprint>
//   READY
//   (then holds until the parent signals)

import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { LinkNode } from "../../src/link-node.js";
import { setCustomAuditLogPath } from "../../src/audit.js";

const stateDir = process.env.OMP_LINK_TEST_DIR;
const holdMs = Number(process.env.OMP_LINK_HOLD_MS || 30_000);

if (!stateDir) {
  console.log("FIXTURE_MISCONFIGURED");
  process.exit(2);
}

setCustomAuditLogPath(path.join(stateDir, "audit.log"));

const node = new LinkNode({
  port: 0,
  bindHost: "127.0.0.1",
  networkMode: "loopback",
  customOmpDir: stateDir,
  terminalName: "liveness-hub",
  sessionId: "liveness",
  workspaceRoot: stateDir,
});

await node.startHub();
console.log(`PORT:${node.port}`);
console.log(`FP:${node.identity.fingerprint}`);
console.log("READY");

await delay(holdMs);
console.log("NOT_SIGNALLED");
process.exit(4);
