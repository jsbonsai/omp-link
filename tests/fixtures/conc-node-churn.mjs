// Concurrency fixture: a terminal that starts and stops, repeatedly, on a shared OMP_DIR.
//
// Constructing a `LinkNode` constructs a `TransferReceiver`, which runs `cleanupOrphanedParts()`
// and `purgeQuarantineOlderThan()` against the inbox every other terminal on this machine shares.
// That is the R5 loss path: it needed nothing more than opening a second terminal.
//
// stdout protocol:
//   ROUND:<i>
//   DONE

import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { LinkNode } from "../../src/link-node.js";
import { setCustomAuditLogPath } from "../../src/audit.js";

const stateDir = process.env.OMP_LINK_TEST_DIR;
const rounds = Number(process.env.OMP_LINK_ROUNDS || 4);

if (!stateDir) {
  console.log("FIXTURE_MISCONFIGURED");
  process.exit(2);
}

setCustomAuditLogPath(path.join(stateDir, "audit.log"));

for (let i = 0; i < rounds; i++) {
  const node = new LinkNode({
    port: 0,
    bindHost: "127.0.0.1",
    networkMode: "loopback",
    customOmpDir: stateDir,
    terminalName: `churn-${i}`,
    sessionId: "churn",
  });
  await node.stop();
  console.log(`ROUND:${i}`);
  await delay(60);
}

console.log("DONE");
process.exit(0);
