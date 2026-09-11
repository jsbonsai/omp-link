// Liveness fixture: a real client terminal that joins a hub and then holds.
//
// The parent decides how this process dies. SIGKILL is the crashed agent (the socket resets and
// the hub learns at the transport layer); SIGSTOP is the frozen agent — the kernel keeps ACKing
// and the connection stays established, so nothing below the application can tell it apart from
// an idle peer. Only an unanswered WebSocket ping can, which is what the hub must do.
//
// stdout protocol:
//   JOINED:<agentInstanceId>
//   (then holds until the parent signals)

import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { LinkNode } from "../../src/link-node.js";
import { setCustomAuditLogPath } from "../../src/audit.js";

const stateDir = process.env.OMP_LINK_TEST_DIR;
const hubUrl = process.env.OMP_LINK_HUB_URL;
const hubFingerprint = process.env.OMP_LINK_HUB_FP;
const terminalName = process.env.OMP_LINK_NAME || "liveness-peer";
const holdMs = Number(process.env.OMP_LINK_HOLD_MS || 30_000);

if (!stateDir || !hubUrl || !hubFingerprint) {
  console.log("FIXTURE_MISCONFIGURED");
  process.exit(2);
}

setCustomAuditLogPath(path.join(stateDir, "audit.log"));

const node = new LinkNode({
  port: 0,
  bindHost: "127.0.0.1",
  networkMode: "loopback",
  customOmpDir: stateDir,
  terminalName,
  sessionId: "liveness",
  workspaceRoot: stateDir,
});

const outcome = await node.connectToHub(hubUrl, hubFingerprint);
if (outcome.state !== "authenticated") {
  console.log(`NOT_ADMITTED:${outcome.state}`);
  process.exit(3);
}

console.log(`JOINED:${node.agentInstanceId}`);

await delay(holdMs);
console.log("NOT_SIGNALLED");
process.exit(4);
