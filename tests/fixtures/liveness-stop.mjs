// Liveness fixture: does a stopped node let its process die?
//
// A liveness sweeper is an interval, and an interval that outlives `stop()` keeps the whole
// agent process alive. The symptom is not a failing assertion anywhere — it is a terminal that
// hangs on quit, which no in-process test can observe because the harness holding the leak is
// the thing that would have to exit. So: start a real hub, join it with a real client, stop
// both, and then simply stop calling anything. A clean node exits here on its own.
//
// stdout protocol:
//   JOINED:<state>
//   TIMERS:<count of live Timeout handles after stop>
//   HANDLES:<comma-separated remaining resource kinds>
//   STOPPED
//   (no process.exit(): exiting is the assertion)

import path from "node:path";

import { LinkNode } from "../../src/link-node.js";
import { setCustomAuditLogPath } from "../../src/audit.js";

const hubDir = process.env.OMP_LINK_HUB_DIR;
const clientDir = process.env.OMP_LINK_CLIENT_DIR;

if (!hubDir || !clientDir) {
  console.log("FIXTURE_MISCONFIGURED");
  process.exit(2);
}

setCustomAuditLogPath(path.join(hubDir, "audit.log"));

const hub = new LinkNode({
  port: 0,
  bindHost: "127.0.0.1",
  networkMode: "loopback",
  customOmpDir: hubDir,
  terminalName: "stop-hub",
  sessionId: "liveness",
  workspaceRoot: hubDir,
});
const client = new LinkNode({
  port: 0,
  bindHost: "127.0.0.1",
  networkMode: "loopback",
  customOmpDir: clientDir,
  terminalName: "stop-client",
  sessionId: "liveness",
  workspaceRoot: clientDir,
});

await hub.startHub();
const outcome = await client.connectToHub(`wss://127.0.0.1:${hub.port}`, hub.identity.fingerprint);
console.log(`JOINED:${outcome.state}`);

await client.stop();
await hub.stop();

const remaining = process.getActiveResourcesInfo();
console.log(`TIMERS:${remaining.filter((r) => r === "Timeout" || r === "Immediate").length}`);
console.log(`HANDLES:${[...new Set(remaining)].sort().join(",")}`);
console.log("STOPPED");
