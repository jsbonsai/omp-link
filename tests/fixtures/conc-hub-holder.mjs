// Concurrency fixture: hold the real hub port until the parent kills this process.
//
// A crashed terminal is the normal case, not the exception: a closed laptop, an OOM kill, a
// `kill -9` on a stuck agent. What must survive it is the ability to host again immediately, and
// `omp-link cleanup` must not invent leftovers out of the debris — an in-flight staging directory
// belonging to a pid that died seconds ago is not yet reclaimable (invariant 13), and a port with
// nothing listening is not something to reclaim at all.
//
// stdout protocol:
//   READY:<port>
//   STAGED:<partPath>
//   (then holds until SIGKILL)

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { LinkNode } from "../../src/link-node.js";
import { CHUNK_SIZE } from "../../src/transfer-receiver.js";
import { setCustomAuditLogPath } from "../../src/audit.js";

const stateDir = process.env.OMP_LINK_TEST_DIR;
const port = Number(process.env.OMP_LINK_TEST_PORT);
const holdMs = Number(process.env.OMP_LINK_HOLD_MS || 20_000);

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
  terminalName: "crash-victim",
  sessionId: "port-reuse",
});

await node.startHub();
console.log(`READY:${node.port}`);

// An accepted-but-unfinished transfer, so the crash leaves real staging debris behind.
const sizeBytes = CHUNK_SIZE + 512;
const body = Buffer.alloc(sizeBytes, 0x41);
const offer = {
  type: "file_offer",
  version: 5,
  transferId: `crash-${process.pid}`,
  from: "sender",
  originPrincipalId: "ed25519-sha256:CONC_CRASH_SENDER",
  filename: "interrupted.bin",
  sizeBytes,
  totalChunks: 2,
  sha256: crypto.createHash("sha256").update(body).digest("hex"),
  ts: Date.now(),
};
const accepted = node.transferReceiver.handleOffer(offer);
if (!accepted.ok) {
  console.log(`OFFER_REFUSED:${accepted.error}`);
  process.exit(3);
}
node.transferReceiver.handleChunk({
  type: "file_chunk",
  version: 5,
  transferId: offer.transferId,
  from: "sender",
  originPrincipalId: offer.originPrincipalId,
  chunkIndex: 0,
  totalChunks: 2,
  data: body.subarray(0, CHUNK_SIZE).toString("base64"),
  ts: Date.now(),
});

const staged = [];
const walk = (dir) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (entry.isFile() && entry.name.endsWith(".part")) staged.push(full);
  }
};
walk(path.join(stateDir, "inbox"));
console.log(`STAGED:${staged.join(",")}`);

await delay(holdMs);
console.log("NOT_KILLED");
process.exit(4);
