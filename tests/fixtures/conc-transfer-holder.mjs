// Concurrency fixture: hold a real in-flight transfer open while other processes start up.
//
// Invariant 13: a `.part` is reclaimable only when the owner pid is dead AND the file is idle past
// ABSOLUTE_TIMEOUT_MS. Both halves have to be tested separately, or the idle rule alone would make
// the test pass with the pid rule deleted. So the staging file's mtime is deliberately backdated
// well past the absolute timeout before the churn begins: from that point the ONLY thing standing
// between this in-flight transfer and every other terminal's `cleanupOrphanedParts()` is the
// liveness of this pid.
//
// A silent loss is the specific hazard: writes continue into an unlinked inode, byte count and
// running sha256 both still pass, and only the finalize inode re-check can tell.
//
// stdout protocol:
//   STAGED:<partPath>
//   BACKDATED:<mtimeIsoString>
//   RESUMED
//   RESULT:<ok>:<complete>:<shaMatches>
//   FINAL:<finalPath>:<sizeOnDisk>

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { TransferReceiver, CHUNK_SIZE, ABSOLUTE_TIMEOUT_MS } from "../../src/transfer-receiver.js";

const stateDir = process.env.OMP_LINK_TEST_DIR;
const readyFile = process.env.OMP_LINK_READY_FILE;
const goFile = process.env.OMP_LINK_GO_FILE;

if (!stateDir || !readyFile || !goFile) {
  console.log("FIXTURE_MISCONFIGURED");
  process.exit(2);
}

const receiver = new TransferReceiver(stateDir);

const totalChunks = 3;
const sizeBytes = CHUNK_SIZE * 2 + 1234;
const payload = crypto.createHash("sha512").update("omp-link-concurrency").digest();
const body = Buffer.alloc(sizeBytes);
for (let i = 0; i < sizeBytes; i += payload.length) payload.copy(body, i);
const expectedSha = crypto.createHash("sha256").update(body).digest("hex");

const transferId = `conc-${process.pid}`;
const offer = {
  type: "file_offer",
  version: 5,
  transferId,
  from: "sender",
  originPrincipalId: "ed25519-sha256:CONC_TRANSFER_SENDER",
  filename: "held-transfer.bin",
  sizeBytes,
  totalChunks,
  sha256: expectedSha,
  ts: Date.now(),
};

const accepted = receiver.handleOffer(offer);
if (!accepted.ok) {
  console.log(`OFFER_REFUSED:${accepted.error}`);
  process.exit(3);
}

function chunkAt(index) {
  const start = index * CHUNK_SIZE;
  return {
    type: "file_chunk",
    version: 5,
    transferId,
    from: "sender",
    originPrincipalId: "ed25519-sha256:CONC_TRANSFER_SENDER",
    chunkIndex: index,
    totalChunks,
    data: body.subarray(start, Math.min(start + CHUNK_SIZE, sizeBytes)).toString("base64"),
    ts: Date.now(),
  };
}

const first = receiver.handleChunk(chunkAt(0));
if (!first.ok) {
  console.log(`CHUNK_REFUSED:${first.error}`);
  process.exit(4);
}

/** The receiver owns the staging path privately; on disk it is the only `.part` this pid owns. */
function findOwnPart() {
  const root = path.join(stateDir, "inbox");
  const found = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith(".part") && dir.includes(`rx-${process.pid}-`)) found.push(full);
    }
  };
  walk(root);
  return found;
}

const parts = findOwnPart();
if (parts.length !== 1) {
  console.log(`STAGING_NOT_FOUND:${parts.length}`);
  process.exit(5);
}
const partPath = parts[0];
console.log(`STAGED:${partPath}`);

const staleTime = new Date(Date.now() - ABSOLUTE_TIMEOUT_MS * 4);
fs.utimesSync(partPath, staleTime, staleTime);
console.log(`BACKDATED:${staleTime.toISOString()}`);

fs.writeFileSync(readyFile, "ready");

const deadline = Date.now() + 15_000;
while (!fs.existsSync(goFile)) {
  if (Date.now() > deadline) {
    console.log("GO_TIMEOUT");
    process.exit(6);
  }
  await delay(50);
}
console.log("RESUMED");

let last;
for (let i = 1; i < totalChunks; i++) {
  last = receiver.handleChunk(chunkAt(i));
  if (!last.ok) break;
}

const shaMatches = last?.sha256 === expectedSha;
console.log(`RESULT:${last?.ok}:${last?.complete}:${shaMatches}${last?.error ? `:${last.error}` : ""}`);
if (last?.finalPath) {
  let size = -1;
  try {
    size = fs.statSync(last.finalPath).size;
  } catch {}
  console.log(`FINAL:${last.finalPath}:${size}`);
}
console.log(`EXPECTED_SHA:${expectedSha}`);
process.exit(0);
