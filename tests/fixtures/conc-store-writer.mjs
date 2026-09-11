// Concurrency fixture: two writers on one `<OMP_DIR>` state store.
//
// `savePairedDevice()` is read-modify-write: `loadPairedDevices()` then one
// `atomicWriteSecureFile()` of the whole map. Each write is atomic; the read-modify-write is not,
// so this is the lost-update window the sprint log flagged (finding 9, §1). `appendAuditLog()` is
// the other shared-file writer and takes the opposite approach (O_APPEND of one line), so both are
// driven from the same fixture and compared under the same load.
//
// Slots keep the writers interleaved: writer A and writer B both perform their i-th write at the
// same wall-clock instant, so the window is probed `count` times per run instead of once.
//
// stdout protocol:
//   ARMED
//   WROTE:<n>       number of records this process claims to have committed
//   DONE

import * as crypto from "node:crypto";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { savePairedDevice, DEFAULT_PERMISSIONS } from "../../src/identity.js";
import { appendAuditLog, setCustomAuditLogPath } from "../../src/audit.js";
import { waitForBarrier } from "./conc-barrier.mjs";

const stateDir = process.env.OMP_LINK_TEST_DIR;
const barrierFile = process.env.OMP_LINK_BARRIER_FILE;
const tag = process.env.OMP_LINK_TAG;
const count = Number(process.env.OMP_LINK_COUNT || 20);
const slotMs = Number(process.env.OMP_LINK_SLOT_MS || 12);
const mode = process.env.OMP_LINK_MODE || "paired";

if (!stateDir || !tag) {
  console.log("FIXTURE_MISCONFIGURED");
  process.exit(2);
}

setCustomAuditLogPath(path.join(stateDir, "audit.log"));

/** Deterministic per (tag, i) so the parent can name every record that should exist. */
function fingerprintFor(seq) {
  const hex = crypto.createHash("sha256").update(`${tag}:${seq}`).digest("hex").toUpperCase();
  return hex.match(/.{2}/g).join(":");
}

console.log("ARMED");
const goAt = await waitForBarrier(barrierFile);

let wrote = 0;
for (let i = 0; i < count; i++) {
  await delay(Math.max(0, goAt + i * slotMs - Date.now()));
  if (mode === "audit") {
    appendAuditLog({
      type: "concurrency_probe",
      timestamp: Date.now(),
      tag,
      seq: i,
      // Long enough that a non-atomic writer would interleave visibly rather than by luck.
      filler: `${tag}-`.repeat(120),
    });
    wrote++;
    continue;
  }
  savePairedDevice(
    {
      principalId: `ed25519-sha256:${fingerprintFor(i)}`,
      fingerprint: fingerprintFor(i),
      certPem: `-----BEGIN CERTIFICATE-----\n${tag}-${i}\n-----END CERTIFICATE-----\n`,
      deviceName: `${tag}-${i}`,
      permissions: DEFAULT_PERMISSIONS,
      pairedAt: Date.now(),
      lastSeen: Date.now(),
    },
    stateDir,
  );
  wrote++;
}

console.log(`WROTE:${wrote}`);
console.log("DONE");
process.exit(0);
