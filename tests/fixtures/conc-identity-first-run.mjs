// Concurrency fixture: several terminals reach `getOrCreateDeviceIdentity()` on a state
// directory that does not have an identity yet.
//
// `generateDeviceCertificate()` shells out to openssl with `-keyout`/`-out` pointing straight at
// the final paths, so two processes creating an identity at the same moment write the same two
// files. The parent checks what the pair on disk is worth afterwards.
//
// Slots keep the processes in lockstep: every process starts slot `i` at the same wall-clock
// instant, so one spawn wave probes the window `i` times instead of once.
//
// stdout protocol:
//   ARMED
//   SLOT:<i>:<principalId>
//   DONE

import * as fs from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { getOrCreateDeviceIdentity } from "../../src/identity.js";
import { waitForBarrier } from "./conc-barrier.mjs";

const root = process.env.OMP_LINK_TEST_DIR;
const barrierFile = process.env.OMP_LINK_BARRIER_FILE;
const slots = Number(process.env.OMP_LINK_SLOTS || 8);
const slotMs = Number(process.env.OMP_LINK_SLOT_MS || 120);

if (!root) {
  console.log("FIXTURE_MISCONFIGURED");
  process.exit(2);
}

console.log("ARMED");
const goAt = await waitForBarrier(barrierFile);

for (let i = 0; i < slots; i++) {
  await delay(Math.max(0, goAt + i * slotMs - Date.now()));
  const dir = path.join(root, `slot-${i}`);
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch {}
  try {
    const identity = getOrCreateDeviceIdentity(dir);
    console.log(`SLOT:${i}:${identity.principalId}`);
  } catch (err) {
    console.log(`SLOT:${i}:THREW:${err instanceof Error ? err.message.slice(0, 80) : String(err)}`);
  }
}

console.log("DONE");
process.exit(0);
