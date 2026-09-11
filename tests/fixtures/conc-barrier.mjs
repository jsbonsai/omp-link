// Shared start barrier for the concurrency fixtures.
//
// A wall-clock deadline handed down at spawn time is not a barrier: `node --import tsx` needs
// several hundred milliseconds to boot, that cost varies with how many processes are starting at
// once, and a fixture that arrives late turns the race into a sequence and the test into a
// vacuous pass. So the parent writes the barrier file only after every child has reported that it
// is armed, and the children spin on it. `waitForBarrier` returns the barrier instant the parent
// recorded, which the slot-scheduled fixtures use as a common clock origin.

import * as fs from "node:fs";
import { setTimeout as delay } from "node:timers/promises";

/**
 * Blocks until `barrierFile` appears, then returns the epoch-ms instant written inside it (or the
 * local arrival time for an empty file). A missing path means "no barrier": start now.
 */
export async function waitForBarrier(barrierFile, timeoutMs = 20_000) {
  if (!barrierFile) return Date.now();
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const raw = fs.readFileSync(barrierFile, "utf8").trim();
      const at = Number(raw);
      return Number.isFinite(at) && at > 0 ? at : Date.now();
    } catch {}
    if (Date.now() > deadline) {
      console.log("BARRIER_TIMEOUT");
      process.exit(9);
    }
    await delay(5);
  }
}
