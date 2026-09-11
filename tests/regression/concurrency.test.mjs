import { test, describe, before, after } from "node:test";
import assert from "node:assert";
import { execFileSync, spawn } from "node:child_process";
import * as crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { FIXTURE_DIR, REPO_ROOT } from "../helpers/child.mjs";
import { LinkNode } from "../../src/link-node.js";
import { setCustomAuditLogPath } from "../../src/audit.js";
import { revokeAllGrants } from "../../src/authorization.js";
import { FULL_PERMISSIONS, getOrCreateDeviceIdentity, loadPairedDevices } from "../../src/identity.js";
import { ABSOLUTE_TIMEOUT_MS, CHUNK_SIZE } from "../../src/transfer-receiver.js";

// Concurrency regressions (C-numbered, distinct from the R-numbered single-process findings).
//
// Everything this tool actually does is multi-process: several terminals on one machine share one
// `OMP_DIR`, one device certificate, one `audit.log`, one inbox, and one hub port. None of that is
// reachable from a single-process test, and the failures it produces are the expensive kind —
// lost pairings, a bricked state directory, a silently misrouted message, two terminals dueling
// for a port. Each test here spawns real processes and asserts an invariant that must hold at any
// interleaving, never a snapshot of the timing this machine happened to produce.
//
// Four of these reproduced live defects when they were written — C3 (a pairing silently lost by
// two terminals approving at once), C7 (two devices answering to one display name, so direct
// messages went to the wrong one), C8 (one device ending up with several identities, or with a
// certificate that did not match its own private key) and C9 (a state directory permanently
// unable to hold an identity after a crash in the claim window). All four were fixed while this
// file was being written, each one after the test reproduced it. Every test asserts the property
// rather than the fix, so it keeps holding the line if the implementation changes again.
//
// A scenario whose timing is randomised by design (C2's succession delay) is made deterministic
// by repetition inside the test, not by pinning an order: the race is re-run and the invariant is
// asserted every cycle.

/** The one port the tool is not free to choose: `attemptLocalSuccession` and `omp-link cleanup` hardcode it. */
const HUB_PORT = 9900;

const live = new Set();

function startFixture(name, env = {}) {
  const child = spawn(process.execPath, ["--import", "tsx", path.join(FIXTURE_DIR, name)], {
    cwd: REPO_ROOT,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const proc = {
    name: env.OMP_LINK_NAME || name,
    child,
    stdout: "",
    stderr: "",
    exit: null,
    lines: () => proc.stdout.split("\n").map((l) => l.trim()).filter(Boolean),
    has: (needle) => proc.stdout.includes(needle),
    find: (prefix) => proc.lines().find((l) => l.startsWith(prefix)) || null,
    kill: (signal = "SIGKILL") => {
      try {
        child.kill(signal);
      } catch {}
    },
    describe: () => `${proc.name}: exit=${JSON.stringify(proc.exit)} stdout=${JSON.stringify(proc.stdout)} stderr=${JSON.stringify(proc.stderr.slice(0, 400))}`,
  };
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (d) => { proc.stdout += d; });
  child.stderr.on("data", (d) => { proc.stderr += d; });
  proc.closed = new Promise((resolve) => {
    child.on("close", (code, signal) => {
      proc.exit = { code, signal };
      live.delete(proc);
      resolve(proc.exit);
    });
  });
  live.add(proc);
  return proc;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitUntil(predicate, timeoutMs, pollMs = 25) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return true;
    if (Date.now() >= deadline) return false;
    await sleep(pollMs);
  }
}

/** Releases the start barrier only once every child says it is armed, so the race is real. */
async function releaseBarrier(procs, barrierFile, timeoutMs = 20_000) {
  const armed = await waitUntil(() => procs.every((p) => p.has("ARMED")), timeoutMs);
  assert.ok(armed, `Not every process reached the barrier: ${procs.map((p) => p.describe()).join(" | ")}`);
  fs.writeFileSync(barrierFile, String(Date.now()));
}

/** A port the kernel says is free right now. Never a hardcoded 199xx. */
function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

/** True when something already holds the hardcoded hub port — this machine's real hub, usually. */
function portBusy(port) {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once("error", () => resolve(true));
    probe.once("listening", () => probe.close(() => resolve(false)));
    probe.listen(port, "127.0.0.1");
  });
}

function readAudit(dir) {
  const file = path.join(dir, "audit.log");
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

let rootDir;

/** A fresh state directory whose device identity already exists: creating it is C8's subject. */
function newStateDir(label) {
  const dir = fs.mkdtempSync(path.join(rootDir, `${label}-`));
  getOrCreateDeviceIdentity(dir);
  return dir;
}

/** The pid of a process that has already exited: a reclaim rule keyed on liveness needs one. */
function deadPid() {
  return Number(execFileSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { encoding: "utf8" }));
}

/**
 * A genuinely abandoned staging directory: dead owner, idle past the absolute transfer deadline.
 * Planted so the reclaim tests can prove the sweep still has teeth — a cleanup that protects a
 * live transfer by never looking at the inbox at all would otherwise pass every assertion.
 */
function plantOrphanStaging(stateDir) {
  const pid = deadPid();
  const staging = path.join(stateDir, "inbox", "default", `rx-${pid}-deadbeef-ORPHAN`);
  fs.mkdirSync(staging, { recursive: true, mode: 0o700 });
  const part = path.join(staging, "abandoned.bin.part");
  fs.writeFileSync(part, "partial payload", { mode: 0o600 });
  const when = new Date(Date.now() - ABSOLUTE_TIMEOUT_MS * 4);
  fs.utimesSync(part, when, when);
  fs.utimesSync(staging, when, when);
  return { pid, staging, part };
}

before(() => {
  rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-concurrency-"));
  setCustomAuditLogPath(path.join(rootDir, "parent-audit.log"));
  revokeAllGrants("concurrency suite setup");
});

after(async () => {
  for (const proc of [...live]) proc.kill("SIGKILL");
  await Promise.all([...live].map((p) => p.closed));
  revokeAllGrants("concurrency suite teardown");
  setCustomAuditLogPath(null);
  if (rootDir && fs.existsSync(rootDir)) fs.rmSync(rootDir, { recursive: true, force: true });
});

describe("CONCURRENCY: several real terminals on one machine", () => {
  // ── C1 ────────────────────────────────────────────────────────────────────
  // Two terminals starting at the same moment is the documented zero-config case: the loser is
  // supposed to join the winner's hub. The loss has to be a rejected promise on a live process
  // (R1), and the loser has to remain a usable terminal afterwards — a survivor that cannot join
  // is the same outage as a crash, one level quieter.
  async function runStartRace(contenders) {
    const dir = newStateDir("start-race");
    const port = await freePort();
    const barrier = path.join(dir, "barrier");
    const release = path.join(dir, "release");

    const procs = Array.from({ length: contenders }, (_, i) =>
      startFixture("conc-race-start-hub.mjs", {
        OMP_LINK_TEST_DIR: dir,
        OMP_LINK_TEST_PORT: String(port),
        OMP_LINK_BARRIER_FILE: barrier,
        OMP_LINK_RELEASE_FILE: release,
        OMP_LINK_NAME: `racer-${i}`,
        OMP_LINK_SETTLE_MS: "12000",
      }));

    await releaseBarrier(procs, barrier);

    const settled = await waitUntil(
      () => procs.every((p) => p.has("SURVIVED")) && procs.filter((p) => p.find("LOST:")).every((p) => p.has("JOINED:") || p.has("JOIN_FAILED:")),
      15_000,
    );
    assert.ok(settled, `Race never settled: ${procs.map((p) => p.describe()).join(" | ")}`);

    const winners = procs.filter((p) => p.find("WON:"));
    const losers = procs.filter((p) => p.find("LOST:"));
    const detail = procs.map((p) => p.describe()).join(" | ");

    assert.strictEqual(winners.length, 1, `Exactly one process may own the port: ${detail}`);
    assert.strictEqual(losers.length, contenders - 1, `Every other process must lose: ${detail}`);

    for (const loser of losers) {
      assert.strictEqual(loser.find("LOST:"), "LOST:EADDRINUSE", `A port collision must surface as EADDRINUSE: ${loser.describe()}`);
      assert.ok(loser.has("SURVIVED"), `A losing process must stay alive: ${loser.describe()}`);
      assert.strictEqual(
        loser.find("JOINED:"),
        "JOINED:authenticated:true",
        `A losing terminal must be able to join the winner: ${loser.describe()}`,
      );
    }

    // The winner has to see them: "authenticated" on the client side plus an empty hub roster
    // would mean the join landed somewhere else.
    const sawPeers = await waitUntil(() => winners[0].lines().includes(`PEERS:${contenders - 1}`), 8000);
    assert.ok(sawPeers, `Winner never saw ${contenders - 1} peer(s): ${detail}`);

    fs.writeFileSync(release, "go");
    await Promise.all(procs.map((p) => p.closed));

    for (const proc of procs) {
      assert.deepStrictEqual(proc.exit, { code: 0, signal: null }, `Process must exit cleanly: ${proc.describe()}`);
      assert.ok(
        !/Unhandled|unhandledRejection|ERR_UNHANDLED/i.test(proc.stderr),
        `No unhandled error or rejection is acceptable: ${proc.describe()}`,
      );
    }

    // No orphaned listener: the port is free the moment the processes are gone.
    assert.strictEqual(await portBusy(port), false, `Port ${port} was left bound after every process exited: ${detail}`);

    const audit = readAudit(dir);
    assert.strictEqual(
      audit.filter((r) => r.type === "hub_started").length,
      1,
      `Exactly one hub may report a successful start: ${JSON.stringify(audit)}`,
    );
    const failures = audit.filter((r) => r.type === "hub_start_failed");
    assert.strictEqual(failures.length, contenders - 1, `Every loss must be recorded: ${JSON.stringify(audit)}`);
    for (const failure of failures) assert.strictEqual(failure.code, "EADDRINUSE", JSON.stringify(failure));
  }

  test("C1: two processes call startHub() on one port at the same instant", { timeout: 40_000 }, async () => {
    await runStartRace(2);
  });

  test("C1: three processes call startHub() on one port at the same instant", { timeout: 40_000 }, async () => {
    await runStartRace(3);
  });

  // ── C2 ────────────────────────────────────────────────────────────────────
  // The succession stampede. Randomised delays (400-1600 ms) make the *order* unpredictable by
  // design, so the test asserts only what must always be true: one hoster, everyone else
  // connected to it, one audit record. Determinism comes from re-running the race inside one
  // test — the hub is killed, the winner is killed, and so on — and asserting the invariant at
  // every cycle, rather than from pinning who wins.
  test("C2: repeated succession stampedes leave exactly one hub and no duelling", { timeout: 90_000 }, async (t) => {
    if (await portBusy(HUB_PORT)) {
      t.skip(`port ${HUB_PORT} is already in use on this machine; free it to run the succession stampede`);
      return;
    }

    const dir = newStateDir("succession");
    const release = path.join(dir, "release");
    const joinerCount = 4;
    const cycles = 3;

    const host = startFixture("conc-extension-terminal.mjs", {
      OMP_DIR: dir,
      OMP_LINK_ROLE: "host",
      OMP_LINK_NAME: "host-terminal",
      OMP_LINK_ROOM: "stampede",
      OMP_LINK_SETTLE_MS: "30000",
      PI_LINK_IGNORE_VERSION_CHECK: "1",
    });
    const joiners = Array.from({ length: joinerCount }, (_, i) =>
      startFixture("conc-extension-terminal.mjs", {
        OMP_DIR: dir,
        OMP_LINK_ROLE: "join",
        OMP_LINK_NAME: `sibling-${i}`,
        OMP_LINK_RELEASE_FILE: release,
        OMP_LINK_SETTLE_MS: "30000",
        PI_LINK_IGNORE_VERSION_CHECK: "1",
      }));
    const all = [host, ...joiners];

    const hosting = await waitUntil(() => host.has("HOSTING"), 15_000);
    assert.ok(hosting, `Host terminal never started hosting: ${host.describe()}`);
    const joined = await waitUntil(() => joiners.every((p) => p.has("JOINED")), 15_000);
    assert.ok(joined, `Not every sibling joined: ${all.map((p) => p.describe()).join(" | ")}`);

    let victim = host;
    let contenders = joiners;

    for (let cycle = 1; cycle <= cycles; cycle++) {
      const auditBefore = readAudit(dir).length;
      victim.kill("SIGKILL");
      await victim.closed;

      const reported = await waitUntil(() => contenders.every((p) => p.has(`FINAL:${cycle}:`)), 15_000);
      const detail = all.map((p) => p.describe()).join(" | ");
      assert.ok(reported, `Cycle ${cycle}: not every survivor settled: ${detail}`);

      const roleOf = (p) => p.find(`FINAL:${cycle}:`).split(":")[2];
      const hubs = contenders.filter((p) => roleOf(p) === "hub");
      const clients = contenders.filter((p) => roleOf(p) === "client");

      assert.strictEqual(hubs.length, 1, `Cycle ${cycle}: exactly one survivor must host: ${detail}`);
      assert.strictEqual(
        clients.length,
        contenders.length - 1,
        `Cycle ${cycle}: every other survivor must be a connected client, not disconnected: ${detail}`,
      );

      // Connected *to the successor*: the new hub must see all of them, or the room has split.
      const expectedPeers = contenders.length - 1;
      const converged = await waitUntil(() => hubs[0].has(`PEERS:${cycle}:${expectedPeers}:`), 10_000);
      assert.ok(
        converged,
        `Cycle ${cycle}: successor never saw its ${expectedPeers} sibling(s) — the survivors did not converge on one hub: ${detail}`,
      );

      const round = readAudit(dir).slice(auditBefore);
      assert.strictEqual(
        round.filter((r) => r.type === "local_hub_succession").length,
        1,
        `Cycle ${cycle}: exactly one succession may be recorded: ${JSON.stringify(round.map((r) => r.type))}`,
      );
      assert.strictEqual(
        round.filter((r) => r.type === "hub_started").length,
        1,
        `Cycle ${cycle}: exactly one hub may start: ${JSON.stringify(round.map((r) => r.type))}`,
      );

      victim = hubs[0];
      contenders = clients;
    }

    fs.writeFileSync(release, "go");
    const remaining = [victim, ...contenders];
    await Promise.all(remaining.map((p) => p.closed));
    for (const proc of remaining) {
      assert.deepStrictEqual(proc.exit, { code: 0, signal: null }, `Survivor must exit cleanly: ${proc.describe()}`);
      assert.ok(!proc.has("TIMEOUT:"), `Survivor must not end up stuck: ${proc.describe()}`);
    }
  });

  // ── C3 ────────────────────────────────────────────────────────────────────
  // `savePairedDevice()` is load-the-map, mutate, write-the-map. Two terminals pairing at once
  // (one machine, one store) is not exotic: `/link accept` in two windows, or one terminal
  // pairing while another consumes an invite. Every device the operator approved must be in the
  // store afterwards — a device that silently vanishes is a pairing the operator believes they
  // did, and the peer is refused on its next connection with no explanation.
  //
  // Before the store lock landed, this run lost 18 of 48 approvals: each write was atomic, the
  // read-modify-write around it was not.
  test(
    "C3: two processes pairing at once must not lose a device",
    { timeout: 40_000 },
    async () => {
      const dir = newStateDir("paired-store");
      const barrier = path.join(dir, "barrier");
      const perProcess = 24;
      const tags = ["alpha", "bravo"];

      const procs = tags.map((tag) =>
        startFixture("conc-store-writer.mjs", {
          OMP_LINK_TEST_DIR: dir,
          OMP_LINK_BARRIER_FILE: barrier,
          OMP_LINK_TAG: tag,
          OMP_LINK_COUNT: String(perProcess),
          OMP_LINK_SLOT_MS: "12",
          OMP_LINK_MODE: "paired",
          OMP_LINK_NAME: `writer-${tag}`,
        }));

      await releaseBarrier(procs, barrier);
      await Promise.all(procs.map((p) => p.closed));
      for (const proc of procs) {
        assert.deepStrictEqual(proc.exit, { code: 0, signal: null }, proc.describe());
        assert.strictEqual(proc.find("WROTE:"), `WROTE:${perProcess}`, proc.describe());
      }

      const stored = loadPairedDevices(dir);
      const expected = tags.flatMap((tag) => Array.from({ length: perProcess }, (_, i) => `${tag}-${i}`));
      const missing = expected.filter((deviceName) => ![...stored.values()].some((d) => d.deviceName === deviceName));

      assert.deepStrictEqual(
        missing,
        [],
        `${missing.length} of ${expected.length} approved devices were lost by concurrent writers `
        + `(store holds ${stored.size}). Each write is atomic, but the read-modify-write around it is not.`,
      );
    },
  );

  // ── C4 ────────────────────────────────────────────────────────────────────
  // The audit log is the oracle every security decision is judged by, and every terminal on the
  // machine appends to the same file. A torn or interleaved line is worse than a missing one: it
  // makes the record unparseable exactly where it matters.
  test("C4: concurrent audit appends stay one intact JSON line each", { timeout: 40_000 }, async () => {
    const dir = newStateDir("audit-writers");
    const barrier = path.join(dir, "barrier");
    const perProcess = 40;
    const tags = ["one", "two", "three"];

    const procs = tags.map((tag) =>
      startFixture("conc-store-writer.mjs", {
        OMP_LINK_TEST_DIR: dir,
        OMP_LINK_BARRIER_FILE: barrier,
        OMP_LINK_TAG: tag,
        OMP_LINK_COUNT: String(perProcess),
        OMP_LINK_SLOT_MS: "4",
        OMP_LINK_MODE: "audit",
        OMP_LINK_NAME: `audit-${tag}`,
      }));

    await releaseBarrier(procs, barrier);
    await Promise.all(procs.map((p) => p.closed));
    for (const proc of procs) assert.deepStrictEqual(proc.exit, { code: 0, signal: null }, proc.describe());

    const raw = fs.readFileSync(path.join(dir, "audit.log"), "utf8");
    const lines = raw.split("\n").filter(Boolean);
    assert.ok(raw.endsWith("\n"), "The log must not end mid-record");

    const seen = new Set();
    for (const [index, line] of lines.entries()) {
      let record;
      try {
        record = JSON.parse(line);
      } catch (err) {
        assert.fail(`Line ${index + 1} of ${lines.length} is not one intact JSON record (${err.message}): ${JSON.stringify(line.slice(0, 200))}`);
      }
      if (record.type === "concurrency_probe") seen.add(`${record.tag}:${record.seq}`);
    }

    const expected = tags.flatMap((tag) => Array.from({ length: perProcess }, (_, i) => `${tag}:${i}`));
    const missing = expected.filter((key) => !seen.has(key));
    assert.deepStrictEqual(missing, [], `Audit records lost under concurrent appends: ${missing.length} of ${expected.length}`);
  });

  // ── C5 ────────────────────────────────────────────────────────────────────
  // R5 was the worst kind of bug: constructing a second LinkNode reclaimed a live transfer's
  // staging file, writes continued into the unlinked inode, and both the byte count and the
  // sha256 still passed. The fix has two halves (owner pid alive, file idle past the absolute
  // timeout); the staging file here is backdated far past the idle rule on purpose, so only the
  // pid rule is left to protect it.
  test("C5: an in-flight transfer survives other terminals starting and stopping", { timeout: 40_000 }, async () => {
    const dir = newStateDir("transfer");
    const ready = path.join(dir, "holder-ready");
    const go = path.join(dir, "holder-go");

    const holder = startFixture("conc-transfer-holder.mjs", {
      OMP_LINK_TEST_DIR: dir,
      OMP_LINK_READY_FILE: ready,
      OMP_LINK_GO_FILE: go,
      OMP_LINK_NAME: "holder",
    });

    const staged = await waitUntil(() => holder.has("BACKDATED:") || holder.exit !== null, 15_000);
    assert.ok(staged, `Holder never staged its transfer: ${holder.describe()}`);
    const partPath = holder.find("STAGED:").slice("STAGED:".length);
    assert.ok(fs.existsSync(partPath), `Staging file missing before the churn: ${holder.describe()}`);

    // A control the sweep is supposed to take: same inbox, backdated the same way, but its owner
    // is gone. If the churn leaves this behind too, "the live transfer survived" means nothing.
    const orphan = plantOrphanStaging(dir);

    const churn = startFixture("conc-node-churn.mjs", {
      OMP_LINK_TEST_DIR: dir,
      OMP_LINK_ROUNDS: "5",
      OMP_LINK_NAME: "churn",
    });
    await churn.closed;
    assert.deepStrictEqual(churn.exit, { code: 0, signal: null }, churn.describe());
    assert.ok(churn.has("DONE"), churn.describe());

    assert.ok(
      fs.existsSync(partPath),
      `A live transfer's staging file was reclaimed by another terminal's startup: ${partPath}\n${churn.describe()}`,
    );
    assert.ok(
      !fs.existsSync(orphan.part),
      `The startup sweep never reclaimed an abandoned staging file (dead pid ${orphan.pid}, idle `
      + `${ABSOLUTE_TIMEOUT_MS * 4} ms), so it cannot be said to have spared the live one: ${churn.describe()}`,
    );

    fs.writeFileSync(go, "go");
    await holder.closed;
    assert.deepStrictEqual(holder.exit, { code: 0, signal: null }, holder.describe());
    assert.strictEqual(
      holder.find("RESULT:"),
      "RESULT:true:true:true",
      `The held transfer must complete with a matching hash: ${holder.describe()}`,
    );

    // Correct bytes on disk, verified by this process rather than by the receiver's own hasher:
    // the R5 loss passed every in-memory check it made about itself.
    const finalLine = holder.find("FINAL:");
    assert.ok(finalLine, holder.describe());
    const finalPath = finalLine.slice("FINAL:".length, finalLine.lastIndexOf(":"));
    const expectedSha = holder.find("EXPECTED_SHA:").slice("EXPECTED_SHA:".length);
    const bytes = fs.readFileSync(finalPath);
    assert.strictEqual(crypto.createHash("sha256").update(bytes).digest("hex"), expectedSha, "Finalised file content differs");
    assert.strictEqual(bytes.length, CHUNK_SIZE * 2 + 1234, "Finalised file is the wrong size");
    assert.ok(!fs.existsSync(partPath), "The staging file must be renamed away, not left behind");
  });

  // ── C6 ────────────────────────────────────────────────────────────────────
  // A terminal dies without unwinding: SIGKILL, an OOM kill, a closed lid. Hosting has to be
  // available again immediately — and the debris a crash leaves is not a leftover to reclaim.
  // `cleanup` reporting a staging directory whose owner died seconds ago would invite a user to
  // delete data that a re-started transfer still owns.
  test("C6: the hub port is rebindable straight after a crash and cleanup invents no leftovers", { timeout: 40_000 }, async (t) => {
    if (await portBusy(HUB_PORT)) {
      t.skip(`port ${HUB_PORT} is already in use on this machine; free it to run the crash-recovery scenario`);
      return;
    }

    const dir = newStateDir("port-reuse");
    const holder = startFixture("conc-hub-holder.mjs", {
      OMP_LINK_TEST_DIR: dir,
      OMP_LINK_TEST_PORT: String(HUB_PORT),
      OMP_LINK_NAME: "crash-victim",
    });

    const up = await waitUntil(() => holder.has("STAGED:"), 15_000);
    assert.ok(up, `Holder never reached a staged transfer on port ${HUB_PORT}: ${holder.describe()}`);
    assert.strictEqual(holder.find("READY:"), `READY:${HUB_PORT}`, holder.describe());
    const stagedParts = holder.find("STAGED:").slice("STAGED:".length).split(",").filter(Boolean);
    assert.strictEqual(stagedParts.length, 1, holder.describe());

    holder.kill("SIGKILL");
    assert.deepStrictEqual(await holder.closed, { code: null, signal: "SIGKILL" }, holder.describe());

    // Immediately, with no grace period: a successor terminal must be able to host.
    const successor = new LinkNode({
      port: HUB_PORT,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dir,
      terminalName: "successor",
      sessionId: "port-reuse",
    });
    await successor.startHub();
    assert.strictEqual(successor.port, HUB_PORT, "The successor must own the real hub port, not a fallback");
    assert.ok(
      fs.existsSync(stagedParts[0]),
      "The successor's own startup sweep destroyed the staging file of the transfer that was in flight when the host died",
    );
    await successor.stop();

    // Control: something cleanup IS meant to offer, so "no leftovers reported" cannot be the
    // answer of a sweep that simply never found the inbox.
    const orphan = plantOrphanStaging(dir);

    const cleanup = JSON.parse(
      execFileSync(process.execPath, [path.join(REPO_ROOT, "bin", "omp-link.mjs"), "cleanup", "--json"], {
        cwd: REPO_ROOT,
        env: { ...process.env, OMP_DIR: dir },
        encoding: "utf8",
      }),
    );

    assert.strictEqual(cleanup.mode, "preview", "cleanup must never act without --apply");
    assert.strictEqual(cleanup.port.listening, false, `Nothing may hold ${HUB_PORT} once the crashed host is gone: ${JSON.stringify(cleanup.port)}`);
    assert.strictEqual(cleanup.port.stoppable, false, JSON.stringify(cleanup.port));

    const ours = [...cleanup.targets, ...cleanup.skipped].filter((target) => String(target.path || "").startsWith(dir));
    assert.deepStrictEqual(
      ours.map((target) => `${target.kind} ${target.path}`),
      [`orphan-staging ${orphan.staging}`],
      `cleanup must offer the abandoned staging dir and nothing else under ${dir}; freshly crashed `
      + `debris is still owned by a transfer that may resume: ${JSON.stringify(ours)}`,
    );
    assert.ok(fs.existsSync(stagedParts[0]), "A preview must not have removed anything");
  });

  // ── C7 ────────────────────────────────────────────────────────────────────
  // Two people whose terminals are both called "laptop" join the same room. A display name is a
  // routing key: `sendMessage`, `executeRemoteRpc` and `resolveExpectedResponder` all resolve a
  // peer by name, so two peers answering to one name means messages, RPCs and correlated
  // responses can land on the wrong device.
  //
  // The window is the pairing queue: at `client_hello` neither peer is authenticated yet, so
  // neither can see the other's name. In 3.4.0 (`git show HEAD:src/link-node.ts`, line 715)
  // `approvePairing` then assigned `ctx.displayName = paired.deviceName` unconditionally and both
  // ended up as "laptop". This asserts the property, not the mechanism: every roster row must be
  // individually addressable, and a message addressed to one device must reach that device.
  test(
    "C7: two devices with one display name must not receive each other's messages",
    { timeout: 40_000 },
    async () => {
      const hubDir = newStateDir("dup-hub");
      const aDir = newStateDir("dup-a");
      const bDir = newStateDir("dup-b");

      const hub = new LinkNode({
        port: 0,
        bindHost: "127.0.0.1",
        networkMode: "loopback",
        customOmpDir: hubDir,
        terminalName: "hub-primary",
      });
      await hub.startHub();
      const hubUrl = `wss://127.0.0.1:${hub.port}`;

      const pending = [];
      hub.onPairingRequested = (req) => pending.push(req);

      const clientA = new LinkNode({ port: 0, customOmpDir: aDir, terminalName: "laptop" });
      const clientB = new LinkNode({ port: 0, customOmpDir: bDir, terminalName: "laptop" });
      const received = new Map([[clientA, []], [clientB, []]]);
      clientA.onMessage = (msg) => received.get(clientA).push(msg);
      clientB.onMessage = (msg) => received.get(clientB).push(msg);

      try {
        // Both arrive before either is approved: that is the window the rename never sees.
        const outcomes = await Promise.all([
          clientA.connectToHub(hubUrl, hub.identity.fingerprint),
          clientB.connectToHub(hubUrl, hub.identity.fingerprint),
        ]);
        assert.deepStrictEqual(outcomes.map((o) => o.state), ["pairing-required", "pairing-required"]);
        assert.strictEqual(pending.length, 2, "Both peers must be queued for pairing");

        for (const req of pending) {
          const approved = hub.approvePairing(req.id, FULL_PERMISSIONS, req.sasCode);
          assert.ok(approved, `Pairing ${req.id} must be approved with its own code`);
        }
        const admitted = await waitUntil(() => clientA.isAuthenticated && clientB.isAuthenticated, 5000);
        assert.ok(admitted, `Both peers must be admitted: A=${clientA.isAuthenticated} B=${clientB.isAuthenticated}`);

        const roster = hub.getConnectedTerminalsList().filter((t) => !t.isSelf);
        assert.strictEqual(roster.length, 2, JSON.stringify(roster));

        // Routing addresses whatever the hub published. Each roster row is a distinct device, so
        // each must be individually addressable.
        assert.strictEqual(
          new Set(roster.map((t) => t.name)).size,
          2,
          `The hub published two peers under one name, so neither can be addressed: ${JSON.stringify(roster)}`,
        );

        for (const entry of roster) hub.sendMessage(entry.name, `for:${entry.principalId}`);
        await waitUntil(() => [...received.values()].every((list) => list.length > 0), 3000);

        for (const [client, list] of received) {
          assert.strictEqual(
            list.length,
            1,
            `${client.identity.principalId} received ${list.length} of the 2 messages: ${JSON.stringify(list.map((m) => m.text))}`,
          );
          assert.strictEqual(
            list[0].text,
            `for:${client.identity.principalId}`,
            "A message addressed to one device was delivered to another",
          );
        }
      } finally {
        await clientA.stop();
        await clientB.stop();
        await hub.stop();
      }
    },
  );

  // ── C8 ────────────────────────────────────────────────────────────────────
  // First run, several terminals — `--link` in two windows on a machine with no `~/.omp` yet, or
  // the dogfooding runbook's own step 1. Creation is the only unrepeatable moment in the identity
  // lifecycle: every process that finds no certificate makes one, and they all write the same two
  // paths. One device may then end up holding several identities — and a `principalId` IS the
  // device. Everything downstream keys on it: sibling admission
  // compares `peerCert.principalId === this.identity.principalId`, remote peers pinned the SPKI,
  // and `paired-devices.json` is indexed by fingerprint.
  //
  // Reproduced before the fix, on both symptoms: 3 processes over 8 synchronised slots produced
  // divergent principalIds in most slots every run, and — while creation still wrote openssl's
  // output straight to the final paths — a certificate next to a foreign private key, which the
  // reuse branch cannot detect because it only parses the certificate. Creation now stages into
  // a temp dir and claims the identity with an exclusive `link(2)` on the key, so the loser
  // adopts the winner's pair. This asserts the outcome: one usable pair, one principalId.
  test(
    "C8: first-run identity creation from several terminals yields one identity per device",
    { timeout: 40_000 },
    async () => {
      const dir = newStateDir("identity-race");
      const root = path.join(dir, "fresh");
      fs.mkdirSync(root, { recursive: true });
      const barrier = path.join(dir, "barrier");
      const slots = 8;

      const procs = Array.from({ length: 3 }, (_, i) =>
        startFixture("conc-identity-first-run.mjs", {
          OMP_LINK_TEST_DIR: root,
          OMP_LINK_BARRIER_FILE: barrier,
          OMP_LINK_SLOTS: String(slots),
          OMP_LINK_SLOT_MS: "120",
          OMP_LINK_NAME: `first-run-${i}`,
        }));

      await releaseBarrier(procs, barrier);
      await Promise.all(procs.map((p) => p.closed));
      for (const proc of procs) assert.deepStrictEqual(proc.exit, { code: 0, signal: null }, proc.describe());

      const broken = [];
      const divergent = [];
      for (let i = 0; i < slots; i++) {
        const identityDir = path.join(root, `slot-${i}`, "identity");
        const key = fs.readFileSync(path.join(identityDir, "device-key.pem"), "utf8");
        const cert = fs.readFileSync(path.join(identityDir, "device-cert.pem"), "utf8");
        try {
          // Exactly what getServerTlsOptions/getClientTlsOptions hand to node:tls.
          crypto.createPrivateKey(key);
          const x509 = new crypto.X509Certificate(cert);
          if (!x509.checkPrivateKey(crypto.createPrivateKey(key))) broken.push(`slot-${i}`);
        } catch (err) {
          broken.push(`slot-${i}: ${err.message.slice(0, 60)}`);
        }
        const reported = new Set(
          procs.map((p) => p.find(`SLOT:${i}:`)).filter(Boolean).map((l) => l.slice(`SLOT:${i}:`.length)),
        );
        if (reported.size > 1) divergent.push(`slot-${i}: ${[...reported].join(" vs ")}`);
      }

      assert.deepStrictEqual(
        broken,
        [],
        `Concurrent first-run identity creation left an unusable key/certificate pair on disk. `
        + `Every later start reuses it, so TLS fails until the user deletes the identity directory. Slots: ${JSON.stringify(broken)}`,
      );
      assert.deepStrictEqual(divergent, [], `Terminals on one device disagreed about their own principalId: ${JSON.stringify(divergent)}`);
    },
  );

  // ── C9 ────────────────────────────────────────────────────────────────────
  // The other side of C8's fix. The identity claim is an exclusive `link(2)` on
  // `device-key.pem`, and the certificate is published a moment later, so a process killed
  // between the two leaves a key with no certificate — the same SIGKILL, OOM kill or closed lid
  // that C6 covers, landing in a two-step window on first run.
  //
  // Before the reclaim landed that state was terminal, not slow: the reuse branch needs both
  // files, so it fell through to creation, found the claim taken, waited IDENTITY_CLAIM_WAIT_MS
  // for a certificate that would never appear, and threw — out of the LinkNode constructor, i.e.
  // out of every command and tool, on this state directory, forever. A key nobody has a
  // certificate for is unusable by definition, so recovery must be automatic rather than a
  // matter of the operator knowing which file to delete.
  test(
    "C9: an identity claim orphaned by a crash must not wedge the state directory",
    { timeout: 40_000 },
    async () => {
      const dir = fs.mkdtempSync(path.join(rootDir, "orphan-claim-"));
      fs.mkdirSync(path.join(dir, "identity"), { recursive: true, mode: 0o700 });
      // Exactly what a process killed between the claim and the rename leaves behind.
      fs.writeFileSync(
        path.join(dir, "identity", "device-key.pem"),
        "-----BEGIN PRIVATE KEY-----\nabandoned-claim\n-----END PRIVATE KEY-----\n",
        { mode: 0o600 },
      );

      let identity;
      let failure = null;
      try {
        identity = getOrCreateDeviceIdentity(dir);
      } catch (err) {
        failure = err instanceof Error ? err.message : String(err);
      }

      assert.strictEqual(
        failure,
        null,
        "A key file with no certificate is an abandoned claim, not an identity: it must be reclaimed, "
        + "not turned into a permanent failure of every /link command",
      );
      assert.ok(
        new crypto.X509Certificate(identity.certPem).checkPrivateKey(crypto.createPrivateKey(identity.keyPem)),
        "The reclaimed identity must be a matching key/certificate pair",
      );
    },
  );
});
