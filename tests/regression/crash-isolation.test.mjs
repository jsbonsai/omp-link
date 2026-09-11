import { test, describe, before, after } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { runFixture, describeChildResult } from "../helpers/child.mjs";

// R1: a port collision must be a rejected promise on a live process, not a dead host.
// Every assertion here is about the CHILD's observable lifecycle, because the defect kills the
// process that would otherwise be asserting. `assert.rejects` in-process cannot see it: the
// promise never settles at all.
describe("REGRESSION R1: hub startup failure is isolated from the host process", () => {
  let stateDir;
  let blocker;
  let blockedPort;

  before(async () => {
    stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-crash-iso-"));

    // Never a hardcoded 199xx: ask the kernel for a free port, then hold it open so the child
    // is guaranteed to collide with a listener this test owns.
    blocker = net.createServer();
    await new Promise((resolve, reject) => {
      blocker.once("error", reject);
      blocker.listen(0, "127.0.0.1", resolve);
    });
    blockedPort = blocker.address().port;
  });

  after(async () => {
    if (blocker) await new Promise((resolve) => blocker.close(resolve));
    if (stateDir && fs.existsSync(stateDir)) fs.rmSync(stateDir, { recursive: true, force: true });
  });

  test("startHub on an occupied port rejects with EADDRINUSE and the process survives", async () => {
    const res = await runFixture(
      "start-hub-on-occupied-port.mjs",
      {
        OMP_LINK_TEST_DIR: stateDir,
        OMP_LINK_TEST_PORT: String(blockedPort),
        OMP_DIR: stateDir,
      },
      25_000,
    );

    assert.strictEqual(res.timedOut, false, `Fixture had to be SIGKILLed: ${describeChildResult(res)}`);
    assert.strictEqual(res.exitCode, 0, `Host process must survive a port collision: ${describeChildResult(res)}`);
    assert.strictEqual(res.signal, null, `Host process must not die by signal: ${describeChildResult(res)}`);

    assert.ok(
      res.lines.includes("REJECTED:EADDRINUSE"),
      `startHub() must reject with EADDRINUSE. Got stdout lines ${JSON.stringify(res.lines)} / stderr ${JSON.stringify(res.stderr)}`,
    );
    assert.ok(
      res.lines.includes("SURVIVED"),
      `Process must still be alive after the failed listen settles: ${describeChildResult(res)}`,
    );
    assert.ok(
      !res.lines.some((l) => l.startsWith("STARTED:")),
      `Port was supposed to be occupied but the hub started: ${describeChildResult(res)}`,
    );
  });

  test("A failed listen emits no unhandled error event and leaves no stale hub role", async () => {
    const res = await runFixture(
      "start-hub-on-occupied-port.mjs",
      {
        OMP_LINK_TEST_DIR: stateDir,
        OMP_LINK_TEST_PORT: String(blockedPort),
        OMP_DIR: stateDir,
      },
      25_000,
    );

    assert.ok(
      !/Unhandled 'error' event/.test(res.stderr),
      `ws re-emits the server error on the WebSocketServer; both emitters need the handler. stderr: ${JSON.stringify(res.stderr)}`,
    );
    assert.ok(
      !/ERR_UNHANDLED_ERROR|EADDRINUSE[\s\S]*at Server/.test(res.stderr),
      `No listen error may reach the default handler. stderr: ${JSON.stringify(res.stderr)}`,
    );
    assert.ok(
      res.lines.includes("ROLE_AFTER_REJECT:disconnected"),
      `Role must fall back to "disconnected" after a failed start: ${describeChildResult(res)}`,
    );
    assert.ok(
      res.lines.some((l) => l === "RESTARTED:hub:true"),
      `Node must be reusable after a failed start (no half-open servers): ${describeChildResult(res)}`,
    );
  });

  test("The failed startup is recorded in the child's redirected audit log only", () => {
    const auditPath = path.join(stateDir, "audit.log");
    assert.ok(fs.existsSync(auditPath), "Fixture must write its audit log inside the test state dir");

    const records = fs
      .readFileSync(auditPath, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l));

    assert.ok(
      records.some((r) => r.type === "hub_start_failed" && r.code === "EADDRINUSE"),
      `Expected a hub_start_failed/EADDRINUSE audit record, got types ${JSON.stringify(records.map((r) => r.type))}`,
    );
    // The successful ephemeral restart proves the same process kept working.
    assert.ok(
      records.some((r) => r.type === "hub_started"),
      `Expected a later hub_started record, got types ${JSON.stringify(records.map((r) => r.type))}`,
    );
  });
});
