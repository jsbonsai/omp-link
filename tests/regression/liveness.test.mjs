import { test, describe, before, after } from "node:test";
import assert from "node:assert";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { FIXTURE_DIR, REPO_ROOT } from "../helpers/child.mjs";
import { LinkNode } from "../../src/link-node.js";
import { readAuditLogs, setCustomAuditLogPath } from "../../src/audit.js";
import {
  FULL_PERMISSIONS,
  getOrCreateDeviceIdentity,
  loadPairedDevices,
  normalizeFingerprint,
  savePairedDevice,
} from "../../src/identity.js";
import { clearTimingsCache } from "../../src/config.js";

// Liveness regressions (L-numbered, distinct from the R- and C- series).
//
// An authenticated connection used to have no keepalive at all. A peer whose laptop slept, whose
// Wi-Fi dropped, or that was SIGKILLed stayed in the roster until the OS eventually tore the TCP
// connection down — minutes, or never on a silent network — and `link_list` kept confidently
// naming agents that were gone. The worst case is a frozen process: SIGSTOP leaves the socket
// established and the kernel still ACKing, so nothing below the application layer can tell it
// apart from an idle peer. Only an unanswered WebSocket ping can.
//
// Every test here uses real nodes and, where the failure needs a separate process to be killable
// or freezable, real child processes. The heartbeat is driven from `link.json` timings
// (`heartbeatIntervalMs`, `heartbeatMissesBeforeDrop`, `clientHubSilenceTimeoutMs`), so each test
// tunes them down rather than waiting out the 15 s/30 s/45 s production defaults — which also
// proves the config path is wired, not just the constants.

/** Fast enough for a test, above every floor `getTimings` enforces. */
const TEST_TIMINGS = {
  heartbeatIntervalMs: 1_000,
  heartbeatMissesBeforeDrop: 2,
  clientHubSilenceTimeoutMs: 2_000,
};

/** Hub-side budget: two silent intervals, plus one for the sweep that notices. */
const HUB_DETECT_BUDGET_MS = 8_000;
/** Client-side budget: the silence window, plus one sweep. */
const CLIENT_DETECT_BUDGET_MS = 8_000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function pollUntil(predicate, timeoutMs, stepMs = 50) {
  const started = Date.now();
  for (;;) {
    if (await predicate()) return Date.now() - started;
    if (Date.now() - started >= timeoutMs) return null;
    await sleep(stepMs);
  }
}

function withDeadline(promise, ms, label) {
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label}: still pending after ${ms}ms`)), ms);
  });
  return Promise.race([
    Promise.resolve(promise).then(
      (value) => { clearTimeout(timer); return value; },
      (err) => { clearTimeout(timer); throw err; },
    ),
    deadline,
  ]);
}

function makeStateDirs(prefix, names) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const dirs = { root };
  for (const name of names) {
    dirs[name] = path.join(root, name);
    fs.mkdirSync(dirs[name], { recursive: true });
  }
  return dirs;
}

/**
 * Timings are read once per state directory at LinkNode construction, so this must run before
 * any node is built against `dir` — in this process and in any child that shares it.
 */
function writeTimings(dir, timings = TEST_TIMINGS) {
  fs.writeFileSync(path.join(dir, "link.json"), JSON.stringify({ timings }), { mode: 0o600 });
  clearTimingsCache();
}

function deviceRecord(identity, deviceName) {
  return {
    principalId: identity.principalId,
    fingerprint: identity.fingerprint,
    certPem: identity.certPem,
    deviceName,
    permissions: FULL_PERMISSIONS,
    pairedAt: Date.now(),
  };
}

const live = new Set();

/** Spawns a fixture and exposes the signal control a liveness test needs. */
function startFixture(name, env) {
  const child = spawn(process.execPath, ["--import", "tsx", path.join(FIXTURE_DIR, name)], {
    cwd: REPO_ROOT,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const proc = {
    child,
    stdout: "",
    stderr: "",
    exited: false,
    stopped: false,
    line: (prefix) => proc.stdout.split("\n").map((l) => l.trim()).find((l) => l.startsWith(prefix)) || null,
    signal: (sig) => { try { child.kill(sig); } catch {} },
    /** Freeze the process: socket stays established, the application stops answering. */
    freeze: () => { proc.stopped = true; proc.signal("SIGSTOP"); },
    kill: () => {
      // A stopped process never handles SIGTERM. Thaw first, then SIGKILL, or the child leaks.
      if (proc.stopped) { proc.signal("SIGCONT"); proc.stopped = false; }
      proc.signal("SIGKILL");
    },
  };
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (c) => { proc.stdout += c; });
  child.stderr.on("data", (c) => { proc.stderr += c; });
  child.on("exit", () => { proc.exited = true; live.delete(proc); });
  live.add(proc);
  return proc;
}

async function waitForLine(proc, prefix, timeoutMs = 20_000) {
  const found = await pollUntil(() => proc.line(prefix) !== null || proc.exited, timeoutMs);
  const value = proc.line(prefix);
  assert.ok(
    found !== null && value !== null,
    `fixture never printed ${prefix} (exited=${proc.exited} stdout=${JSON.stringify(proc.stdout)} stderr=${JSON.stringify(proc.stderr)})`,
  );
  return value.slice(prefix.length);
}

after(() => {
  for (const proc of [...live]) proc.kill();
});

// ── L1 / L2: a hub must not keep a dead or frozen peer in its roster ──────────────────────────

describe("REGRESSION L1/L2: a hub drops peers that stop answering", () => {
  let dirs;
  let hub;
  let hubUrl;

  before(async () => {
    dirs = makeStateDirs("omplink-liveness-hub-", ["hub", "killed", "frozen"]);
    setCustomAuditLogPath(path.join(dirs.root, "test-audit.log"));
    for (const dir of [dirs.hub, dirs.killed, dirs.frozen]) writeTimings(dir);

    // Both peers run in their own process, so their identities must exist before the hub can
    // be told to trust them.
    for (const [dir, name] of [[dirs.killed, "killed-peer"], [dirs.frozen, "frozen-peer"]]) {
      savePairedDevice(deviceRecord(getOrCreateDeviceIdentity(dir), name), dirs.hub);
    }

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.hub,
      terminalName: "liveness-hub",
      sessionId: "liveness",
      workspaceRoot: dirs.hub,
    });
    await hub.startHub();
    hubUrl = `wss://127.0.0.1:${hub.port}`;
  });

  after(async () => {
    await hub?.stop();
    fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  const joinPeer = async (dir, name) => {
    const proc = startFixture("liveness-peer.mjs", {
      OMP_LINK_TEST_DIR: dir,
      OMP_LINK_HUB_URL: hubUrl,
      OMP_LINK_HUB_FP: hub.identity.fingerprint,
      OMP_LINK_NAME: name,
      OMP_LINK_HOLD_MS: "60000",
    });
    await waitForLine(proc, "JOINED:");
    const joined = await pollUntil(
      () => hub.getConnectedTerminalsList().some((t) => t.name === name),
      5_000,
    );
    assert.ok(joined !== null, `${name} never reached the hub roster`);
    return proc;
  };

  test("L1: a SIGKILLed peer leaves the roster within a bounded time", async () => {
    const peer = await joinPeer(dirs.killed, "killed-peer");

    peer.kill();

    const gone = await pollUntil(
      () => !hub.getConnectedTerminalsList().some((t) => t.name === "killed-peer"),
      HUB_DETECT_BUDGET_MS,
    );
    assert.ok(
      gone !== null,
      `a SIGKILLed peer was still in the roster after ${HUB_DETECT_BUDGET_MS}ms: `
      + JSON.stringify(hub.getConnectedTerminalsList().map((t) => t.name)),
    );
  });

  test("L2: a SIGSTOPped peer leaves the roster — the socket is alive, the process is not", async () => {
    const peer = await joinPeer(dirs.frozen, "frozen-peer");

    peer.freeze();

    // Nothing at the transport layer changes here: the kernel of a stopped process still
    // completes the TCP handshake work and ACKs. Only the missing pong can expose it.
    const gone = await pollUntil(
      () => !hub.getConnectedTerminalsList().some((t) => t.name === "frozen-peer"),
      HUB_DETECT_BUDGET_MS,
    );
    assert.ok(
      gone !== null,
      `a frozen peer held its roster slot for the full ${HUB_DETECT_BUDGET_MS}ms — a TCP-level `
      + "check cannot see this, so the heartbeat is the only thing that can",
    );

    const timeouts = readAuditLogs(500).filter((r) => r.type === "peer_liveness_timeout");
    assert.ok(
      timeouts.some((r) => r.peer === "frozen-peer"),
      `expected a peer_liveness_timeout audit entry for the frozen peer, saw: ${JSON.stringify(timeouts)}`,
    );

    peer.kill();
  });
});

// ── L3: a hub that dies mid-RPC must fail the caller and report the loss ──────────────────────

describe("REGRESSION L3: a killed hub disconnects its client and fires onHubDisconnected", () => {
  let dirs;
  let client;
  let hubProc;
  let disconnects;

  before(async () => {
    dirs = makeStateDirs("omplink-liveness-deadhub-", ["hub", "client"]);
    setCustomAuditLogPath(path.join(dirs.root, "test-audit.log"));
    for (const dir of [dirs.hub, dirs.client]) writeTimings(dir);

    client = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.client,
      terminalName: "orphan-client",
      sessionId: "liveness",
      workspaceRoot: dirs.client,
    });
    savePairedDevice(deviceRecord(client.identity, "orphan-client"), dirs.hub);

    hubProc = startFixture("liveness-hub.mjs", {
      OMP_LINK_TEST_DIR: dirs.hub,
      OMP_LINK_HOLD_MS: "60000",
    });
    const port = await waitForLine(hubProc, "PORT:");
    const fingerprint = await waitForLine(hubProc, "FP:");

    disconnects = 0;
    client.onHubDisconnected = () => { disconnects += 1; };

    const outcome = await client.connectToHub(`wss://127.0.0.1:${port}`, fingerprint);
    assert.strictEqual(outcome.state, "authenticated");
  });

  after(async () => {
    hubProc?.kill();
    await client?.stop();
    fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("L3: the in-flight RPC fails immediately and the loss is reported exactly once", async () => {
    // Freeze first so the hub cannot answer, then kill: the request is genuinely in flight when
    // its hub dies. A killed peer resets the socket, which reaches `ws` as an "error" event —
    // the path that used to null `clientWs` and silently skip `onHubDisconnected`, so local hub
    // succession never ran for the one failure it exists for.
    hubProc.freeze();
    const pending = client.executeRemoteRpc("liveness-hub", "system_status", {});
    pending.catch(() => {}); // the assertion below owns the rejection; do not leak it meanwhile
    await sleep(100);
    hubProc.kill();

    await assert.rejects(
      withDeadline(pending, CLIENT_DETECT_BUDGET_MS, "in-flight RPC after the hub died"),
      /disconnect|closed|failed|reset|stop/i,
      "an RPC whose hub died must fail its caller now, not wait out the RPC timeout",
    );

    const settled = await pollUntil(() => client.role === "disconnected", CLIENT_DETECT_BUDGET_MS);
    assert.ok(settled !== null, `client stayed role="${client.role}" after its hub was killed`);
    assert.strictEqual(client.isAuthenticated, false);
    assert.strictEqual(
      disconnects,
      1,
      "onHubDisconnected must fire exactly once — zero means succession never runs, twice means "
      + "a second terminal races for the port",
    );
  });
});

// ── L3b: a link that ends in a transport error, not a close ───────────────────────────────────

describe("REGRESSION L3b: a link lost to a transport error still reports the loss", () => {
  let dirs;
  let hub;
  let client;
  let disconnects;

  before(async () => {
    dirs = makeStateDirs("omplink-liveness-error-", ["hub", "client"]);
    setCustomAuditLogPath(path.join(dirs.root, "test-audit.log"));
    for (const dir of [dirs.hub, dirs.client]) writeTimings(dir);

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.hub,
      terminalName: "error-hub",
      sessionId: "liveness",
      workspaceRoot: dirs.hub,
    });
    client = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.client,
      terminalName: "error-client",
      sessionId: "liveness",
      workspaceRoot: dirs.client,
    });
    await hub.startHub();
    savePairedDevice(deviceRecord(client.identity, "error-client"), dirs.hub);

    disconnects = 0;
    client.onHubDisconnected = () => { disconnects += 1; };
    const outcome = await client.connectToHub(`wss://127.0.0.1:${hub.port}`, hub.identity.fingerprint);
    assert.strictEqual(outcome.state, "authenticated");
  });

  after(async () => {
    await client?.stop();
    await hub?.stop();
    fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("L3b: an error event must not swallow onHubDisconnected", async () => {
    // Not every lost link arrives as a close frame. `ws` reports a protocol-level fault — here
    // a frame past the 2 MiB `maxPayload`, the same shape a corrupted or hostile hub produces —
    // as an "error" followed by a close. The error handler used to null `clientWs` itself, so
    // the close that followed hit the ownership guard and returned: the node went
    // `disconnected` while `onHubDisconnected` never fired, and local hub succession — the
    // whole reason this room survives a host going away — silently did not run.
    for (const socket of hub.wss.clients) socket.send(Buffer.alloc(3 * 1024 * 1024, 0x41));

    const settled = await pollUntil(() => client.role === "disconnected", 5_000);
    assert.ok(settled !== null, `client stayed role="${client.role}" after a transport error`);
    assert.strictEqual(
      disconnects,
      1,
      "every way a client link can end must report the loss exactly once",
    );
  });

  test("L3c: a join that never connected is a failed join, not a lost hub", async () => {
    // The counterweight to L3b. `onHubDisconnected` makes the host try local hub succession,
    // so reporting a *failed* connection through it would have `/link on` against a dead
    // endpoint quietly start hosting — "join never creates" (AGENTS.md invariant 20). A
    // connection refused at the transport layer reaches `ws` as an error too, which is exactly
    // why it must be told apart from a link that was once live.
    const lonely = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.client,
      terminalName: "lonely-client",
      sessionId: "liveness",
      workspaceRoot: dirs.client,
    });
    let reported = 0;
    lonely.onHubDisconnected = () => { reported += 1; };

    // Port 1 on loopback refuses instantly and is never a link hub.
    await assert.rejects(lonely.connectToHub("wss://127.0.0.1:1", hub.identity.fingerprint));
    await sleep(300);

    assert.strictEqual(reported, 0, "a connection that never opened must not report a hub loss");
    assert.strictEqual(lonely.role, "disconnected");
    await lonely.stop();
  });
});

// ── L4: a hub that goes silent without closing ────────────────────────────────────────────────

describe("REGRESSION L4: a client notices a hub that stopped answering", () => {
  let dirs;
  let client;
  let hubProc;
  let disconnects;

  before(async () => {
    dirs = makeStateDirs("omplink-liveness-silenthub-", ["hub", "client"]);
    setCustomAuditLogPath(path.join(dirs.root, "test-audit.log"));
    for (const dir of [dirs.hub, dirs.client]) writeTimings(dir);

    client = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.client,
      terminalName: "patient-client",
      sessionId: "liveness",
      workspaceRoot: dirs.client,
    });
    savePairedDevice(deviceRecord(client.identity, "patient-client"), dirs.hub);

    hubProc = startFixture("liveness-hub.mjs", {
      OMP_LINK_TEST_DIR: dirs.hub,
      OMP_LINK_HOLD_MS: "60000",
    });
    const port = await waitForLine(hubProc, "PORT:");
    const fingerprint = await waitForLine(hubProc, "FP:");

    disconnects = 0;
    client.onHubDisconnected = () => { disconnects += 1; };

    const outcome = await client.connectToHub(`wss://127.0.0.1:${port}`, fingerprint);
    assert.strictEqual(outcome.state, "authenticated");
  });

  after(async () => {
    hubProc?.kill();
    await client?.stop();
    fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("L4: a frozen hub moves the client to disconnected so succession can run", async () => {
    hubProc.freeze();

    const settled = await pollUntil(() => client.role === "disconnected", CLIENT_DETECT_BUDGET_MS);
    assert.ok(
      settled !== null,
      `client still reported role="${client.role}" ${CLIENT_DETECT_BUDGET_MS}ms after its hub `
      + "froze; the TCP connection is still established, so only the ping can expose this",
    );
    assert.strictEqual(client.isAuthenticated, false);
    assert.strictEqual(disconnects, 1, "the loss must be reported exactly once");

    const timeouts = readAuditLogs(500).filter((r) => r.type === "hub_liveness_timeout");
    assert.ok(timeouts.length >= 1, "a client that gives up on its hub must say so in the audit log");
  });
});

// ── L5: a reconnecting agent instance replaces itself instead of doubling ─────────────────────

describe("REGRESSION L5: a reconnecting agent instance is not counted twice", () => {
  let dirs;
  let hub;
  let hubUrl;
  let first;
  let second;

  before(async () => {
    dirs = makeStateDirs("omplink-liveness-rejoin-", ["hub", "peer"]);
    setCustomAuditLogPath(path.join(dirs.root, "test-audit.log"));
    for (const dir of [dirs.hub, dirs.peer]) writeTimings(dir);

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.hub,
      terminalName: "rejoin-hub",
      sessionId: "liveness",
      workspaceRoot: dirs.hub,
    });
    await hub.startHub();
    hubUrl = `wss://127.0.0.1:${hub.port}`;

    first = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.peer,
      terminalName: "rejoiner",
      sessionId: "liveness",
      workspaceRoot: dirs.peer,
    });
    second = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.peer,
      terminalName: "rejoiner",
      sessionId: "liveness",
      workspaceRoot: dirs.peer,
    });
    savePairedDevice(deviceRecord(first.identity, "rejoiner"), dirs.hub);
  });

  after(async () => {
    await first?.stop();
    await second?.stop();
    await hub?.stop();
    fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("L5: the hub evicts the stale context instead of listing the agent twice", async () => {
    assert.strictEqual((await first.connectToHub(hubUrl, hub.identity.fingerprint)).state, "authenticated");

    // The same terminal coming back: same device key, same agentInstanceId, brand new TLS
    // session. `readonly` is a compile-time promise, and a genuine reconnect is exactly this —
    // a process that already announced this instance id announcing it again.
    second.agentInstanceId = first.agentInstanceId;
    assert.strictEqual((await second.connectToHub(hubUrl, hub.identity.fingerprint)).state, "authenticated");

    const settled = await pollUntil(() => hub.getConnectedTerminalsList().length === 2, 5_000);
    const roster = hub.getConnectedTerminalsList();
    assert.ok(
      settled !== null,
      `roster should hold the hub plus one instance of the rejoiner, got ${JSON.stringify(roster.map((t) => t.name))}`,
    );
    assert.deepStrictEqual(
      roster.filter((t) => !t.isSelf).map((t) => t.agentInstanceId),
      [first.agentInstanceId],
      "one agentInstanceId must occupy exactly one roster slot",
    );

    // The evicted side must know it is out, not keep sending into a socket the hub has dropped.
    const evicted = await pollUntil(() => first.role === "disconnected", 5_000);
    assert.ok(evicted !== null, `the superseded connection still reports role="${first.role}"`);

    // `isSelf` is a local judgement, never a peer's claim. A client absorbing the hub's roster
    // must end up with exactly one self entry — its own — or a consumer that lists reachable
    // peers by excluding self finds none and refuses every send.
    const clientView = second.getConnectedTerminalsList();
    assert.deepStrictEqual(
      clientView.filter((t) => t.isSelf).map((t) => t.agentInstanceId),
      [second.agentInstanceId],
      `a client's roster must contain exactly one self: ${JSON.stringify(clientView)}`,
    );
    assert.ok(
      clientView.some((t) => t.name === "rejoin-hub" && !t.isSelf),
      "the hub must appear in the client's roster as a reachable peer",
    );
  });
});

// ── L6: nothing the liveness work armed may outlive stop() ────────────────────────────────────

describe("REGRESSION L6: stop() leaves no timer behind", () => {
  let dirs;

  before(() => {
    dirs = makeStateDirs("omplink-liveness-stop-", ["hub", "client"]);
    setCustomAuditLogPath(path.join(dirs.root, "test-audit.log"));
    for (const dir of [dirs.hub, dirs.client]) writeTimings(dir);
    savePairedDevice(
      deviceRecord(getOrCreateDeviceIdentity(dirs.client), "stop-client"),
      dirs.hub,
    );
  });

  after(() => {
    fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("L6: a stopped hub and client let their process exit on its own", async () => {
    // The oracle is the exit, not an assertion: a leaked interval keeps the event loop alive,
    // and the only observer that can report that is a process that is not the one leaking.
    const proc = startFixture("liveness-stop.mjs", {
      OMP_LINK_HUB_DIR: dirs.hub,
      OMP_LINK_CLIENT_DIR: dirs.client,
    });

    const exited = await pollUntil(() => proc.exited, 20_000);
    assert.ok(
      exited !== null,
      "the fixture never exited after stop() — something is still holding the event loop: "
      + JSON.stringify(proc.stdout),
    );
    assert.strictEqual(proc.child.exitCode, 0, `fixture exited badly: ${JSON.stringify(proc.stdout)} ${JSON.stringify(proc.stderr)}`);
    assert.match(proc.stdout, /JOINED:authenticated/);
    assert.match(proc.stdout, /STOPPED/);
    assert.match(proc.stdout, /TIMERS:0/, `stop() left timers armed: ${JSON.stringify(proc.stdout)}`);
  });
});

// ── L7: a name that is already spoken for, whether or not its owner is online ─────────────────

describe("REGRESSION L7: display names cannot be squatted while their owner is offline", () => {
  let dirs;
  let hub;
  let hubUrl;
  const clients = [];

  before(async () => {
    dirs = makeStateDirs("omplink-liveness-names-", ["hub", "absent", "squatter", "lookalike"]);
    setCustomAuditLogPath(path.join(dirs.root, "test-audit.log"));
    for (const dir of [dirs.hub, dirs.squatter, dirs.lookalike]) writeTimings(dir);

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.hub,
      terminalName: "names-hub",
      sessionId: "liveness",
      workspaceRoot: dirs.hub,
    });
    await hub.startHub();
    hubUrl = `wss://127.0.0.1:${hub.port}`;

    // The rightful owner of "orchestrator": a real paired device that simply is not connected
    // right now — a laptop that is asleep, which is the normal state of half a team's machines.
    savePairedDevice(
      deviceRecord(getOrCreateDeviceIdentity(dirs.absent), "orchestrator"),
      dirs.hub,
    );

    hub.onPairingRequested = (req) => {
      hub.approvePairing(req.id, FULL_PERMISSIONS, req.sasCode);
    };
  });

  after(async () => {
    for (const c of clients) await c.stop();
    await hub?.stop();
    fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  /** Pairs a brand-new device claiming `claimed` and returns the name the hub persisted. */
  const pairClaiming = async (dir, claimed) => {
    const node = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dir,
      terminalName: claimed,
      sessionId: "liveness",
      workspaceRoot: dir,
    });
    clients.push(node);
    await node.connectToHub(hubUrl, hub.identity.fingerprint);
    const fp = normalizeFingerprint(node.identity.fingerprint);
    const stored = await pollUntil(() => loadPairedDevices(dirs.hub).has(fp), 5_000);
    assert.ok(stored !== null, `the hub never persisted a record for the device claiming ${JSON.stringify(claimed)}`);
    return loadPairedDevices(dirs.hub).get(fp).deviceName;
  };

  test("L7: an offline device still owns its name", async () => {
    // Only live sockets used to be checked, so a newcomer could be *persisted* under an absent
    // device's exact name. When the real device came back both answered to one routing key —
    // and `handleHubClientHello` prefers the stored name, so the legitimate device was the one
    // that got suffixed. The name is what `link_send` and `resolveExpectedResponder` resolve.
    const assigned = await pairClaiming(dirs.squatter, "orchestrator");
    assert.match(
      assigned,
      /^orchestrator@[0-9A-F]{6}$/,
      `a device claiming an already-registered name must be suffixed, got ${JSON.stringify(assigned)}`,
    );
  });

  test("L7: a zero-width look-alike is the same name", async () => {
    // "orchestrator\u200b" renders identically on both screens. Raw === never matched it, so
    // the operator would see two entries they cannot tell apart and address the wrong one.
    const assigned = await pairClaiming(dirs.lookalike, "orchestrator\u200b");
    assert.ok(
      assigned.includes("@"),
      `a look-alike of a taken name must collide, got ${JSON.stringify(assigned)}`,
    );
    assert.notStrictEqual(assigned.normalize("NFKC").replace(/\p{Cf}/gu, ""), "orchestrator");
  });
});
