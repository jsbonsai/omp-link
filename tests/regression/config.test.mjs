import { test, describe, before, after, beforeEach } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import WebSocket from "ws";

import {
  loadConfig,
  saveConfig,
  getCurrentRoom,
  resolveCurrentRoom,
  getTimings,
  clearTimingsCache,
  DEFAULT_TIMINGS,
  CONFIG_SCHEMA_VERSION,
} from "../../src/config.js";
import {
  appendAuditLog,
  getAuditLogStatus,
  setCustomAuditLogPath,
  setAuditAgentInstanceId,
  readAuditLogs,
} from "../../src/audit.js";
import extension from "../../index.js";
import { LinkNode } from "../../src/link-node.js";
import { getOrCreateDeviceIdentity } from "../../src/identity.js";
import { TransferReceiver, CHUNK_SIZE } from "../../src/transfer-receiver.js";
import { createExecGrant, revokeGrantsForPrincipal } from "../../src/authorization.js";

// Configuration is the one file a stranger who cloned the repo will hand-edit, and the audit log
// is both the security oracle and the `/link shared` receipt. The invariants pinned here are:
// loading NEVER throws whatever is in the file, a bad value degrades to the default without
// taking its neighbours with it, a pre-3.5 file migrates silently, and a log that cannot be
// written says so instead of rendering a reassuring empty receipt.

function writeConfig(dir, text) {
  fs.writeFileSync(path.join(dir, "link.json"), text);
}

const VALID_ROOM = {
  roomId: "11111111-2222-3333-4444-555555555555",
  label: "backend",
  hubPrincipalId: "ed25519-sha256:AA:BB",
  hubFingerprint: "AA:BB",
  endpoint: "192.168.1.5:9900",
  lastJoinedAt: 1757462400000,
};

describe("config module: link.json shape, validation and tunables", () => {
  let dir;

  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-config-"));
    setCustomAuditLogPath(path.join(dir, "test-audit.log"));
  });

  beforeEach(() => {
    clearTimingsCache();
    const file = path.join(dir, "link.json");
    if (fs.existsSync(file)) fs.rmSync(file);
  });

  after(() => {
    setCustomAuditLogPath(null);
    setAuditAgentInstanceId(null);
    if (dir && fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  });

  test("no file yields defaults, no warning, and an empty room list", () => {
    const loaded = loadConfig(dir);
    assert.strictEqual(loaded.exists, false);
    assert.strictEqual(loaded.warning, null);
    assert.strictEqual(loaded.usedDefaults, true);
    assert.strictEqual(loaded.migrated, false);
    assert.deepStrictEqual(loaded.config.rooms, []);
    assert.deepStrictEqual(loaded.timings, { ...DEFAULT_TIMINGS });
    assert.strictEqual(loaded.path, path.join(dir, "link.json"));
    assert.strictEqual(loaded.config.configVersion, CONFIG_SCHEMA_VERSION);
  });

  test("a valid file overrides defaults and reports that file values are in force", () => {
    writeConfig(dir, JSON.stringify({
      configVersion: CONFIG_SCHEMA_VERSION,
      terminalName: "  mac-studio  ",
      network: "tailscale",
      currentRoomId: VALID_ROOM.roomId,
      rooms: [VALID_ROOM],
      timings: { heartbeatIntervalMs: 20_000, rpcTimeoutMs: 45_000 },
    }));

    const loaded = loadConfig(dir);
    assert.strictEqual(loaded.warning, null);
    assert.strictEqual(loaded.exists, true);
    assert.strictEqual(loaded.usedDefaults, false);
    assert.strictEqual(loaded.config.terminalName, "mac-studio");
    assert.strictEqual(loaded.config.network, "tailscale");
    assert.strictEqual(loaded.timings.heartbeatIntervalMs, 20_000);
    assert.strictEqual(loaded.timings.rpcTimeoutMs, 45_000);
    // Untouched keys keep their defaults.
    assert.strictEqual(loaded.timings.pairingWindowMs, DEFAULT_TIMINGS.pairingWindowMs);
    assert.deepStrictEqual(resolveCurrentRoom(loaded.config), VALID_ROOM);
    assert.deepStrictEqual(getCurrentRoom(dir), VALID_ROOM);
  });

  test("currentRoomId naming a room that is gone resolves to null rather than a phantom room", () => {
    writeConfig(dir, JSON.stringify({ currentRoomId: "not-a-room", rooms: [VALID_ROOM] }));
    assert.strictEqual(getCurrentRoom(dir), null);
  });

  // Every corruption class a hand-edited or half-written file can produce. None may throw, all
  // must fall back to defaults, and all but the missing-file case must explain themselves.
  const CORRUPTIONS = [
    ["truncated JSON", '{"rooms": ['],
    ["empty file", ""],
    ["whitespace only", "   \n  "],
    ["literal null", "null"],
    ["a JSON array", "[1,2,3]"],
    ["a JSON string", '"hello"'],
    ["a JSON number", "42"],
    ["rooms as an object", '{"rooms": {"a": 1}}'],
    ["rooms as a string", '{"rooms": "backend"}'],
  ];

  for (const [label, content] of CORRUPTIONS) {
    test(`corruption (${label}) yields defaults plus a warning and never throws`, () => {
      writeConfig(dir, content);
      let loaded;
      assert.doesNotThrow(() => {
        loaded = loadConfig(dir);
      });
      assert.strictEqual(loaded.usedDefaults, true, "must fall back to defaults");
      assert.deepStrictEqual(loaded.config.rooms, []);
      assert.deepStrictEqual(loaded.timings, { ...DEFAULT_TIMINGS });
      assert.ok(loaded.warning, "a corrupt config must be reported, not silently ignored");
      assert.match(loaded.warning, /link\.json/);
      // The bar for a user-facing string: it names what to do next.
      assert.match(loaded.warning, /delete the file|\/link create|permissions/i);
      assert.doesNotThrow(() => getTimings(dir));
      assert.deepStrictEqual(getTimings(dir), { ...DEFAULT_TIMINGS });
    });
  }

  test("an unusable room record is skipped, counted and reported; usable siblings survive", () => {
    writeConfig(dir, JSON.stringify({
      rooms: [VALID_ROOM, { roomId: "no-endpoint", hubPrincipalId: "x", hubFingerprint: "y" }, null],
    }));
    const loaded = loadConfig(dir);
    assert.strictEqual(loaded.config.rooms.length, 1);
    assert.strictEqual(loaded.config.rooms[0].roomId, VALID_ROOM.roomId);
    assert.match(loaded.warning, /2 unusable room record\(s\)/);
  });

  test("a wrong-typed timing falls back for that key alone and is reported", () => {
    writeConfig(dir, JSON.stringify({
      timings: { rpcTimeoutMs: "soon", heartbeatIntervalMs: 20_000 },
    }));
    const loaded = loadConfig(dir);
    assert.strictEqual(loaded.timings.rpcTimeoutMs, DEFAULT_TIMINGS.rpcTimeoutMs);
    assert.strictEqual(loaded.timings.heartbeatIntervalMs, 20_000, "a bad key must not poison its neighbours");
    assert.match(loaded.warning, /rpcTimeoutMs/);
  });

  test("non-positive, non-finite and absurdly small timings are clamped, never adopted", () => {
    writeConfig(dir, JSON.stringify({
      timings: {
        heartbeatMissesBeforeDrop: 0,
        heartbeatIntervalMs: 1,
        rpcTimeoutMs: -5,
        pairingWindowMs: null,
        transferAbsoluteMs: 1e309,
      },
    }));
    const t = loadConfig(dir).timings;
    // 0 misses would drop every peer on the first tick; a 1ms ping interval is a flood.
    assert.strictEqual(t.heartbeatMissesBeforeDrop, DEFAULT_TIMINGS.heartbeatMissesBeforeDrop);
    assert.strictEqual(t.heartbeatIntervalMs, 1_000);
    assert.strictEqual(t.rpcTimeoutMs, DEFAULT_TIMINGS.rpcTimeoutMs);
    assert.strictEqual(t.pairingWindowMs, DEFAULT_TIMINGS.pairingWindowMs);
    assert.strictEqual(t.transferAbsoluteMs, DEFAULT_TIMINGS.transferAbsoluteMs);
    for (const [key, value] of Object.entries(t)) {
      assert.ok(Number.isInteger(value) && value > 0, `${key} must be a positive integer, got ${value}`);
    }
  });

  test("a fractional timing is floored to an integer so no caller re-clamps", () => {
    writeConfig(dir, JSON.stringify({ timings: { rpcTimeoutMs: 12_345.678 } }));
    assert.strictEqual(loadConfig(dir).timings.rpcTimeoutMs, 12_345);
  });

  test("unknown keys are preserved through load and save", () => {
    writeConfig(dir, JSON.stringify({
      terminalName: "mac",
      futureFeature: { enabled: true },
      writtenBy: "some-other-tool",
    }));
    const loaded = loadConfig(dir);
    assert.deepStrictEqual(loaded.config.futureFeature, { enabled: true });
    assert.strictEqual(loaded.config.writtenBy, "some-other-tool");
    assert.strictEqual(loaded.warning, null);

    saveConfig({ currentRoomId: VALID_ROOM.roomId, rooms: [VALID_ROOM] }, dir);
    const after = loadConfig(dir);
    assert.deepStrictEqual(after.config.futureFeature, { enabled: true }, "a round trip must not amputate foreign keys");
    assert.strictEqual(after.config.terminalName, "mac");
    assert.strictEqual(after.config.rooms.length, 1);
    assert.strictEqual(after.config.configVersion, CONFIG_SCHEMA_VERSION);
  });

  test("a v3.4.0 file (no configVersion) migrates silently and keeps every value", () => {
    writeConfig(dir, JSON.stringify({
      terminalName: "old-terminal",
      network: "lan",
      currentRoomId: VALID_ROOM.roomId,
      rooms: [VALID_ROOM],
    }));
    const loaded = loadConfig(dir);
    assert.strictEqual(loaded.migrated, true);
    assert.strictEqual(loaded.warning, null, "a forward migration of a config file must not nag the user");
    assert.strictEqual(loaded.config.configVersion, CONFIG_SCHEMA_VERSION);
    assert.strictEqual(loaded.config.terminalName, "old-terminal");
    assert.deepStrictEqual(resolveCurrentRoom(loaded.config), VALID_ROOM);

    // The migration is only persisted when something else writes; the file is not rewritten on read.
    const onDisk = JSON.parse(fs.readFileSync(path.join(dir, "link.json"), "utf8"));
    assert.strictEqual(onDisk.configVersion, undefined);
    saveConfig({ terminalName: "old-terminal" }, dir);
    assert.strictEqual(
      JSON.parse(fs.readFileSync(path.join(dir, "link.json"), "utf8")).configVersion,
      CONFIG_SCHEMA_VERSION,
    );
  });

  test("a file from a newer build is preserved and warned about, never discarded", () => {
    writeConfig(dir, JSON.stringify({
      configVersion: CONFIG_SCHEMA_VERSION + 7,
      terminalName: "from-the-future",
      rooms: [VALID_ROOM],
    }));
    const loaded = loadConfig(dir);
    assert.strictEqual(loaded.migrated, false);
    assert.strictEqual(loaded.config.terminalName, "from-the-future");
    assert.strictEqual(loaded.config.rooms.length, 1, "downgrading a terminal must not eat its rooms");
    assert.match(loaded.warning, /newer omp-link/);
  });

  test("saveConfig writes 0600 and getTimings picks up the new values after the write", () => {
    saveConfig({ timings: { rpcTimeoutMs: 7_000 } }, dir);
    const mode = fs.statSync(path.join(dir, "link.json")).mode & 0o777;
    assert.strictEqual(mode, 0o600);
    assert.strictEqual(getTimings(dir).rpcTimeoutMs, 7_000);
  });

  test("getTimings returns a copy, so a caller cannot mutate the cached tunables", () => {
    const first = getTimings(dir);
    first.rpcTimeoutMs = 1;
    assert.notStrictEqual(getTimings(dir).rpcTimeoutMs, 1);
  });
});

describe("audit log: vocabulary, sequencing and write failure", () => {
  let dir;

  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-config-audit-"));
  });

  after(() => {
    setCustomAuditLogPath(null);
    setAuditAgentInstanceId(null);
    if (dir && fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  });

  test("records carry a monotonic logSeq and the emitting agentInstanceId", () => {
    setCustomAuditLogPath(path.join(dir, "seq-audit.log"));
    setAuditAgentInstanceId("agent-instance-one");
    appendAuditLog({ type: "pairing_approved", timestamp: Date.now(), principalId: "p1" });
    setAuditAgentInstanceId("agent-instance-two");
    appendAuditLog({ type: "authorization_denied", timestamp: Date.now(), principalId: "p2" });

    const records = readAuditLogs(10);
    assert.strictEqual(records.length, 2);
    assert.ok(records[1].logSeq > records[0].logSeq, "logSeq must increase");
    assert.strictEqual(records[0].agentInstanceId, "agent-instance-one");
    assert.strictEqual(records[1].agentInstanceId, "agent-instance-two");
    // Sibling terminals sharing one log must be distinguishable.
    assert.notStrictEqual(records[0].agentInstanceId, records[1].agentInstanceId);
    assert.strictEqual(getAuditLogStatus().writable, true);
  });

  test("an explicit agentInstanceId on the record is not overwritten by the process default", () => {
    setCustomAuditLogPath(path.join(dir, "explicit-audit.log"));
    setAuditAgentInstanceId("process-default");
    appendAuditLog({ type: "grant_used", timestamp: Date.now(), agentInstanceId: "caller-supplied" });
    assert.strictEqual(readAuditLogs(1)[0].agentInstanceId, "caller-supplied");
  });

  test("a read-only state directory sets the not-writable flag instead of throwing", (t) => {
    if (typeof process.getuid === "function" && process.getuid() === 0) {
      t.skip("root ignores directory permissions");
      return;
    }
    const roDir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-config-ro-"));
    try {
      fs.chmodSync(roDir, 0o500);
      setCustomAuditLogPath(path.join(roDir, "audit.log"));
      assert.strictEqual(getAuditLogStatus().writable, true, "a fresh path starts healthy");

      assert.doesNotThrow(() => {
        appendAuditLog({ type: "authorization_denied", timestamp: Date.now(), principalId: "denied-peer" });
      }, "an unwritable log must never turn a denial into a crash");

      const status = getAuditLogStatus();
      assert.strictEqual(status.writable, false, "the failure must be recorded, not swallowed");
      assert.ok(status.error && status.error.includes("audit.log"), `error should name the file: ${status.error}`);
      assert.strictEqual(fs.existsSync(path.join(roDir, "audit.log")), false);

      // Recovery: once the directory is writable again the next successful write clears the flag.
      fs.chmodSync(roDir, 0o700);
      appendAuditLog({ type: "authorization_denied", timestamp: Date.now(), principalId: "denied-peer" });
      assert.strictEqual(getAuditLogStatus().writable, true);
    } finally {
      fs.chmodSync(roDir, 0o700);
      fs.rmSync(roDir, { recursive: true, force: true });
      setCustomAuditLogPath(null);
    }
  });
});

// ── Tunables must reach the behaviour they name ──────────────────────────────────────────────
//
// `getTimings()` returning the configured number proves nothing on its own: a key can be
// declared, validated and readable while its call site still uses a module constant, and the
// operator who edited link.json gets silence instead of an effect. Every case below writes a
// non-default value and then observes the behaviour it is supposed to change. Where a case
// asserts consuming-object state instead of an effect, the comment says which and why.

function writeTimings(dir, timings) {
  fs.writeFileSync(path.join(dir, "link.json"), JSON.stringify({ timings }));
  clearTimingsCache();
}

function findDeadPid() {
  for (let pid = 65_000; pid > 20_000; pid -= 3) {
    try {
      process.kill(pid, 0);
    } catch (err) {
      if (err.code === "ESRCH") return pid;
    }
  }
  throw new Error("Could not find an unused pid on this machine");
}

function plantOrphan(stateDir, idleMs) {
  const inbox = path.join(stateDir, "inbox", "default");
  fs.mkdirSync(inbox, { recursive: true });
  const owner = fs.mkdtempSync(path.join(inbox, `rx-${findDeadPid()}-${crypto.randomBytes(4).toString("hex")}-`));
  const part = path.join(owner, "abandoned.bin.part");
  fs.writeFileSync(part, "abandoned bytes", { mode: 0o600 });
  const when = (Date.now() - idleMs) / 1000;
  fs.utimesSync(part, when, when);
  return part;
}

const offerFor = (transferId, payload) => ({
  type: "file_offer",
  version: 5,
  id: `off-${transferId}`,
  transferId,
  from: "sender",
  originPrincipalId: "ed25519-sha256:CONFIG_TIMINGS_SENDER",
  to: "receiver",
  filename: "payload.bin",
  sizeBytes: payload.length,
  totalChunks: Math.ceil(payload.length / CHUNK_SIZE),
  sha256: crypto.createHash("sha256").update(payload).digest("hex"),
  ts: Date.now(),
});

const chunkFor = (transferId, payload, index) => ({
  type: "file_chunk",
  version: 5,
  id: `chunk-${transferId}-${index}`,
  transferId,
  from: "sender",
  to: "receiver",
  chunkIndex: index,
  totalChunks: Math.ceil(payload.length / CHUNK_SIZE),
  data: payload.subarray(index * CHUNK_SIZE, (index + 1) * CHUNK_SIZE).toString("base64"),
  ts: Date.now(),
});

describe("tunables: handshake, transfer and grant deadlines are read from link.json", () => {
  const GRANT_PRINCIPAL = "ed25519-sha256:CONFIG_TIMINGS_GRANT";
  let root;
  let hub;
  let control;

  before(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "omp-timings-"));
    setCustomAuditLogPath(path.join(root, "audit.log"));
  });

  after(async () => {
    if (hub) await hub.stop();
    if (control) control.abortAllTransfers();
    revokeGrantsForPrincipal(GRANT_PRINCIPAL, undefined, "timings teardown");
    setCustomAuditLogPath(null);
    clearTimingsCache();
    if (root) fs.rmSync(root, { recursive: true, force: true });
  });

  test("handshakeTimeoutMs closes an idle handshake at the configured deadline", async () => {
    // Observable effect: a peer that completes mutual TLS and then says nothing is closed 4408.
    // At the 1 s floor that happens inside this test instead of at the 10 s default, and the
    // close reason quotes the configured value — a fixed "(10s)" would be a lie once tuned.
    const hubDir = fs.mkdtempSync(path.join(root, "hub-"));
    writeTimings(hubDir, { handshakeTimeoutMs: 1_000 });

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      customOmpDir: hubDir,
      terminalName: "timings-hub",
      workspaceRoot: root,
    });
    await hub.startHub();

    const clientDir = fs.mkdtempSync(path.join(root, "client-"));
    const identity = getOrCreateDeviceIdentity(clientDir);
    const ws = new WebSocket(`wss://127.0.0.1:${hub.port}`, {
      cert: identity.certPem,
      key: identity.keyPem,
      rejectUnauthorized: false,
    });

    const startedAt = Date.now();
    const closed = await new Promise((resolve, reject) => {
      const bail = setTimeout(() => {
        try { ws.terminate(); } catch {}
        reject(new Error("the hub never closed a handshake that said nothing"));
      }, 8_000);
      ws.on("close", (code, reason) => {
        clearTimeout(bail);
        resolve({ code, reason: reason.toString(), elapsedMs: Date.now() - startedAt });
      });
      // A close from the peer surfaces as both events on some platforms; the close is the verdict.
      ws.on("error", () => {});
    });

    assert.strictEqual(closed.code, 4408, `expected a handshake-timeout close, got ${closed.code} ${closed.reason}`);
    assert.match(
      closed.reason,
      /Handshake timeout \(1s\)/,
      "the 4408 reason must report the configured deadline, not a hardcoded 10s",
    );
    assert.ok(
      closed.elapsedMs < 5_000,
      `closed after ${closed.elapsedMs} ms, which is the 10 s default rather than the configured 1 s`,
    );
  });

  test("transferInactivityMs aborts a stalled transfer at the configured deadline", async () => {
    // Observable effect: the stalled transfer is gone, so its next chunk is refused as unknown.
    // The control receiver on default timings still holds its transfer after the same wait —
    // without it this would only prove that time passes.
    const fastDir = fs.mkdtempSync(path.join(root, "tx-fast-"));
    const slowDir = fs.mkdtempSync(path.join(root, "tx-default-"));
    writeTimings(fastDir, { transferInactivityMs: 1_000 });

    const payload = crypto.randomBytes(4_096);
    const fast = new TransferReceiver(fastDir);
    control = new TransferReceiver(slowDir);

    assert.deepStrictEqual(fast.getTransferTimeouts(), {
      inactivityMs: 1_000,
      absoluteMs: DEFAULT_TIMINGS.transferAbsoluteMs,
    });
    assert.strictEqual(fast.handleOffer(offerFor("tx-fast", payload)).ok, true);
    assert.strictEqual(control.handleOffer(offerFor("tx-default", payload)).ok, true);

    await new Promise((r) => setTimeout(r, 1_600));

    const stalled = fast.handleChunk(chunkFor("tx-fast", payload, 0));
    assert.strictEqual(stalled.ok, false, "a transfer idle past the configured inactivity deadline must be gone");
    assert.match(stalled.error, /not found or already terminated/);
    assert.strictEqual(
      control.handleChunk(chunkFor("tx-default", payload, 0)).ok,
      true,
      "a receiver on default timings must still hold its transfer after 1.6 s",
    );
  });

  test("transferAbsoluteMs decides when an abandoned staging file becomes reclaimable", () => {
    // Observable effect, and deliberately clock-free: `cleanupOrphanedParts` reclaims a `.part`
    // owned by a dead pid only once it is idle past the absolute transfer deadline. The
    // configured receiver reclaims a 5-second-idle file; the control on the 120 s default leaves
    // the identical file alone, which is the invariant-13 half that must not regress.
    const fastDir = fs.mkdtempSync(path.join(root, "abs-fast-"));
    const slowDir = fs.mkdtempSync(path.join(root, "abs-default-"));
    writeTimings(fastDir, { transferAbsoluteMs: 1_000 });

    const reclaimable = plantOrphan(fastDir, 5_000);
    const spared = plantOrphan(slowDir, 5_000);

    new TransferReceiver(fastDir); // the sweep runs in the constructor
    new TransferReceiver(slowDir);

    assert.strictEqual(
      fs.existsSync(reclaimable),
      false,
      "a part idle past the configured transferAbsoluteMs must be reclaimed",
    );
    assert.strictEqual(
      fs.existsSync(spared),
      true,
      "the same part is nowhere near the 120 s default deadline and must survive",
    );
  });

  test("grantDefaultMs sets the lifetime of a grant whose approver named no duration", () => {
    // Observable state rather than an effect: observing expiry means waiting out the grant, and
    // the floor is 1 s, so the cheap and exact observation is the lifetime the grant was issued
    // with. `expiresAt` is what every consumer (`checkAndConsumeExecGrant`, `/link devices`)
    // reads, so this is the consumed value, not a restatement of the config.
    const grantDir = fs.mkdtempSync(path.join(root, "grant-"));
    writeTimings(grantDir, { grantDefaultMs: 5_000 });

    const grant = createExecGrant(GRANT_PRINCIPAL, "agent-timings", "timings-peer", { customOmpDir: grantDir });
    const lifetimeMs = grant.expiresAt - grant.createdAt;
    assert.ok(
      Math.abs(lifetimeMs - 5_000) <= 50,
      `grant lifetime was ${lifetimeMs} ms; the configured grantDefaultMs of 5000 never reached it`,
    );
    assert.notStrictEqual(lifetimeMs, DEFAULT_TIMINGS.grantDefaultMs);

    // An explicit duration still wins: the tunable is the default, not a ceiling.
    const explicit = createExecGrant(GRANT_PRINCIPAL, "agent-explicit", "timings-peer", {
      customOmpDir: grantDir,
      durationMs: 30_000,
    });
    assert.ok(Math.abs(explicit.expiresAt - explicit.createdAt - 30_000) <= 50);

    revokeGrantsForPrincipal(GRANT_PRINCIPAL, undefined, "timings test cleanup");
  });
});

describe("tunables: discoveryProbeMs bounds the sweep the extension runs", () => {
  let dir;
  let previousOmpDir;
  let harness;

  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-timings-discover-"));
    previousOmpDir = process.env.OMP_DIR;
    // `index.ts` has no customOmpDir seam: it resolves state through getOmpDir(), so the state
    // root must be in the environment before the extension factory runs.
    process.env.OMP_DIR = dir;
    setCustomAuditLogPath(path.join(dir, "audit.log"));
    clearTimingsCache();

    const tools = new Map();
    const pi = {
      registerFlag() {},
      getFlag() { return undefined; },
      registerTool(spec) { tools.set(spec.name, spec); },
      registerCommand() {},
      registerMessageRenderer() {},
      sendMessage() {},
      on() {},
    };
    extension(pi);
    assert.ok(tools.has("link_discover"), "extension registered no link_discover tool");
    harness = async () => {
      const startedAt = Date.now();
      await tools.get("link_discover").execute("timings-call", {});
      return Date.now() - startedAt;
    };
  });

  after(() => {
    setCustomAuditLogPath(null);
    clearTimingsCache();
    if (previousOmpDir === undefined) delete process.env.OMP_DIR;
    else process.env.OMP_DIR = previousOmpDir;
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  test("a short discoveryProbeMs shortens the real link_discover sweep", async (t) => {
    // Observable effect: the tool is the consumer, and the sweep's own duration is the only
    // thing the budget changes. The default run is measured first and doubles as the guard: an
    // environment where UDP broadcast cannot be sent resolves the sweep immediately, and there
    // no budget is exercised, so there is nothing to observe and the case skips rather than
    // failing for a reason that has nothing to do with the wiring.
    const defaultMs = await harness();
    if (defaultMs < 400) {
      t.skip(`discovery resolved in ${defaultMs} ms on the default budget: this environment does not exercise it`);
      return;
    }

    writeTimings(dir, { discoveryProbeMs: 100 });
    const configuredMs = await harness();

    assert.ok(
      configuredMs < defaultMs / 2,
      `sweep took ${configuredMs} ms with discoveryProbeMs=100 against ${defaultMs} ms on the `
      + `default 1200: the call site is still passing its own literal`,
    );
  });
});
