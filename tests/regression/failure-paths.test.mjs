import { test, describe, before, after } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

import { LinkNode } from "../../src/link-node.js";
import {
  NO_PERMISSIONS,
  DEFAULT_PERMISSIONS,
  FULL_PERMISSIONS,
  SAS_WORD_LIST,
  deriveLocalSas,
  encodeSasWords,
  loadPairedDevices,
  savePairedDevice,
  removePairedDevice,
  normalizeFingerprint,
} from "../../src/identity.js";
import { revokeAllGrants } from "../../src/authorization.js";
import { TransferReceiver, CHUNK_SIZE, ABSOLUTE_TIMEOUT_MS } from "../../src/transfer-receiver.js";
import { readAuditLogs, setCustomAuditLogPath } from "../../src/audit.js";

// Denial, failure and shared-state coverage. Every node here is local to its own describe with
// its own state dirs: the ordered mesh suite must never be able to grant these tests a
// permission they did not ask for, and these tests must never leave a paired device behind.

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function pollUntil(predicate, timeoutMs = 3_000, stepMs = 25) {
  const started = Date.now();
  for (;;) {
    if (await predicate()) return true;
    if (Date.now() - started >= timeoutMs) return false;
    await sleep(stepMs);
  }
}

/** Settles with the promise, or rejects with a labeled error. Turns a hang into a message. */
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

/**
 * A hung RPC keeps a 30s timer alive and would stall the whole file after the failing
 * assertion. Teardown only — never called to mask a failure.
 */
function clearPendingWaiters(node) {
  if (!node) return;
  for (const map of [node.pendingRpcRequests, node.pendingCompactRequests, node.pendingFileAcks]) {
    if (!map) continue;
    for (const pending of map.values()) clearTimeout(pending.timeout);
    map.clear();
  }
}

function deviceRecord(node, deviceName, permissions) {
  return {
    principalId: node.identity.principalId,
    fingerprint: node.identity.fingerprint,
    certPem: node.identity.certPem,
    deviceName,
    permissions,
    pairedAt: Date.now(),
  };
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

// ── R2: a client applies its own capability gate to hub-originated traffic ──────────────────

describe("REGRESSION R2: hub-originated RPC is gated by the client's own permissions", () => {
  const CANARY = "CANARY-SECRET-R2-8f2c1d4a";
  const DENIED_RPCS = [
    { action: "read_file", params: { filePath: "canary.txt" } },
    { action: "git_status", params: {} },
    { action: "git_diff", params: {} },
    { action: "list_dir", params: { filePath: "." } },
    { action: "system_status", params: {} },
  ];

  let dirs;
  let hub;
  let client;
  let hubUrl;

  /** Re-asserts "the hub is granted nothing" on both permission sources the client consults. */
  function denyHubOnClient() {
    savePairedDevice(deviceRecord(hub, "r2-hub", NO_PERMISSIONS), dirs.client);
    // Stored record AND live context: `persistPairedHubIdentity` rewrites the record at
    // authentication time, and the dispatcher prefers the connection context.
    if (client.clientContext) client.clientContext.permissions = NO_PERMISSIONS;
  }

  async function connectDenied() {
    denyHubOnClient();
    const outcome = await client.connectToHub(hubUrl, hub.identity.fingerprint);
    denyHubOnClient();
    const visible = await pollUntil(() =>
      hub.getConnectedTerminalsList().some((t) => t.name === "r2-client"),
    );
    assert.ok(visible, "Hub never saw the client join; test setup failed before asserting denial");
    return outcome;
  }

  before(async () => {
    dirs = makeStateDirs("omp-r2-", ["hub", "client", "workspace"]);
    setCustomAuditLogPath(path.join(dirs.root, "audit.log"));
    revokeAllGrants();
    fs.writeFileSync(path.join(dirs.workspace, "canary.txt"), CANARY);

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.hub,
      terminalName: "r2-hub",
      sessionId: "r2",
    });
    client = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.client,
      terminalName: "r2-client",
      sessionId: "r2",
      workspaceRoot: dirs.workspace,
    });

    await hub.startHub();
    hubUrl = `wss://127.0.0.1:${hub.port}`;

    // The hub trusts the client fully: the only gate under test is the client's.
    savePairedDevice(deviceRecord(client, "r2-client", FULL_PERMISSIONS), dirs.hub);
    await connectDenied();
  });

  after(async () => {
    clearPendingWaiters(hub);
    clearPendingWaiters(client);
    if (client) await client.stop();
    if (hub) await hub.stop();
    revokeAllGrants();
    if (dirs?.root && fs.existsSync(dirs.root)) fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("A NO_PERMISSIONS hub cannot read a canary from the client's workspace", async () => {
    const res = await withDeadline(
      client && hub.executeRemoteRpc("r2-client", "read_file", { filePath: "canary.txt" }),
      10_000,
      "read_file denial hung",
    );

    assert.strictEqual(res.ok, false, `read_file must be denied, got ${JSON.stringify(res)}`);
    assert.ok(
      !JSON.stringify(res).includes(CANARY),
      `Canary leaked to a hub with no permissions: ${JSON.stringify(res)}`,
    );
    assert.strictEqual(
      fs.readFileSync(path.join(dirs.workspace, "canary.txt"), "utf8"),
      CANARY,
      "Canary fixture was modified by the test",
    );
  });

  test("Every inspection action is denied to a NO_PERMISSIONS hub", async () => {
    const leaked = [];
    const allowed = [];

    for (const rpc of DENIED_RPCS) {
      const res = await withDeadline(
        hub.executeRemoteRpc("r2-client", rpc.action, rpc.params),
        10_000,
        `${rpc.action} denial hung`,
      );
      const serialized = JSON.stringify(res);
      if (res.ok !== false) allowed.push(`${rpc.action} -> ${serialized}`);
      if (serialized.includes(CANARY)) leaked.push(rpc.action);
    }

    assert.deepStrictEqual(allowed, [], `Actions permitted with NO_PERMISSIONS: ${allowed.join(" | ")}`);
    assert.deepStrictEqual(leaked, [], `Actions that leaked the canary: ${leaked.join(", ")}`);
  });

  test("Each denial is recorded in the audit log against the hub's principal", () => {
    const denials = readAuditLogs(500).filter(
      (r) => r.type === "authorization_denied" && r.principalId === hub.identity.principalId,
    );

    assert.ok(
      denials.length > 0,
      `No authorization_denied record for the hub principal. Types seen: ${JSON.stringify([
        ...new Set(readAuditLogs(500).map((r) => r.type)),
      ])}`,
    );

    const required = new Set(denials.map((r) => r.required));
    for (const capability of ["readContent", "inspectMetadata", "readDiff", "observe"]) {
      assert.ok(
        required.has(capability),
        `Expected a denial recorded for "${capability}", saw ${JSON.stringify([...required])}`,
      );
    }
  });

  test("A denied RPC fails fast instead of hanging until the 30s timeout", async () => {
    const started = Date.now();
    const res = await withDeadline(
      hub.executeRemoteRpc("r2-client", "read_file", { filePath: "canary.txt" }),
      5_000,
      "Denied RPC never answered (caller left waiting on its own timeout)",
    );
    const elapsed = Date.now() - started;

    assert.strictEqual(res.ok, false, `Expected a fast denial, got ${JSON.stringify(res)}`);
    assert.ok(
      elapsed < 2_000,
      `Denial took ${elapsed}ms; a denied peer must be answered, not dropped`,
    );
  });

  test("Denial holds after the client reconnects with a pinned hub", async () => {
    await client.stop();
    await connectDenied();

    const res = await withDeadline(
      hub.executeRemoteRpc("r2-client", "read_file", { filePath: "canary.txt" }),
      10_000,
      "read_file denial hung after reconnect",
    );

    assert.strictEqual(res.ok, false, `Reconnect restored access: ${JSON.stringify(res)}`);
    assert.ok(!JSON.stringify(res).includes(CANARY), `Canary leaked after reconnect: ${JSON.stringify(res)}`);
  });

  test("A NO_PERMISSIONS hub cannot force a context compaction", async () => {
    let compactInvoked = false;
    client.onCompactRequest = async () => {
      compactInvoked = true;
      return { ok: true };
    };

    const res = await withDeadline(
      hub.requestCompact("r2-client", "trim your context"),
      5_000,
      "compact_request denial hung",
    );

    assert.strictEqual(res.ok, false, `compact must be denied, got ${JSON.stringify(res)}`);
    assert.strictEqual(compactInvoked, false, "Client ran a compaction it never authorized");
  });

  test("With no stored record the client falls back to deny, never to trusting its hub", async () => {
    removePairedDevice(hub.identity.principalId, dirs.client);
    assert.strictEqual(
      loadPairedDevices(dirs.client).size,
      0,
      "Test setup: the client must have no stored record for the hub",
    );
    // Both permission sources are now absent, which is the state a client is in before it has
    // ever recorded anything about its hub. Absence must not resolve to full access.
    if (client.clientContext) client.clientContext.permissions = undefined;

    const res = await withDeadline(
      hub.executeRemoteRpc("r2-client", "read_file", { filePath: "canary.txt" }),
      10_000,
      "read_file denial hung after local revocation",
    );

    assert.strictEqual(res.ok, false, `Unknown hub was granted access: ${JSON.stringify(res)}`);
    assert.ok(!JSON.stringify(res).includes(CANARY), `Canary leaked to an unknown hub: ${JSON.stringify(res)}`);
  });
});

// ── R12: correlated responses are authorized by the pending request ─────────────────────────

describe("REGRESSION R12: a forged rpc_response cannot satisfy a pending request", () => {
  const FORGED = "FORGED-RPC-RESULT-do-not-accept";
  let dirs;
  let hub;
  let client;

  function hubSocketFor(displayName) {
    for (const [socket, ctx] of hub.hubConnections) {
      if (ctx.displayName === displayName) return socket;
    }
    return null;
  }

  /**
   * Starts a real RPC, then injects a response frame straight onto the hub's socket (bypassing
   * `sendApplicationFrame`, exactly as a malicious relay would). The genuine answer is a
   * guaranteed failure, so any success can only have come from the forgery.
   *
   * Liveness is deliberately NOT asserted: the forger here is the relay itself, which can
   * always withhold the genuine answer (and the inbound dedupe cache is keyed by frame id, so
   * a forgery burns the id). The property under test is that the forged payload is never
   * accepted.
   */
  async function raceForgedResponse(extraFields) {
    // A dropped forgery leaves its request pending for good (the relay withheld the answer), so
    // the id under test is the one this call added, not "the only one".
    const before = new Set(client.pendingRpcRequests.keys());
    const pending = client.executeRemoteRpc("r12-hub", "read_file", {
      filePath: "no-such-file-please-do-not-create.txt",
    });
    const added = [...client.pendingRpcRequests.keys()].filter((id) => !before.has(id));
    assert.strictEqual(added.length, 1, `Expected one new pending RPC id, got ${JSON.stringify(added)}`);

    const socket = hubSocketFor("r12-client");
    assert.ok(socket, "Test setup: no hub socket for the client");
    socket.send(
      JSON.stringify({
        type: "rpc_response",
        version: 5,
        id: added[0],
        from: "r12-hub",
        to: "r12-client",
        ok: true,
        result: FORGED,
        ts: Date.now(),
        ...extraFields,
      }),
    );

    try {
      const value = await withDeadline(pending, 3_000, "unsettled");
      return { status: "fulfilled", value };
    } catch (err) {
      return { status: "rejected", error: err };
    } finally {
      clearPendingWaiters(client);
    }
  }

  before(async () => {
    dirs = makeStateDirs("omp-r12-", ["hub", "client", "workspace"]);
    setCustomAuditLogPath(path.join(dirs.root, "audit.log"));
    revokeAllGrants();

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.hub,
      terminalName: "r12-hub",
      sessionId: "r12",
      workspaceRoot: dirs.workspace,
    });
    client = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.client,
      terminalName: "r12-client",
      sessionId: "r12",
      workspaceRoot: dirs.workspace,
    });

    await hub.startHub();
    savePairedDevice(deviceRecord(client, "r12-client", FULL_PERMISSIONS), dirs.hub);
    savePairedDevice(deviceRecord(hub, "r12-hub", FULL_PERMISSIONS), dirs.client);
    await client.connectToHub(`wss://127.0.0.1:${hub.port}`, hub.identity.fingerprint);
    const ready = await pollUntil(() => hub.getConnectedTerminalsList().some((t) => t.name === "r12-client"));
    assert.ok(ready, "Test setup: client never authenticated");
  });

  after(async () => {
    clearPendingWaiters(hub);
    clearPendingWaiters(client);
    if (client) await client.stop();
    if (hub) await hub.stop();
    revokeAllGrants();
    if (dirs?.root && fs.existsSync(dirs.root)) fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("A response with no originPrincipalId is dropped and audited", async () => {
    const settled = await raceForgedResponse({});

    if (settled.status === "fulfilled") {
      assert.notStrictEqual(
        settled.value.result,
        FORGED,
        "An unauthenticated response frame satisfied a pending RPC",
      );
      assert.strictEqual(
        settled.value.originPrincipalId,
        hub.identity.principalId,
        "An accepted response must carry the authenticated origin of the answering peer",
      );
    }

    assert.ok(
      readAuditLogs(500).some((r) => r.type === "rpc_response_origin_mismatch"),
      `Expected an rpc_response_origin_mismatch record, saw ${JSON.stringify([
        ...new Set(readAuditLogs(500).map((r) => r.type)),
      ])}`,
    );
  });

  test("A response carrying a foreign originPrincipalId is dropped", async () => {
    const foreign = `ed25519-sha256:${normalizeFingerprint(crypto.randomBytes(32).toString("hex"))}`;
    const settled = await raceForgedResponse({ originPrincipalId: foreign });

    if (settled.status === "fulfilled") {
      assert.notStrictEqual(settled.value.result, FORGED, "A foreign-origin response satisfied a pending RPC");
    }
    assert.ok(
      readAuditLogs(500).some(
        (r) => r.type === "rpc_response_origin_mismatch" && r.actualPrincipalId === foreign,
      ),
      "Expected the foreign principal to be named in the audit record",
    );
  });
});

// ── R12 liveness: origin checks must not break honest relaying ───────────────────────────────

describe("REGRESSION R12: legitimate correlated answers still resolve", () => {
  const RELAY_CANARY = "RELAY-ANSWER-4d91ba";
  let dirs;
  let hub;
  let alpha;
  let beta;

  async function joinAsPeer(node, label, dir) {
    savePairedDevice(deviceRecord(node, label, FULL_PERMISSIONS), dirs.hub);
    await node.connectToHub(`wss://127.0.0.1:${hub.port}`, hub.identity.fingerprint);
    // This peer explicitly grants its hub inspection rights; the relayed request is carried on
    // the hub connection, so without this the target's own gate would (correctly) deny it.
    savePairedDevice(deviceRecord(hub, "relay-hub", FULL_PERMISSIONS), dir);
    if (node.clientContext) node.clientContext.permissions = FULL_PERMISSIONS;
  }

  before(async () => {
    dirs = makeStateDirs("omp-relay-", ["hub", "alpha", "beta", "hub-workspace", "beta-workspace"]);
    setCustomAuditLogPath(path.join(dirs.root, "audit.log"));
    revokeAllGrants();
    fs.writeFileSync(path.join(dirs["beta-workspace"], "relay-canary.txt"), RELAY_CANARY);

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.hub,
      terminalName: "relay-hub",
      sessionId: "relay",
      workspaceRoot: dirs["hub-workspace"],
    });
    alpha = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.alpha,
      terminalName: "relay-alpha",
      sessionId: "relay",
    });
    beta = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.beta,
      terminalName: "relay-beta",
      sessionId: "relay",
      workspaceRoot: dirs["beta-workspace"],
    });

    await hub.startHub();
    await joinAsPeer(alpha, "relay-alpha", dirs.alpha);
    await joinAsPeer(beta, "relay-beta", dirs.beta);
    const ready = await pollUntil(() => {
      const names = hub.getConnectedTerminalsList().map((t) => t.name);
      return names.includes("relay-alpha") && names.includes("relay-beta");
    });
    assert.ok(ready, "Test setup: both peers must be authenticated on the hub");
  });

  after(async () => {
    for (const node of [alpha, beta, hub]) {
      clearPendingWaiters(node);
      if (node) await node.stop();
    }
    revokeAllGrants();
    if (dirs?.root && fs.existsSync(dirs.root)) fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("Peer alpha receives peer beta's answer, attributed to beta", async () => {
    const res = await withDeadline(
      alpha.executeRemoteRpc("relay-beta", "read_file", { filePath: "relay-canary.txt" }),
      10_000,
      "A legitimate relayed response never resolved",
    );

    assert.strictEqual(res.ok, true, `Relayed RPC failed: ${JSON.stringify(res)}`);
    assert.strictEqual(res.result, RELAY_CANARY);
    assert.strictEqual(
      res.originPrincipalId,
      beta.identity.principalId,
      "A relayed answer must stay attributed to the peer that produced it, not to the relay",
    );
  });

  test("The hub's own answer resolves on the caller, attributed to the hub", async () => {
    // Deliberately not a file read: `registeredWorkspaces` is a process-global registry keyed
    // by "default", so two in-process nodes cannot both own that id.
    const res = await withDeadline(
      alpha.executeRemoteRpc("relay-hub", "system_status"),
      10_000,
      "A hub-answered RPC never resolved on the client",
    );

    assert.strictEqual(res.ok, true, `Hub RPC failed: ${JSON.stringify(res)}`);
    assert.strictEqual(res.result.hubPrincipalId, hub.identity.principalId);
    assert.strictEqual(res.originPrincipalId, hub.identity.principalId);
  });

  test("A hub-answered compact_response resolves and carries the hub's origin", async () => {
    let asked = false;
    hub.onCompactRequest = async () => {
      asked = true;
      return { ok: true };
    };

    const res = await withDeadline(
      alpha.requestCompact("relay-hub", "trim context"),
      10_000,
      "compact_response never resolved on the client (correlated answers need an authenticated origin)",
    );

    assert.strictEqual(asked, true, "Hub never ran the compaction");
    assert.strictEqual(res.ok, true, `compact failed: ${JSON.stringify(res)}`);
    assert.strictEqual(
      res.originPrincipalId,
      hub.identity.principalId,
      "Every correlated response must carry the authenticated origin of its answerer",
    );
  });
});

// ── R3: pairing fails closed without a verified SAS ─────────────────────────────────────────

describe("REGRESSION R3: pairing without a verified SAS pairs nobody", () => {
  let roots = [];
  let liveNodes = [];

  after(async () => {
    // Nodes are registered at construction, not on success: a failed handshake must not leave a
    // listening hub behind holding the whole test file's event loop open.
    for (const node of liveNodes) {
      clearPendingWaiters(node);
      await node.stop();
    }
    liveNodes = [];
    for (const root of roots) {
      if (fs.existsSync(root)) fs.rmSync(root, { recursive: true, force: true });
    }
    roots = [];
  });

  /** Brings an unpaired client to the point where the host is asked to approve. */
  async function startPairingAttempt(label) {
    const dirs = makeStateDirs(`omp-${label}-`, ["hub", "client"]);
    roots.push(dirs.root);
    setCustomAuditLogPath(path.join(dirs.root, "audit.log"));

    const hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.hub,
      terminalName: `${label}-hub`,
      sessionId: label,
    });
    const client = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.client,
      terminalName: `${label}-client`,
      sessionId: label,
    });
    liveNodes.push(hub, client);

    await hub.startHub();

    let request = null;
    hub.onPairingRequested = (req) => { request = req; };

    const outcome = await withDeadline(
      client.connectToHub(`wss://127.0.0.1:${hub.port}`),
      10_000,
      "connectToHub never settled for an unpaired client",
    );
    const asked = await pollUntil(() => request !== null);
    assert.ok(asked, "Hub never raised a pairing request");

    return { dirs, hub, client, request, outcome };
  }

  test("An unpaired connect settles as pairing-required with a four-word code", async () => {
    const attempt = await startPairingAttempt("r3-required");
    try {
      assert.strictEqual(
        attempt.outcome?.state,
        "pairing-required",
        `Expected {state:"pairing-required"}, got ${JSON.stringify(attempt.outcome)}`,
      );
      assert.match(attempt.outcome.sasCode, /^[A-Za-z]+-[A-Za-z]+-[A-Za-z]+-[A-Za-z]+$/);
      assert.strictEqual(attempt.client.isAuthenticated, false, "Pairing-required must not be authenticated");
      assert.strictEqual(loadPairedDevices(attempt.dirs.hub).size, 0, "Nothing may be paired yet");
    } finally {
      await attempt.client.stop();
      await attempt.hub.stop();
    }
  });

  test("approvePairing with no code returns null and pairs nobody", async () => {
    const attempt = await startPairingAttempt("r3-nocode");
    try {
      const paired = attempt.hub.approvePairing(attempt.request.id, FULL_PERMISSIONS);

      assert.strictEqual(paired, null, `Approval without a SAS code must fail closed, got ${JSON.stringify(paired)}`);
      assert.strictEqual(loadPairedDevices(attempt.dirs.hub).size, 0, "A device was pinned without SAS verification");
      await sleep(300);
      assert.strictEqual(attempt.client.isAuthenticated, false, "Client authenticated without SAS verification");
      assert.ok(
        readAuditLogs(200).some((r) => r.type === "pairing_rejected_missing_sas"),
        `Expected a pairing_rejected_missing_sas record, saw ${JSON.stringify([
          ...new Set(readAuditLogs(200).map((r) => r.type)),
        ])}`,
      );
    } finally {
      await attempt.client.stop();
      await attempt.hub.stop();
    }
  });

  test("approvePairing with a wrong code returns null, pairs nobody and denies the peer", async () => {
    const attempt = await startPairingAttempt("r3-wrongcode");
    try {
      const wrong = "ACORN-ACORN-ACORN-ACORN";
      assert.notStrictEqual(attempt.request.sasCode, wrong, "Test setup: the wrong code must differ");

      const paired = attempt.hub.approvePairing(attempt.request.id, FULL_PERMISSIONS, wrong);

      assert.strictEqual(paired, null, `A mismatched SAS must fail closed, got ${JSON.stringify(paired)}`);
      assert.strictEqual(loadPairedDevices(attempt.dirs.hub).size, 0, "A device was pinned with a mismatched SAS");

      const disconnected = await pollUntil(() => attempt.client.role === "disconnected");
      assert.ok(
        disconnected,
        `A rejected pairing must drop the connection, client role is "${attempt.client.role}"`,
      );
      assert.strictEqual(attempt.client.isAuthenticated, false);
    } finally {
      await attempt.client.stop();
      await attempt.hub.stop();
    }
  });

  test("deriveLocalSas refuses to invent a code without a TLS exporter", () => {
    const spki = crypto.randomBytes(44);
    const hubNonce = crypto.randomBytes(32);
    const clientNonce = crypto.randomBytes(32);

    for (const socket of [null, undefined, {}, { exportKeyingMaterial: "not-a-function" }]) {
      assert.throws(
        () => deriveLocalSas(socket, spki, spki, hubNonce, clientNonce),
        /PAIRING_UNSUPPORTED_RUNTIME/,
        `A socket without an exporter (${JSON.stringify(socket)}) must not yield a SAS code`,
      );
    }
  });
});

// ── R4: the SAS word list is a wire encoding, not a display list ────────────────────────────

describe("REGRESSION R4: SAS dictionary covers every byte", () => {
  test("The list holds exactly 256 unique frozen words", () => {
    assert.strictEqual(SAS_WORD_LIST.length, 256, `encodeSasWords indexes raw bytes 0-255`);
    assert.strictEqual(new Set(SAS_WORD_LIST).size, 256, "Duplicate words collapse distinct codes");
    assert.throws(() => { SAS_WORD_LIST[0] = "TAMPERED"; }, TypeError, "The wire encoding must be frozen");
  });

  test("No byte value renders as undefined", () => {
    const bad = [];
    for (let byte = 0; byte <= 255; byte++) {
      if (typeof SAS_WORD_LIST[byte] !== "string" || SAS_WORD_LIST[byte].length === 0) bad.push(byte);
      const code = encodeSasWords(Buffer.from([byte, byte, byte, byte]));
      if (code.includes("undefined")) bad.push(byte);
    }
    assert.deepStrictEqual(bad, [], `Bytes rendering as undefined: ${bad.join(", ")}`);
  });
});

// ── R5: two receivers share one state dir ───────────────────────────────────────────────────

describe("REGRESSION R5: a second receiver must not destroy an in-flight transfer", () => {
  let dirs;

  const listParts = (root) => {
    const found = [];
    const walk = (dir) => {
      if (!fs.existsSync(dir)) return;
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.name.endsWith(".part")) found.push(full);
      }
    };
    walk(path.join(root, "inbox"));
    return found.sort();
  };

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

  const offerFor = (transferId, payload, from) => ({
    type: "file_offer",
    version: 5,
    id: `off-${transferId}`,
    transferId,
    from,
    originPrincipalId: `ed25519-sha256:${from.toUpperCase()}`,
    to: "receiver",
    filename: "payload.bin",
    sizeBytes: payload.length,
    totalChunks: Math.ceil(payload.length / CHUNK_SIZE),
    sha256: crypto.createHash("sha256").update(payload).digest("hex"),
    ts: Date.now(),
  });

  const chunkFor = (transferId, payload, index, from) => ({
    type: "file_chunk",
    version: 5,
    id: `chunk-${transferId}-${index}`,
    transferId,
    from,
    to: "receiver",
    chunkIndex: index,
    totalChunks: Math.ceil(payload.length / CHUNK_SIZE),
    data: payload.subarray(index * CHUNK_SIZE, (index + 1) * CHUNK_SIZE).toString("base64"),
    ts: Date.now(),
  });

  before(() => {
    dirs = makeStateDirs("omp-r5-", ["shared", "orphans"]);
    setCustomAuditLogPath(path.join(dirs.root, "audit.log"));
  });

  after(() => {
    if (dirs?.root && fs.existsSync(dirs.root)) fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("Constructing a second receiver leaves the first receiver's transfer intact", () => {
    const payload = crypto.randomBytes(CHUNK_SIZE + 4_096); // 2 chunks
    const transferId = "tx-shared-state";
    const first = new TransferReceiver(dirs.shared);

    assert.strictEqual(first.handleOffer(offerFor(transferId, payload, "peer-a")).ok, true);
    assert.strictEqual(first.handleChunk(chunkFor(transferId, payload, 0, "peer-a")).ok, true);

    const partsBefore = listParts(dirs.shared);
    assert.strictEqual(partsBefore.length, 1, "Test setup: expected exactly one in-flight .part");

    // A second terminal on the same machine constructs its own receiver over the same state dir.
    const second = new TransferReceiver(dirs.shared);

    assert.deepStrictEqual(
      listParts(dirs.shared),
      partsBefore,
      "A second receiver deleted a live .part; writes then continue into an unlinked inode",
    );

    const res = first.handleChunk(chunkFor(transferId, payload, 1, "peer-a"));
    assert.strictEqual(res.ok, true, `Final chunk failed: ${res.error}`);
    assert.strictEqual(res.complete, true, "Transfer never completed");
    assert.ok(fs.existsSync(res.finalPath), `Received file missing at ${res.finalPath}`);
    assert.ok(
      fs.readFileSync(res.finalPath).equals(payload),
      "Received file content does not match the sent payload",
    );

    second.abortAllTransfers();
    first.abortAllTransfers();
  });

  test("A part owned by a dead pid and idle past the deadline is reclaimed", () => {
    const inbox = path.join(dirs.orphans, "inbox", "default");
    fs.mkdirSync(inbox, { recursive: true });

    const deadPid = findDeadPid();
    const orphanDir = fs.mkdtempSync(path.join(inbox, `rx-${deadPid}-${crypto.randomBytes(4).toString("hex")}-`));
    const orphanPart = path.join(orphanDir, "abandoned.bin.part");
    fs.writeFileSync(orphanPart, "abandoned bytes");
    const idleSince = (Date.now() - ABSOLUTE_TIMEOUT_MS - 60_000) / 1000;
    fs.utimesSync(orphanPart, idleSince, idleSince);

    const receiver = new TransferReceiver(dirs.orphans);
    receiver.cleanupOrphanedParts();

    assert.strictEqual(
      fs.existsSync(orphanPart),
      false,
      "An abandoned .part whose owner pid is dead must be reclaimed",
    );
  });

  test("A part owned by a live pid is never reclaimed, however idle", () => {
    const inbox = path.join(dirs.orphans, "inbox", "default");
    fs.mkdirSync(inbox, { recursive: true });

    const liveDir = fs.mkdtempSync(path.join(inbox, `rx-${process.pid}-${crypto.randomBytes(4).toString("hex")}-`));
    const livePart = path.join(liveDir, "in-flight.bin.part");
    fs.writeFileSync(livePart, "still being written");
    const idleSince = (Date.now() - ABSOLUTE_TIMEOUT_MS - 60_000) / 1000;
    fs.utimesSync(livePart, idleSince, idleSince);

    const receiver = new TransferReceiver(dirs.orphans);
    receiver.cleanupOrphanedParts();

    assert.strictEqual(
      fs.existsSync(livePart),
      true,
      "A .part owned by a live process must survive cleanup regardless of its mtime",
    );
  });
});

// ── R8: "connected" means authenticated ─────────────────────────────────────────────────────

describe("REGRESSION R8: connectToHub settles on authentication, not on socket open", () => {
  let dirs;
  let hub;
  let client;

  before(async () => {
    dirs = makeStateDirs("omp-r8-", ["hub", "client"]);
    setCustomAuditLogPath(path.join(dirs.root, "audit.log"));

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.hub,
      terminalName: "r8-hub",
      sessionId: "r8",
    });
    client = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.client,
      terminalName: "r8-client",
      sessionId: "r8",
    });

    await hub.startHub();
    savePairedDevice(deviceRecord(client, "r8-client", DEFAULT_PERMISSIONS), dirs.hub);
    savePairedDevice(deviceRecord(hub, "r8-hub", DEFAULT_PERMISSIONS), dirs.client);
  });

  after(async () => {
    clearPendingWaiters(hub);
    clearPendingWaiters(client);
    if (client) await client.stop();
    if (hub) await hub.stop();
    if (dirs?.root && fs.existsSync(dirs.root)) fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("A pre-paired connect resolves authenticated, with no settling delay", async () => {
    const outcome = await withDeadline(
      client.connectToHub(`wss://127.0.0.1:${hub.port}`, hub.identity.fingerprint),
      10_000,
      "connectToHub never settled",
    );

    assert.deepStrictEqual(
      outcome,
      { state: "authenticated" },
      `Expected {state:"authenticated"}, got ${JSON.stringify(outcome)}`,
    );
    assert.strictEqual(
      client.isAuthenticated,
      true,
      "connectToHub resolved while the connection was still unauthenticated",
    );
    assert.strictEqual(client.role, "client");
  });

  test("The client roster matches the hub roster", async () => {
    const names = (node) => node.getConnectedTerminalsList().map((t) => t.name).sort();
    const hubNames = names(hub);

    const converged = await pollUntil(
      () => JSON.stringify(names(client)) === JSON.stringify(hubNames),
      2_000,
    );

    assert.ok(
      converged,
      `Client roster ${JSON.stringify(names(client))} never matched hub roster ${JSON.stringify(hubNames)}`,
    );
    assert.deepStrictEqual(names(client), ["r8-client", "r8-hub"]);
  });

  test("A fingerprint mismatch rejects instead of connecting unpinned", async () => {
    const bogus = normalizeFingerprint(crypto.randomBytes(32).toString("hex"));
    const stray = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      networkMode: "loopback",
      customOmpDir: dirs.client,
      terminalName: "r8-stray",
      sessionId: "r8",
    });

    try {
      await assert.rejects(
        () => withDeadline(stray.connectToHub(`wss://127.0.0.1:${hub.port}`, bogus), 10_000, "pin mismatch hung"),
        (err) => {
          assert.match(err.message, /fingerprint|pin/i, `Unexpected rejection: ${err.message}`);
          return true;
        },
      );
      assert.strictEqual(stray.isAuthenticated, false);
    } finally {
      clearPendingWaiters(stray);
      await stray.stop();
    }
  });
});
