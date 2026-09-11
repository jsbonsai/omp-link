import { test, describe, before, after } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

import extension from "../../index.js";
import { LinkNode } from "../../src/link-node.js";
import {
  DEFAULT_PERMISSIONS,
  FULL_PERMISSIONS,
  SAS_WORD_LIST,
  loadPairedDevices,
  savePairedDevice,
} from "../../src/identity.js";
import { registerWorkspace } from "../../src/inspection.js";
import { createExecGrant, getActiveGrants, revokeAllGrants } from "../../src/authorization.js";
import { readAuditLogs, setCustomAuditLogPath } from "../../src/audit.js";

// Human misuse coverage. The rest of the suite drives the protocol correctly and asserts that
// correct protocol behaviour follows. Nothing in it drives the product the way a person does:
// out of order, twice, with a typo, or after changing their mind. Every assertion here is on
// something a human can see — a returned tool result, a rendered notification, a stored record
// or an audit event — never on a private field.
//
// Pairing initiation is rate limited to 10/min per remote address *per hub node*, so each group
// gets its own hub rather than sharing one and going red on the eleventh pairing.

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function pollUntil(predicate, timeoutMs = 5_000, stepMs = 25) {
  const started = Date.now();
  for (;;) {
    if (await predicate()) return true;
    if (Date.now() - started >= timeoutMs) return false;
    await sleep(stepMs);
  }
}

/** A port nothing is listening on: bound, read, released. */
async function reserveDeadPort() {
  return await new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.on("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
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

/** Exactly the comparison `approvePairing` performs (link-node.ts:1013-1017). */
const normalizeSas = (code) => code.replace(/[^a-zA-Z0-9]/g, "").toUpperCase();

/**
 * Same four words, different order. Returns null only if all four words are identical, in
 * which case no reordering is observable at all (p ≈ 6e-8 per draw).
 */
function swapTwoWords(code) {
  const words = code.split("-");
  for (let i = 0; i < words.length; i++) {
    for (let j = i + 1; j < words.length; j++) {
      if (words[i] !== words[j]) {
        const swapped = [...words];
        [swapped[i], swapped[j]] = [swapped[j], swapped[i]];
        return swapped.join("-");
      }
    }
  }
  return null;
}

/** One word replaced by a different dictionary word; the other three are right. */
function oneWordWrong(code) {
  const words = code.split("-");
  words[3] = SAS_WORD_LIST.find((w) => w !== words[3]);
  return words.join("-");
}

async function connectFreshClient(hubUrl, root, terminalName) {
  const dir = fs.mkdtempSync(path.join(root, "client-"));
  const client = new LinkNode({ port: 0, customOmpDir: dir, terminalName, workspaceRoot: root });
  const outcome = await client.connectToHub(hubUrl);
  return { client, dir, outcome };
}

/**
 * The extension under a fake host. `index.ts` keeps every command, tool and piece of session
 * state inside one closure, so this is the only way to drive `/link` the way a person does.
 * The double-load guard (`globalThis.__omp_link_loaded`) means exactly one harness per process.
 */
function makeExtensionHarness() {
  const notices = [];
  const messages = [];
  const tools = new Map();
  const commands = new Map();

  const pi = {
    registerFlag() {},
    getFlag() {
      return undefined;
    },
    registerTool(spec) {
      tools.set(spec.name, spec);
    },
    registerCommand(name, spec) {
      commands.set(name, spec);
    },
    registerMessageRenderer() {},
    sendMessage(msg) {
      messages.push(msg);
    },
    on() {},
  };

  const ctx = {
    ui: {
      notify: (text, level) => notices.push({ text, level }),
      setStatus() {},
      confirm: async () => false,
      select: async () => null,
    },
  };

  extension(pi);
  assert.ok(commands.has("link"), "extension registered no /link command");

  return {
    notices,
    messages,
    reset() {
      notices.length = 0;
      messages.length = 0;
    },
    async run(args) {
      await commands.get("link").handler(args, ctx);
      return notices[notices.length - 1] || { text: "", level: "none" };
    },
    async tool(name, params = {}) {
      const res = await tools.get(name).execute("human-flow-call", params);
      return { text: res.content[0].text, details: res.details };
    },
  };
}

// ── H1-H14: the /link surface, driven the way a person drives it ────────────────────────────

describe("HUMAN: /link answers the state the user is actually in", () => {
  let dirs;
  let hub;
  let hubUrl;
  let deadPort;
  let staleRoom;
  let h;
  let previousOmpDir;
  const pairingRequests = [];

  before(async () => {
    dirs = makeStateDirs("human-ext-", ["ext", "hub", "workspace"]);
    previousOmpDir = process.env.OMP_DIR;
    // The extension has no customOmpDir seam: it resolves state through getOmpDir(), which
    // reads OMP_DIR. This must be set before the factory runs, and restored afterwards.
    process.env.OMP_DIR = dirs.ext;
    setCustomAuditLogPath(path.join(dirs.root, "audit.log"));

    deadPort = await reserveDeadPort();
    staleRoom = {
      roomId: crypto.randomUUID(),
      label: "ghost-room",
      hubPrincipalId: `ed25519-sha256:${new Array(32).fill("AA").join(":")}`,
      hubFingerprint: new Array(32).fill("AA").join(":"),
      endpoint: `127.0.0.1:${deadPort}`,
      lastJoinedAt: Date.now() - 60_000,
    };
    // `currentRoom` is resolved once, when the extension loads. A stale room has to be on disk
    // before that, exactly as it would be after the hosting machine went away overnight.
    fs.writeFileSync(
      path.join(dirs.ext, "link.json"),
      JSON.stringify({ terminalName: "human-ext", currentRoomId: staleRoom.roomId, rooms: [staleRoom] }),
    );

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      customOmpDir: dirs.hub,
      terminalName: "hub-human",
      workspaceRoot: dirs.workspace,
    });
    hub.onPairingRequested = (req) => pairingRequests.push(req);
    await hub.startHub();
    hubUrl = `127.0.0.1:${hub.port}`;

    h = makeExtensionHarness();
  });

  after(async () => {
    if (hub) await hub.stop();
    revokeAllGrants("human-flows teardown");
    if (previousOmpDir === undefined) delete process.env.OMP_DIR;
    else process.env.OMP_DIR = previousOmpDir;
    if (dirs?.root) fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("H1: accept before any device has asked to pair says who approves, not 'not found'", async () => {
    const notice = await h.run("accept 1 ALPHA-BRAVO-CHARLIE-DELTA");
    assert.strictEqual(notice.level, "warning");
    assert.match(notice.text, /not hosting a room/);
    assert.match(notice.text, /no pairing requests to approve/);
    assert.strictEqual(loadPairedDevices(dirs.ext).size, 0, "nothing may be paired by an accept with no request");
  });

  test("H2: deny for an id that never existed refuses without inventing a device", async () => {
    const notice = await h.run("deny 4242");
    assert.strictEqual(notice.level, "warning");
    assert.match(notice.text, /not hosting a room/);
    assert.match(notice.text, /no pairing requests to refuse/);
  });

  test("H3: end when not hosting points at the verb that does apply", async () => {
    const notice = await h.run("end");
    assert.strictEqual(notice.level, "warning");
    assert.match(notice.text, /not hosting a room/);
    assert.match(notice.text, /\/link off/);
  });

  test("H4: invite when not hosting refuses and names the prerequisite", async () => {
    const notice = await h.run("invite");
    assert.strictEqual(notice.level, "warning");
    assert.match(notice.text, /Only the hosting terminal can issue invites/);
    assert.match(notice.text, /\/link create/);
  });

  test("H5: revoke a device that was never paired names the string the user typed", async () => {
    const notice = await h.run("revoke ghost-laptop");
    assert.strictEqual(notice.level, "error");
    assert.match(notice.text, /Device "ghost-laptop" not found/);
  });

  test("H6: devices allow for an unknown device changes nothing", async () => {
    const notice = await h.run("devices allow ghost-laptop metadata");
    assert.strictEqual(notice.level, "error");
    assert.match(notice.text, /Device "ghost-laptop" not found/);
    assert.strictEqual(loadPairedDevices(dirs.ext).size, 0);
  });

  test("H7: grant for a paired device that is not connected issues no grant", async () => {
    savePairedDevice(deviceRecord(hub, "offline-peer", FULL_PERMISSIONS), dirs.ext);
    assert.strictEqual(loadPairedDevices(dirs.ext).size, 1, "test setup: one paired device on disk");

    const notice = await h.run("grant offline-peer");
    assert.strictEqual(notice.level, "warning");
    // The device is real and offline; the link is off, which is the first honest reason.
    assert.match(notice.text, /Link is off|not connected right now/);
    assert.strictEqual(getActiveGrants().length, 0, "an offline device must not receive a grant");
  });

  test("H8: tools refuse while the link is off and never blame a missing peer", async () => {
    const calls = [
      ["link_send", { to: "somebody", message: "hello" }],
      ["link_exec", { to: "somebody", action: "git_status" }],
      ["link_list", {}],
    ];
    for (const [name, params] of calls) {
      const res = await h.tool(name, params);
      assert.match(res.text, /^Link is off\./, `${name} must name the link state`);
      assert.match(res.text, /\/link join|\/link create/, `${name} must say what to do next`);
      assert.doesNotMatch(
        res.text,
        /peer not found|not found|offline|no such/i,
        `${name} must not claim the peer is missing when the link itself is off`,
      );
    }
  });

  test("H9: off when already off is idempotent, and still takes any live grant with it", async () => {
    // A grant outliving the /link off that was supposed to stand this agent down is the whole
    // point of the verb; "already off" must not become a reason to skip the revocation.
    createExecGrant("ed25519-sha256:HUMAN_FLOWS_H9", "agent-h9", "phantom-peer", {
      maxUses: 5,
      durationMs: 60_000,
    });
    assert.strictEqual(getActiveGrants().length, 1, "test setup: one live grant");

    const first = await h.run("off");
    assert.strictEqual(getActiveGrants().length, 0, "/link off must revoke every live command grant");
    const second = await h.run("off");
    for (const notice of [first, second]) {
      assert.strictEqual(notice.level, "info");
      assert.match(notice.text, /already off|Left the room/);
    }
    assert.match(second.text, /Link was already off/);
    const status = await h.tool("link_status");
    assert.strictEqual(status.details.state, "off");
    assert.strictEqual(status.details.usable, false);
  });

  test("H10: a fat-fingered request id is refused with the usage and approves nothing", async () => {
    const before = loadPairedDevices(dirs.ext).size;

    // Two surfaces print the usage line and they disagree on the placeholder: the handler says
    // "<request-id>" (index.ts:1253) and the argument parser says "<id>" (command-registry.mjs).
    // Both are accepted here; the divergence is reported as P3, not pinned as correct.
    const USAGE = /Usage: \/link accept <(?:request-)?id> <code>/;

    const nonNumeric = await h.run("accept abc ALPHA-BRAVO-CHARLIE-DELTA");
    assert.match(nonNumeric.text, /is not a pairing request id/);
    assert.match(nonNumeric.text, USAGE);

    const zero = await h.run("accept 0 ALPHA-BRAVO-CHARLIE-DELTA");
    assert.match(zero.text, /is not a pairing request id/);

    // A negative id is rejected by the argument parser as a flag. The wording is the parser's,
    // but the outcome a human needs is the same: refused, with the usage line.
    const negative = await h.run("accept -1 ALPHA-BRAVO-CHARLIE-DELTA");
    assert.match(negative.text, USAGE);

    // The code renders as WORD-WORD-WORD-WORD; typing it with spaces is the obvious mistake.
    const spaced = await h.run("accept 1 ALPHA BRAVO CHARLIE DELTA");
    assert.match(spaced.text, /Unexpected argument/);
    assert.match(spaced.text, USAGE);

    // A device name starting with "-" is read as a flag, and must be refused, not guessed at.
    const dashName = await h.run("devices show -weird-laptop");
    assert.match(dashName.text, /Unknown flag|Usage: \/link devices/);

    assert.strictEqual(loadPairedDevices(dirs.ext).size, before, "no malformed accept may pair anything");
  });

  test("H11: a room record pointing at a dead endpoint fails by name and never falls back to hosting", async () => {
    const notice = await h.run("on");
    assert.strictEqual(notice.level, "error");
    assert.match(notice.text, /Could not rejoin "ghost-room"/);
    assert.match(
      notice.text,
      new RegExp(`127\\.0\\.0\\.1:${deadPort}`),
      "the failure must name the endpoint that did not answer",
    );

    const status = await h.tool("link_status");
    assert.strictEqual(status.details.state, "off", "a failed rejoin is not a room");
    assert.notStrictEqual(status.details.role, "hub", "a failed rejoin must never silently start hosting");
    assert.strictEqual(status.details.usable, false);
  });

  test("H12: while pairing is pending the tools name the pairing, not a missing peer", async () => {
    await h.run(`join ${hubUrl}`);

    const status = await h.tool("link_status");
    assert.strictEqual(status.details.state, "pairing");
    assert.strictEqual(status.details.usable, false);

    const calls = [
      ["link_send", { to: "hub-human", message: "hello" }],
      ["link_exec", { to: "hub-human", action: "git_status" }],
      ["link_list", {}],
    ];
    for (const [name, params] of calls) {
      const res = await h.tool(name, params);
      assert.match(res.text, /waiting to be verified by the host/, `${name} must name the pairing state`);
      assert.doesNotMatch(
        res.text,
        /peer not found|Peer not found|offline/i,
        `${name} must not claim the peer is missing while pairing is pending`,
      );
    }

    assert.ok(
      await pollUntil(() => pairingRequests.length === 1),
      "the hub never saw the pairing request",
    );
  });

  test("H12b: granting exec to an offline device with the link up issues nothing and says why", async () => {
    // The device record from H7 is still on disk and its peer is not connected. With a live
    // node the handler gets past the "link is off" branch, and this build then refuses for a
    // reason the operator cannot act on: initNode() hardcodes allowRemoteExec: false
    // (index.ts:322), so /link grant can never succeed here. Reported as P2 debt.
    const notice = await h.run("grant offline-peer");
    assert.strictEqual(notice.level, "warning");
    assert.match(notice.text, /disabled on this terminal|not connected right now/);
    assert.match(notice.text, /Nothing was granted|connect first/);
    assert.strictEqual(getActiveGrants().length, 0, "no grant may be issued to a device that is not there");
  });

  // Regression guard for the P1 this suite found: index.ts set `awaitingPairing` when
  // connectToHub() settled with `pairing-required` and nothing cleared it on success, because
  // the connect promise is already settled (link-node.ts:1702 nulls `clientConnectSettle`) and
  // the later `pair_response{approved:true}` reaches index.ts only as an onNotification string
  // (link-node.ts:1915). The agent stayed "pairing" forever after the host said yes: every
  // tool refused with "waiting to be verified by the host" while the node was authenticated
  // and the hub was already in its roster, and the room was never persisted. Fixed by
  // `watchForAdmission`/`completeJoin` in index.ts; the observable contract is below.
  test("H13: once the host approves, the joining agent must stop refusing every tool", async () => {
    const req = pairingRequests[0];
    assert.ok(req, "test setup: H12 must have produced a pairing request");
    const approved = hub.approvePairing(req.id, DEFAULT_PERMISSIONS, req.sasCode);
    assert.ok(approved, "test setup: the hub must approve its own derived code");

    const admitted = await pollUntil(async () => {
      const snapshot = await h.tool("link_status");
      return snapshot.details.state === "connected";
    }, 10_000);
    assert.ok(admitted, "the host approved: the card must stop saying the agent is waiting to be verified");

    const status = await h.tool("link_status");
    assert.strictEqual(status.details.usable, true);
    assert.strictEqual(status.details.peers.length, 1, "the approved agent must see the hub in its roster");

    const sent = await h.tool("link_send", { to: "hub-human", message: "hello" });
    assert.match(sent.text, /Message sent/, "an approved agent must be able to use its own tools");

    assert.ok(
      status.details.room,
      "a completed pairing must be remembered as a room, or /link on cannot resume it",
    );
  });

  test("H14: off after a pairing leaves nothing shared", async () => {
    const notice = await h.run("off");
    assert.strictEqual(notice.level, "info");
    assert.match(notice.text, /Nothing on this machine is shared/);
    const status = await h.tool("link_status");
    assert.strictEqual(status.details.state, "off");
    assert.strictEqual(status.details.usable, false);
  });

  // The other half of the wedge: the host never says yes. index.ts's admission watch gives up
  // after PAIRING_WATCH_MS (65s, a module const with no injection seam), so the 65s expiry
  // itself is deliberately not exercised — a 65s sleep does not belong in this suite. What is
  // exercised is the outcome a human actually hits first: the host walks away and the socket
  // goes, at which point the agent must return to a state it can act on rather than refusing
  // every tool with "waiting to be verified" until the process restarts.
  test("H14b: a pairing the host never answers does not wedge the agent", async () => {
    const lonelyDirs = makeStateDirs("human-lonely-", ["hub", "workspace"]);
    const lonelyHub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      customOmpDir: lonelyDirs.hub,
      terminalName: "hub-lonely",
      workspaceRoot: lonelyDirs.workspace,
    });
    try {
      await lonelyHub.startHub();
      await h.run(`join 127.0.0.1:${lonelyHub.port}`);
      const pairing = await h.tool("link_status");
      assert.strictEqual(pairing.details.state, "pairing", "test setup: the join must be waiting on the host");

      // Nobody approves; the host's terminal goes away.
      await lonelyHub.stop();

      const recovered = await pollUntil(async () => {
        const snapshot = await h.tool("link_status");
        return snapshot.details.state !== "pairing";
      }, 10_000);
      assert.ok(recovered, "an unanswered pairing must not leave the agent 'pairing' forever");

      const status = await h.tool("link_status");
      assert.strictEqual(status.details.usable, false);
      const res = await h.tool("link_send", { to: "hub-lonely", message: "hello" });
      assert.doesNotMatch(
        res.text,
        /waiting to be verified/,
        "after the host is gone the refusal must name the real state, not a pairing that ended",
      );
      assert.match(res.text, /Link is off|Link is blocked/);
    } finally {
      await lonelyHub.stop();
      await h.run("off");
      fs.rmSync(lonelyDirs.root, { recursive: true, force: true });
    }
  });
});

// ── H15: the SAS comparison, as typed by a human ────────────────────────────────────────────

describe("HUMAN: approving with the right words typed wrong", () => {
  let dirs;
  let hub;
  let hubUrl;
  const requests = [];

  before(async () => {
    dirs = makeStateDirs("human-sas-", ["hub", "workspace"]);
    setCustomAuditLogPath(path.join(dirs.root, "audit.log"));
    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      customOmpDir: dirs.hub,
      terminalName: "hub-sas",
      workspaceRoot: dirs.workspace,
    });
    hub.onPairingRequested = (req) => requests.push(req);
    await hub.startHub();
    hubUrl = `wss://127.0.0.1:${hub.port}`;
  });

  after(async () => {
    if (hub) await hub.stop();
    if (dirs?.root) fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  // approvePairing strips every non-alphanumeric character and uppercases both sides
  // (link-node.ts:1013-1014), so case and separators do not matter and order does.
  const VARIANTS = [
    { name: "exactly as shown", transform: (c) => c, approves: true },
    { name: "all lowercase", transform: (c) => c.toLowerCase(), approves: true },
    { name: "with spaces and stray whitespace", transform: (c) => `  ${c.split("-").join(" ")}  `, approves: true },
    { name: "with the hyphens left out", transform: (c) => c.replace(/-/g, ""), approves: true },
    { name: "with two words in the wrong order", transform: swapTwoWords, approves: false },
    { name: "with one word wrong", transform: oneWordWrong, approves: false },
  ];

  for (const variant of VARIANTS) {
    test(`H15 (${variant.approves ? "MUST pair" : "MUST NOT pair"}): code typed ${variant.name}`, async () => {
      const seen = requests.length;
      const { client, outcome } = await connectFreshClient(hubUrl, dirs.root, `sas-${seen}`);
      try {
        assert.strictEqual(outcome.state, "pairing-required");
        assert.ok(await pollUntil(() => requests.length > seen), "hub never raised the pairing request");
        const req = requests[seen];

        const typed = variant.transform(req.sasCode);
        assert.ok(typed, "all four SAS words were identical; re-run (p ~ 6e-8)");
        if (!variant.approves) {
          assert.notStrictEqual(
            normalizeSas(typed),
            normalizeSas(req.sasCode),
            "test setup: the wrong variant must actually differ after normalisation",
          );
        }

        const approved = hub.approvePairing(req.id, DEFAULT_PERMISSIONS, typed);
        const stored = loadPairedDevices(dirs.hub).get(client.identity.fingerprint);

        if (variant.approves) {
          assert.ok(approved, `"${typed}" should have been accepted as the same code`);
          assert.ok(stored, "an approved device must be pinned on disk");
          assert.ok(
            await pollUntil(() => client.isAuthenticated),
            "an approved client must reach the authenticated phase",
          );
        } else {
          assert.strictEqual(approved, null, `"${typed}" must not pair anything`);
          assert.strictEqual(stored, undefined, "a refused device must not be pinned");
          assert.ok(
            await pollUntil(() => !client.isAuthenticated && client.role === "disconnected"),
            "a refused peer must be disconnected, not left hanging",
          );
          const denials = readAuditLogs(500).filter((e) => e.type === "pairing_rejected_invalid_sas");
          assert.ok(denials.length > 0, "a mismatched code must be audited");
        }
      } finally {
        await client.stop();
      }
    });
  }
});

// ── H16-H19: wrong ids, repetition, and giving up ───────────────────────────────────────────

describe("HUMAN: wrong request ids, approving twice, and a peer that gives up", () => {
  let dirs;
  let hub;
  let hubUrl;
  const requests = [];
  const clients = [];

  before(async () => {
    dirs = makeStateDirs("human-ids-", ["hub", "workspace"]);
    setCustomAuditLogPath(path.join(dirs.root, "audit.log"));
    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      customOmpDir: dirs.hub,
      terminalName: "hub-ids",
      workspaceRoot: dirs.workspace,
    });
    hub.onPairingRequested = (req) => requests.push(req);
    await hub.startHub();
    hubUrl = `wss://127.0.0.1:${hub.port}`;
  });

  after(async () => {
    for (const c of clients) await c.stop();
    if (hub) await hub.stop();
    if (dirs?.root) fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("H16: id 0, a negative id and an unknown id refuse without touching the live request", async () => {
    const { client, outcome } = await connectFreshClient(hubUrl, dirs.root, "ids-alpha");
    clients.push(client);
    assert.strictEqual(outcome.state, "pairing-required");
    assert.ok(await pollUntil(() => requests.length === 1));
    const req = requests[0];

    for (const bogus of [0, -1, 4242, Number.NaN]) {
      assert.strictEqual(
        hub.approvePairing(bogus, DEFAULT_PERMISSIONS, req.sasCode),
        null,
        `approving id ${bogus} must do nothing`,
      );
      assert.strictEqual(hub.denyPairing(bogus), false, `denying id ${bogus} must do nothing`);
    }

    // The real request survived every fat finger above.
    const approved = hub.approvePairing(req.id, DEFAULT_PERMISSIONS, req.sasCode);
    assert.ok(approved, "a bogus id must not consume or kill the pending request");
    assert.ok(await pollUntil(() => client.isAuthenticated));
  });

  test("H17: approving the same request twice does not re-pair or reset permissions", async () => {
    const req = requests[0];
    const fingerprint = clients[0].identity.fingerprint;

    // The operator narrows the device after pairing, then hits the approve line again.
    assert.strictEqual(
      hub.updatePeerPermissions(clients[0].identity.principalId, { message: false }),
      true,
    );
    assert.strictEqual(loadPairedDevices(dirs.hub).get(fingerprint).permissions.message, false);

    const second = hub.approvePairing(req.id, FULL_PERMISSIONS, req.sasCode);
    assert.strictEqual(second, null, "a consumed request id must not approve a second time");
    assert.strictEqual(
      loadPairedDevices(dirs.hub).get(fingerprint).permissions.message,
      false,
      "a repeated approve must not silently restore permissions the operator removed",
    );
    assert.strictEqual(clients[0].isAuthenticated, true, "the established session must be untouched");
  });

  test("H18: approving with another pending request's id refuses, and only that request dies", async () => {
    const seen = requests.length;
    const bravo = await connectFreshClient(hubUrl, dirs.root, "ids-bravo");
    const charlie = await connectFreshClient(hubUrl, dirs.root, "ids-charlie");
    clients.push(bravo.client, charlie.client);
    assert.ok(await pollUntil(() => requests.length === seen + 2));

    const reqBravo = requests.find((r) => r.displayName === "ids-bravo");
    const reqCharlie = requests.find((r) => r.displayName === "ids-charlie");
    assert.ok(reqBravo && reqCharlie);

    // Right code, wrong row: the operator reads Bravo's code and types Charlie's id.
    const wrong = hub.approvePairing(reqCharlie.id, DEFAULT_PERMISSIONS, reqBravo.sasCode);
    assert.strictEqual(wrong, null, "a code from another request must never pair a device");
    assert.strictEqual(
      loadPairedDevices(dirs.hub).get(charlie.client.identity.fingerprint),
      undefined,
      "Charlie must not be pinned by Bravo's code",
    );
    // Charlie is collateral: a mismatched code fails that request closed.
    assert.ok(
      await pollUntil(() => charlie.client.role === "disconnected"),
      "the request whose id was used must be failed closed, not left pending",
    );
    assert.strictEqual(hub.denyPairing(reqCharlie.id), false, "the failed request must be gone");

    // Bravo, who did nothing wrong, is still waiting and still approvable.
    const bravoApproved = hub.approvePairing(reqBravo.id, DEFAULT_PERMISSIONS, reqBravo.sasCode);
    assert.ok(bravoApproved, "an untouched pending request must survive someone else's mistake");
    assert.ok(await pollUntil(() => bravo.client.isAuthenticated));
  });

  test("H19: a peer that gives up while pending leaves no request behind, and a late approve fails cleanly", async () => {
    const seen = requests.length;
    const { client } = await connectFreshClient(hubUrl, dirs.root, "ids-quitter");
    assert.ok(await pollUntil(() => requests.length === seen + 1));
    const req = requests[seen];

    await client.stop();
    // The socket close is what retires the request (link-node.ts:1626-1631); give it a tick.
    await sleep(300);

    assert.strictEqual(hub.denyPairing(req.id), false, "a hub must not hold a pending request for a gone peer");
    assert.strictEqual(
      hub.approvePairing(req.id, DEFAULT_PERMISSIONS, req.sasCode),
      null,
      "approving a peer that left must fail cleanly, not throw",
    );
    assert.strictEqual(
      loadPairedDevices(dirs.hub).get(client.identity.fingerprint),
      undefined,
      "a peer that gave up must not end up paired",
    );
  });
});

// ── H20: names a human actually types ───────────────────────────────────────────────────────

describe("HUMAN: device names with spaces, dashes, unicode and 300 characters", () => {
  let dirs;
  let hub;
  let hubUrl;
  const requests = [];
  const clients = [];

  before(async () => {
    dirs = makeStateDirs("human-names-", ["hub", "workspace"]);
    setCustomAuditLogPath(path.join(dirs.root, "audit.log"));
    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      customOmpDir: dirs.hub,
      terminalName: "hub-names",
      workspaceRoot: dirs.workspace,
    });
    hub.onPairingRequested = (req) => requests.push(req);
    await hub.startHub();
    hubUrl = `wss://127.0.0.1:${hub.port}`;
  });

  after(async () => {
    for (const c of clients) await c.stop();
    if (hub) await hub.stop();
    if (dirs?.root) fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  const LONG_NAME = "x".repeat(300);
  const NAME_CASES = [
    { label: "spaces inside and around", sent: "  jo's  work laptop  ", expected: "jo's  work laptop" },
    { label: "a leading hyphen", sent: "-rf laptop", expected: "-rf laptop" },
    { label: "unicode and emoji", sent: "笔记本 ünïcødé 🙂", expected: "笔记本 ünïcødé 🙂" },
    { label: "300 characters", sent: LONG_NAME, expected: LONG_NAME.slice(0, 64) },
  ];

  // A name that sanitises to nothing is refused at the wire boundary rather than shown to an
  // operator as `Device ""`. Identity is the SPKI pin, but a prompt nobody can read is a prompt
  // nobody can answer, so the connection is closed instead of raising a nameless request.
  test("H20c: a device named with only whitespace is refused, not shown as a blank name", async () => {
    const seen = requests.length;
    await assert.rejects(
      connectFreshClient(hubUrl, dirs.root, "     "),
      /closed the connection|displayName/i,
      "a nameless device must not be admitted to the pairing queue",
    );
    assert.strictEqual(requests.length, seen, "no pairing request may be raised for a nameless device");
  });
  for (const nameCase of NAME_CASES) {
    test(`H20: a device named with ${nameCase.label} is shown sanitized and never crashes the hub`, async () => {
      const seen = requests.length;
      const { client } = await connectFreshClient(hubUrl, dirs.root, nameCase.sent);
      clients.push(client);
      assert.ok(await pollUntil(() => requests.length > seen), "hub never raised the pairing request");
      const req = requests[seen];

      assert.strictEqual(req.displayName, nameCase.expected);
      assert.ok(req.displayName.length <= 64, "a display name must be bounded before a human sees it");
      assert.match(req.sasCode, /^[A-Z]+-[A-Z]+-[A-Z]+-[A-Z]+$/, "the hub must still derive a usable code");
    });
  }

  test("H20b: the truncated name is the name that routes", async () => {
    const req = requests.find((r) => r.displayName === LONG_NAME.slice(0, 64));
    assert.ok(req, "test setup: the 300-character client must have asked to pair");
    const paired = hub.approvePairing(req.id, DEFAULT_PERMISSIONS, req.sasCode);
    assert.ok(paired);
    assert.strictEqual(paired.deviceName.length, 64, "the stored device name is the truncated one");
    assert.ok(
      await pollUntil(() => hub.getConnectedTerminalsList().some((t) => t.name === paired.deviceName)),
      "the roster must show the truncated name",
    );
    assert.strictEqual(
      hub.sendMessage(paired.deviceName, "routing check"),
      true,
      "a human copying the displayed name must be able to address the peer",
    );
    assert.strictEqual(hub.sendMessage(LONG_NAME, "routing check"), false, "the untruncated name addresses nobody");
  });
});

// ── H21-H23: impatience ─────────────────────────────────────────────────────────────────────

describe("HUMAN: running the same command twice because nothing looked like it happened", () => {
  let dirs;
  let hub;
  let hubUrl;
  let client;
  const requests = [];

  before(async () => {
    dirs = makeStateDirs("human-twice-", ["hub", "client", "workspace"]);
    setCustomAuditLogPath(path.join(dirs.root, "audit.log"));
    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      customOmpDir: dirs.hub,
      terminalName: "hub-twice",
      workspaceRoot: dirs.workspace,
    });
    client = new LinkNode({
      port: 0,
      customOmpDir: dirs.client,
      terminalName: "client-twice",
      workspaceRoot: dirs.workspace,
    });
    hub.onPairingRequested = (req) => requests.push(req);
    await hub.startHub();
    hubUrl = `wss://127.0.0.1:${hub.port}`;
  });

  after(async () => {
    if (client) await client.stop();
    if (hub) await hub.stop();
    if (dirs?.root) fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("H21: hosting twice from one node leaves one hub on one port, still answering", async () => {
    const firstPort = hub.port;
    await hub.startHub();
    assert.strictEqual(hub.role, "hub");
    assert.strictEqual(hub.port, firstPort, "a second create must not move the room to a new port");

    const { client: probe, outcome } = await connectFreshClient(hubUrl, dirs.root, "twice-probe");
    try {
      assert.strictEqual(outcome.state, "pairing-required", "the restarted hub must still accept connections");
    } finally {
      await probe.stop();
    }
  });

  test("H22: joining twice ends with one live session, not two", async () => {
    const first = await client.connectToHub(hubUrl);
    assert.strictEqual(first.state, "pairing-required");
    assert.ok(await pollUntil(() => requests.some((r) => r.displayName === "client-twice")));
    const req = requests.find((r) => r.displayName === "client-twice");
    assert.ok(hub.approvePairing(req.id, FULL_PERMISSIONS, req.sasCode));
    assert.ok(await pollUntil(() => client.isAuthenticated));

    // Impatient second join against a session that already works.
    const second = await client.connectToHub(hubUrl);
    assert.strictEqual(second.state, "authenticated");
    assert.strictEqual(client.isAuthenticated, true);

    const oneRow = await pollUntil(
      () => hub.getConnectedTerminalsList().filter((t) => t.name === "client-twice").length === 1,
    );
    assert.ok(
      oneRow,
      `a second join must supersede the first, not double the roster: ${JSON.stringify(
        hub.getConnectedTerminalsList().map((t) => t.name),
      )}`,
    );
    assert.strictEqual(
      await client.executeRemoteRpc("hub-twice", "git_status", {}).then((r) => typeof r.ok),
      "boolean",
      "the surviving session must still serve RPCs",
    );
  });

  test("H23: stopping twice is harmless and leaves nothing connected", async () => {
    await client.stop();
    await client.stop();
    assert.strictEqual(client.role, "disconnected");
    assert.strictEqual(client.isAuthenticated, false);
    assert.ok(
      await pollUntil(() => !hub.getConnectedTerminalsList().some((t) => t.name === "client-twice")),
      "the hub roster must drop a peer that left",
    );
  });
});

// ── H24-H26: regret ─────────────────────────────────────────────────────────────────────────

describe("HUMAN: changing your mind while the peer is using what you gave it", () => {
  let dirs;
  let hub;
  let client;
  let hubUrl;
  const requests = [];

  before(async () => {
    dirs = makeStateDirs("human-regret-", ["hub", "client", "workspace"]);
    setCustomAuditLogPath(path.join(dirs.root, "audit.log"));
    execFileSync("git", ["init", "-q"], { cwd: dirs.workspace });

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      customOmpDir: dirs.hub,
      terminalName: "hub-regret",
      allowRemoteExec: true,
      workspaceRoot: dirs.workspace,
    });
    client = new LinkNode({
      port: 0,
      customOmpDir: dirs.client,
      terminalName: "client-regret",
      workspaceRoot: dirs.workspace,
    });
    // `registeredWorkspaces` is process-global and every LinkNode constructor writes "default".
    // Pin it to this group's scratch repo after both nodes exist: no test inspects the repo.
    registerWorkspace({ id: "default", rootDir: dirs.workspace });

    hub.onPairingRequested = (req) => requests.push(req);
    await hub.startHub();
    hubUrl = `wss://127.0.0.1:${hub.port}`;

    const outcome = await client.connectToHub(hubUrl);
    assert.strictEqual(outcome.state, "pairing-required");
    assert.ok(await pollUntil(() => requests.length === 1));
    assert.ok(hub.approvePairing(requests[0].id, FULL_PERMISSIONS, requests[0].sasCode));
    assert.ok(await pollUntil(() => client.isAuthenticated));
  });

  after(async () => {
    revokeAllGrants("human-flows teardown");
    if (client) await client.stop();
    if (hub) await hub.stop();
    if (dirs?.root) fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("H24: narrowing a capability stops the poll the peer is already running", async () => {
    const before = await client.executeRemoteRpc("hub-regret", "git_status", {});
    assert.strictEqual(before.ok, true, `baseline poll must succeed: ${before.error}`);

    // The operator has second thoughts halfway through the peer's polling loop.
    assert.strictEqual(
      hub.updatePeerPermissions(client.identity.principalId, { inspectMetadata: false }),
      true,
    );

    for (let i = 0; i < 3; i++) {
      const after = await client.executeRemoteRpc("hub-regret", "git_status", {});
      assert.strictEqual(after.ok, false, "a narrowed capability must take effect on the live connection");
      assert.match(after.error, /inspectMetadata/, "the refusal must name the capability that was removed");
    }

    const denials = readAuditLogs(500).filter((e) => e.type === "authorization_denied");
    assert.ok(denials.length >= 3, "every refusal must be audited");
  });

  test("H25: revoking a device mid-session fails the in-flight call, the next call, and closes the socket", async () => {
    assert.strictEqual(
      hub.updatePeerPermissions(client.identity.principalId, { inspectMetadata: true }),
      true,
    );
    createExecGrant(client.identity.principalId, client.agentInstanceId, "client-regret", {
      maxUses: 2,
      durationMs: 30_000,
    });
    assert.strictEqual(getActiveGrants().length, 1);

    const inFlight = client.executeRemoteRpc("hub-regret", "exec", { command: "sleep 2" });
    const settled = inFlight.then(
      (value) => ({ ok: true, value }),
      (err) => ({ ok: false, message: err.message }),
    );
    await sleep(300);

    assert.strictEqual(hub.revokeDevice(client.identity.principalId), true);

    const result = await settled;
    assert.strictEqual(result.ok, false, "an in-flight call must fail when the device is revoked mid-call");
    assert.match(result.message, /connection closed|Link stopped|not connected/i);

    assert.ok(
      await pollUntil(() => client.role === "disconnected" && !client.isAuthenticated),
      "revoking a device must close its socket",
    );

    await assert.rejects(
      () => client.executeRemoteRpc("hub-regret", "git_status", {}),
      /not connected/i,
      "a call after revocation must fail immediately, not wait out the 30s timeout",
    );

    assert.strictEqual(getActiveGrants().length, 0, "revoking a device must take its grants with it");
    assert.strictEqual(
      loadPairedDevices(dirs.hub).get(client.identity.fingerprint),
      undefined,
      "a revoked device must be unpinned",
    );
    const revocations = readAuditLogs(500).filter((e) => e.type === "device_revoked");
    assert.ok(revocations.length > 0, "revocation must be on the sharing receipt");
  });

  test("H26: stopping the hub takes every live exec grant with it", async () => {
    createExecGrant("ed25519-sha256:HUMAN_FLOWS_H26", "agent-h26", "held-elsewhere", {
      maxUses: 5,
      durationMs: 60_000,
    });
    assert.strictEqual(getActiveGrants().length, 1, "test setup: one live grant");

    await hub.stop();

    assert.strictEqual(getActiveGrants().length, 0, "no grant may outlive the link that issued it");
    assert.strictEqual(hub.role, "disconnected");
  });
});

// ── H27: a pinned record that no longer describes the device ────────────────────────────────

describe("HUMAN: a paired-device record whose fingerprint no longer matches", () => {
  let dirs;
  let hub;
  let client;
  let hubUrl;
  const requests = [];

  before(async () => {
    dirs = makeStateDirs("human-stale-", ["hub", "client", "workspace"]);
    setCustomAuditLogPath(path.join(dirs.root, "audit.log"));
    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      customOmpDir: dirs.hub,
      terminalName: "hub-stale",
      workspaceRoot: dirs.workspace,
    });
    client = new LinkNode({
      port: 0,
      customOmpDir: dirs.client,
      terminalName: "client-stale",
      workspaceRoot: dirs.workspace,
    });
    hub.onPairingRequested = (req) => requests.push(req);
    await hub.startHub();
    hubUrl = `wss://127.0.0.1:${hub.port}`;
  });

  after(async () => {
    if (client) await client.stop();
    if (hub) await hub.stop();
    if (dirs?.root) fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  test("H27: a stored record with the right principal and a stale fingerprint admits nobody", async () => {
    const stale = {
      principalId: client.identity.principalId,
      fingerprint: new Array(32).fill("BB").join(":"),
      certPem: client.identity.certPem,
      deviceName: "client-stale",
      permissions: FULL_PERMISSIONS,
      pairedAt: Date.now() - 86_400_000,
    };
    savePairedDevice(stale, dirs.hub);
    assert.strictEqual(loadPairedDevices(dirs.hub).size, 1, "test setup: the stale record is on disk");

    const outcome = await client.connectToHub(hubUrl);
    assert.strictEqual(
      outcome.state,
      "pairing-required",
      "a record whose fingerprint does not match the presented certificate must not admit the peer",
    );
    assert.strictEqual(client.isAuthenticated, false);
    assert.ok(await pollUntil(() => requests.length === 1), "the peer must be treated as unknown and queued");

    const devices = loadPairedDevices(dirs.hub);
    assert.strictEqual(devices.size, 1, "the stale record must not be silently rewritten");
    assert.ok(
      devices.get(stale.fingerprint),
      "the stale record must still be there for the operator to inspect and remove",
    );
  });
});
