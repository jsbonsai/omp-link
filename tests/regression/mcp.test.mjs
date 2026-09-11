import { test, describe, before, after } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { LinkNode } from "../../src/link-node.js";
import { CONFIG_SCHEMA_VERSION } from "../../src/config.js";
import { FULL_PERMISSIONS, getOrCreateDeviceIdentity, savePairedDevice } from "../../src/identity.js";
import { revokeAllGrants } from "../../src/authorization.js";
import { setCustomAuditLogPath } from "../../src/audit.js";

// MCP stdio surface. Everything here drives the real binary as a child process under bare `node`
// — no tsx loader, no in-process import — because that is exactly how Claude Code, Codex CLI and
// Cursor start it, and because the loader shim in bin/omp-link-mcp.mjs is the part most likely to
// break silently on a fresh clone.
//
// The load-bearing assertion is stdout purity: hosts parse stdout with a strict JSON-RPC reader,
// so one stray log line turns the server into a hang with no error message anywhere.

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const MCP_BIN = path.join(REPO_ROOT, "bin", "omp-link-mcp.mjs");

const RPC_TIMEOUT_MS = 20_000;
const EXPECTED_TOOLS = ["link_status", "link_send", "link_list", "link_discover", "link_exec", "link_send_file"];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function pollUntil(predicate, timeoutMs = 10_000, stepMs = 100) {
  const started = Date.now();
  for (;;) {
    if (await predicate()) return true;
    if (Date.now() - started >= timeoutMs) return false;
    await sleep(stepMs);
  }
}

function deviceRecord(identity, deviceName, permissions) {
  return {
    principalId: identity.principalId,
    fingerprint: identity.fingerprint,
    certPem: identity.certPem,
    deviceName,
    permissions,
    pairedAt: Date.now(),
  };
}

/**
 * A JSON-RPC-over-stdio client for the real binary.
 *
 * Every byte the child writes to stdout is kept verbatim in `stdoutRaw` so a test can assert what
 * the stream contained, not just what this client managed to parse.
 */
class McpChild {
  constructor(ompDir, extraArgs = []) {
    this.stdoutRaw = "";
    this.stderrRaw = "";
    this.pending = new Map();
    this.nextId = 1;
    this.exited = false;
    this.exitCode = null;
    this.child = spawn(process.execPath, [MCP_BIN, "--omp-dir", ompDir, ...extraArgs], {
      // cwd is the node's workspaceRoot. Never the repo tree.
      cwd: ompDir,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, OMP_DIR: ompDir },
    });

    let buffer = "";
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (chunk) => {
      this.stdoutRaw += chunk;
      buffer += chunk;
      let nl = buffer.indexOf("\n");
      while (nl !== -1) {
        const line = buffer.slice(0, nl);
        buffer = buffer.slice(nl + 1);
        this.#deliver(line);
        nl = buffer.indexOf("\n");
      }
    });
    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (chunk) => { this.stderrRaw += chunk; });
    this.child.on("exit", (code) => {
      this.exited = true;
      this.exitCode = code;
      for (const { reject } of this.pending.values()) {
        reject(new Error(`server exited with code ${code} before answering\nstderr:\n${this.stderrRaw}`));
      }
      this.pending.clear();
    });
  }

  #deliver(line) {
    let frame;
    try {
      frame = JSON.parse(line);
    } catch {
      return; // Purity assertions inspect stdoutRaw; a corrupt line must not crash the client.
    }
    const waiter = this.pending.get(frame.id);
    if (!waiter) return;
    this.pending.delete(frame.id);
    waiter.resolve(frame);
  }

  /** Frames returned in order, one per newline-delimited line the child wrote. */
  frames() {
    return this.stdoutRaw.split("\n").filter((l) => l !== "").map((l) => JSON.parse(l));
  }

  writeRaw(text) {
    this.child.stdin.write(text);
  }

  notify(method, params) {
    this.writeRaw(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
  }

  /** Sends a request and resolves with the whole response frame (result or error). */
  request(method, params, id = this.nextId++) {
    const waiter = {};
    const settled = new Promise((resolve, reject) => {
      waiter.resolve = resolve;
      waiter.reject = reject;
    });
    this.pending.set(id, waiter);
    this.writeRaw(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    const timer = setTimeout(() => {
      if (!this.pending.delete(id)) return;
      waiter.reject(new Error(`${method} did not answer within ${RPC_TIMEOUT_MS}ms\nstderr:\n${this.stderrRaw}`));
    }, RPC_TIMEOUT_MS);
    return settled.finally(() => clearTimeout(timer));
  }

  /** Sends a raw line that is deliberately not a valid request, keyed to no id. */
  async requestRaw(line, id) {
    const waiter = {};
    const settled = new Promise((resolve, reject) => {
      waiter.resolve = resolve;
      waiter.reject = reject;
    });
    this.pending.set(id, waiter);
    this.writeRaw(line);
    const timer = setTimeout(() => {
      if (!this.pending.delete(id)) return;
      waiter.reject(new Error(`raw frame produced no answer within ${RPC_TIMEOUT_MS}ms`));
    }, RPC_TIMEOUT_MS);
    return settled.finally(() => clearTimeout(timer));
  }

  async handshake() {
    const res = await this.request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "omp-link-test-host", version: "0.0.0" },
    });
    this.notify("notifications/initialized");
    return res;
  }

  async callTool(name, args) {
    return this.request("tools/call", { name, arguments: args });
  }

  async signalAndWait(signal, timeoutMs = 10_000) {
    this.child.kill(signal);
    await pollUntil(() => this.exited, timeoutMs);
    return this.exitCode;
  }

  async close() {
    if (this.exited) return;
    try { this.child.stdin.end(); } catch {}
    if (!await pollUntil(() => this.exited, 5_000)) this.child.kill("SIGKILL");
  }
}

/**
 * Assert stdout carried nothing but well-formed JSON-RPC 2.0 frames.
 *
 * `stdoutRaw` is the exact byte stream, so this catches a stray `console.log`, a banner, an
 * uncaught warning printed to stdout, or a frame split across a line — every one of which
 * desynchronises a host's parser.
 */
function assertStdoutIsPureJsonRpc(child) {
  const raw = child.stdoutRaw;
  assert.ok(raw.length > 0, "the server wrote nothing to stdout");
  assert.ok(raw.endsWith("\n"), "the last stdout frame was not newline-terminated");
  const lines = raw.split("\n");
  assert.strictEqual(lines.pop(), "", "trailing bytes after the final newline");
  for (const [index, line] of lines.entries()) {
    assert.notStrictEqual(line, "", `stdout line ${index + 1} is empty`);
    let frame;
    try {
      frame = JSON.parse(line);
    } catch (err) {
      assert.fail(`stdout line ${index + 1} is not JSON (${err.message}): ${JSON.stringify(line.slice(0, 200))}`);
    }
    assert.ok(frame && typeof frame === "object" && !Array.isArray(frame), `stdout line ${index + 1} is not a JSON-RPC object`);
    assert.strictEqual(frame.jsonrpc, "2.0", `stdout line ${index + 1} is missing jsonrpc "2.0"`);
    const isResponse = Object.hasOwn(frame, "result");
    const isError = Object.hasOwn(frame, "error");
    assert.ok(isResponse !== isError, `stdout line ${index + 1} must carry exactly one of result/error`);
    assert.ok(Object.hasOwn(frame, "id"), `stdout line ${index + 1} is a response with no id`);
  }
}

// ── MCP protocol surface with no link configured ─────────────────────────────

describe("REGRESSION R28: the MCP server speaks JSON-RPC and stays usable with the link off", () => {
  let root;
  let ompDir;
  let mcp;

  before(async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "omp-mcp-off-"));
    ompDir = path.join(root, "state");
    fs.mkdirSync(ompDir, { recursive: true });
    setCustomAuditLogPath(path.join(root, "audit.log"));
    mcp = new McpChild(ompDir);
  });

  after(async () => {
    await mcp?.close();
    setCustomAuditLogPath(null);
    if (root && fs.existsSync(root)) fs.rmSync(root, { recursive: true, force: true });
  });

  test("initialize negotiates a supported revision and declares the tools capability", async () => {
    const res = await mcp.handshake();
    assert.ok(res.result, `initialize failed: ${JSON.stringify(res.error)}`);
    assert.strictEqual(res.result.protocolVersion, "2025-06-18", "the client's requested revision must be echoed");
    assert.ok(res.result.capabilities?.tools, "the tools capability must be declared");
    assert.strictEqual(res.result.serverInfo?.name, "omp-link");
    assert.match(res.result.serverInfo?.version || "", /^\d+\.\d+\.\d+/);
    assert.ok(
      typeof res.result.instructions === "string" && res.result.instructions.length > 0,
      "Codex uses serverInfo instructions as server-wide guidance",
    );
  });

  test("an unsupported protocol revision is answered with one this server speaks", async () => {
    const res = await mcp.request("initialize", { protocolVersion: "1999-01-01", capabilities: {} });
    assert.strictEqual(res.result.protocolVersion, "2025-06-18");
  });

  test("tools/list exposes exactly the six read-and-message tools with valid JSON Schema", async () => {
    const res = await mcp.request("tools/list");
    assert.ok(res.result, `tools/list failed: ${JSON.stringify(res.error)}`);
    const names = res.result.tools.map((t) => t.name);
    assert.deepStrictEqual([...names].sort(), [...EXPECTED_TOOLS].sort());

    // link_compact is meaningful only where the host exposes a compaction API for the agent's
    // own context. MCP has none, so a link_compact here could only lie about having compacted.
    assert.ok(!names.includes("link_compact"), "link_compact must not be exposed over MCP");

    for (const tool of res.result.tools) {
      assert.ok(tool.description && tool.description.length > 10, `${tool.name} needs a description`);
      const schema = tool.inputSchema;
      assert.strictEqual(schema.type, "object", `${tool.name} inputSchema must be an object schema`);
      assert.ok(schema.properties && typeof schema.properties === "object", `${tool.name} needs properties`);
      const declared = Object.keys(schema.properties);
      for (const key of declared) {
        const prop = schema.properties[key];
        assert.ok(
          ["string", "number", "boolean", "integer", "array", "object"].includes(prop.type),
          `${tool.name}.${key} has no usable JSON Schema type`,
        );
      }
      for (const required of schema.required || []) {
        assert.ok(declared.includes(required), `${tool.name} requires "${required}" but never declares it`);
      }
    }
  });

  test("the parameter schemas match the Pi extension's tools exactly", async () => {
    const byName = new Map((await mcp.request("tools/list")).result.tools.map((t) => [t.name, t]));
    assert.deepStrictEqual(Object.keys(byName.get("link_send").inputSchema.properties).sort(), ["message", "to"]);
    assert.deepStrictEqual(byName.get("link_send").inputSchema.required.sort(), ["message", "to"]);
    assert.deepStrictEqual(Object.keys(byName.get("link_send_file").inputSchema.properties).sort(), ["filePath", "to"]);
    assert.deepStrictEqual(byName.get("link_send_file").inputSchema.required.sort(), ["filePath", "to"]);
    const exec = byName.get("link_exec").inputSchema;
    assert.deepStrictEqual(Object.keys(exec.properties).sort(), ["action", "command", "count", "filePath", "pattern", "to"]);
    assert.deepStrictEqual(exec.required.sort(), ["action", "to"]);
    assert.deepStrictEqual(exec.properties.action.enum, [
      "git_status", "git_diff", "git_log", "search_text", "read_file", "list_dir", "exec",
    ]);
    for (const name of ["link_status", "link_list", "link_discover"]) {
      assert.deepStrictEqual(Object.keys(byName.get(name).inputSchema.properties), []);
    }
  });

  test("a call with no room configured fails cleanly and names the command that fixes it", async () => {
    const res = await mcp.callTool("link_send", { to: "peer", message: "hello" });
    assert.ok(res.result, `tools/call should answer with a result, got ${JSON.stringify(res.error)}`);
    assert.strictEqual(res.result.isError, true, "a call on a dead link must be flagged as an error");
    const text = res.result.content[0].text;
    assert.match(text, /No room is configured/);
    assert.match(text, /omp-link create <name>/, "the failure must name the next action");
    assert.ok(!/\n\s+at /.test(text), `a stack trace leaked into a user-facing string: ${text}`);
  });

  test("link_status answers with the link off instead of failing, and says what to do", async () => {
    const res = await mcp.callTool("link_status", {});
    assert.ok(res.result, JSON.stringify(res.error));
    assert.notStrictEqual(res.result.isError, true, "link_status must always answer");
    assert.strictEqual(res.result.structuredContent.state, "off");
    assert.strictEqual(res.result.structuredContent.usable, false);
    assert.strictEqual(res.result.structuredContent.room, null);
    assert.match(res.result.content[0].text, /^Link is off\./);
    assert.match(res.result.content[0].text, /omp-link (create|join)/);
  });

  test("malformed and unknown frames produce proper JSON-RPC errors, never a crash", async () => {
    const parse = await mcp.requestRaw("this is not json at all\n", null);
    assert.strictEqual(parse.error.code, -32700, "invalid JSON must be a parse error");
    assert.strictEqual(parse.id, null);

    const notObject = await mcp.requestRaw("\"a bare string\"\n", null);
    assert.strictEqual(notObject.error.code, -32600);

    const batch = await mcp.requestRaw("[{\"jsonrpc\":\"2.0\",\"id\":901,\"method\":\"ping\"}]\n", null);
    assert.strictEqual(batch.error.code, -32600, "MCP 2025-06-18 removed batching; it must be refused, not applied");

    const badVersion = await mcp.requestRaw("{\"jsonrpc\":\"1.0\",\"id\":902,\"method\":\"ping\"}\n", 902);
    assert.strictEqual(badVersion.error.code, -32600);

    const unknownMethod = await mcp.request("no/such/method");
    assert.strictEqual(unknownMethod.error.code, -32601);

    const unknownTool = await mcp.callTool("link_compact", { to: "peer" });
    assert.strictEqual(unknownTool.error.code, -32602, "an absent tool must be a protocol error, not a silent no-op");

    const missingArg = await mcp.callTool("link_send", { to: "peer" });
    assert.strictEqual(missingArg.error.code, -32602);

    const badEnum = await mcp.callTool("link_exec", { to: "peer", action: "rm_rf" });
    assert.strictEqual(badEnum.error.code, -32602);

    const badType = await mcp.callTool("link_exec", { to: "peer", action: "git_log", count: "many" });
    assert.strictEqual(badType.error.code, -32602);

    // Still alive and answering after all of that.
    assert.ok((await mcp.request("ping")).result, "the server died on a malformed frame");
  });

  test("a notification is never answered", async () => {
    const before = mcp.frames().length;
    mcp.notify("notifications/initialized");
    mcp.notify("notifications/cancelled", { requestId: 12345 });
    mcp.notify("notifications/does_not_exist");
    // A round trip proves the notifications were processed and produced no frame of their own.
    await mcp.request("ping");
    assert.strictEqual(mcp.frames().length, before + 1, "a notification produced a response frame");
  });

  test("stdout carried nothing but valid JSON-RPC frames", () => {
    assertStdoutIsPureJsonRpc(mcp);
  });
});

// ── MCP against a live hub ───────────────────────────────────────────────────

describe("REGRESSION R29: the MCP server attaches to the configured room and drives it", () => {
  const MCP_NAME = "mcp-agent";
  const HUB_NAME = "hub-primary";

  let root;
  let hubDir;
  let mcpDir;
  let hub;
  let mcp;
  const hubInbox = [];

  before(async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "omp-mcp-live-"));
    hubDir = path.join(root, "hub");
    mcpDir = path.join(root, "mcp");
    for (const dir of [hubDir, mcpDir]) fs.mkdirSync(dir, { recursive: true });
    setCustomAuditLogPath(path.join(root, "audit.log"));
    revokeAllGrants("mcp suite setup");

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      customOmpDir: hubDir,
      terminalName: HUB_NAME,
      workspaceRoot: hubDir,
    });
    hub.onMessage = (msg) => { hubInbox.push(msg); };
    await hub.startHub();

    // The MCP server is a child process, so its device identity has to exist before it starts
    // for the hub to be able to pin it. Both sides pre-paired: the hub gates the MCP node's
    // inbound traffic, and the MCP node gates the hub's.
    const mcpIdentity = getOrCreateDeviceIdentity(mcpDir);
    savePairedDevice(deviceRecord(mcpIdentity, MCP_NAME, FULL_PERMISSIONS), hubDir);
    savePairedDevice(deviceRecord(hub.identity, HUB_NAME, FULL_PERMISSIONS), mcpDir);

    // The room the operator would have created with `omp-link create`. The MCP server attaches
    // to whatever this says and never creates a room of its own.
    const room = {
      roomId: hub.roomId,
      label: "mcp-room",
      hubPrincipalId: hub.identity.principalId,
      hubFingerprint: hub.identity.fingerprint,
      endpoint: `127.0.0.1:${hub.port}`,
      lastJoinedAt: Date.now(),
    };
    fs.writeFileSync(
      path.join(mcpDir, "link.json"),
      `${JSON.stringify({ configVersion: CONFIG_SCHEMA_VERSION, currentRoomId: room.roomId, rooms: [room] }, null, 2)}\n`,
    );

    mcp = new McpChild(mcpDir, ["--name", MCP_NAME]);
    const init = await mcp.handshake();
    assert.ok(init.result, `test setup: initialize failed ${JSON.stringify(init.error)}`);
  });

  after(async () => {
    await mcp?.close();
    if (hub) await hub.stop();
    revokeAllGrants("mcp suite teardown");
    setCustomAuditLogPath(null);
    if (root && fs.existsSync(root)) fs.rmSync(root, { recursive: true, force: true });
  });

  test("link_status reports the room it actually joined", async () => {
    const res = await mcp.callTool("link_status", {});
    assert.ok(res.result, JSON.stringify(res.error));
    const details = res.result.structuredContent;
    assert.strictEqual(details.state, "connected", `attach failed: ${res.result.content[0].text}\nstderr:\n${mcp.stderrRaw}`);
    assert.strictEqual(details.usable, true);
    assert.strictEqual(details.role, "client");
    assert.strictEqual(details.terminalName, MCP_NAME);
    assert.strictEqual(details.room.label, "mcp-room");
    assert.strictEqual(details.room.roomId, hub.roomId);
    assert.strictEqual(details.attach.phase, "attached");
    assert.ok(details.peers.some((p) => p.name === HUB_NAME), `hub missing from the roster: ${JSON.stringify(details.peers)}`);
    assert.match(res.result.content[0].text, /^Link is connected in room "mcp-room"/);
  });

  test("the hub sees the MCP server as an ordinary authenticated terminal", async () => {
    assert.ok(
      await pollUntil(() => hub.getConnectedTerminalsList().some((t) => t.name === MCP_NAME)),
      "the MCP server never appeared on the hub roster",
    );
  });

  test("link_list names both terminals and marks which one is this agent", async () => {
    const res = await mcp.callTool("link_list", {});
    assert.ok(res.result, JSON.stringify(res.error));
    assert.notStrictEqual(res.result.isError, true);
    const text = res.result.content[0].text;
    assert.match(text, new RegExp(`- ${MCP_NAME} \\(this agent\\)`));
    assert.match(text, new RegExp(`- ${HUB_NAME}(?! \\(this agent\\))`));
    const names = res.result.structuredContent.terminals.map((t) => t.name).sort();
    assert.deepStrictEqual(names, [HUB_NAME, MCP_NAME].sort());
  });

  test("link_send actually delivers to the hub", async () => {
    const body = `mcp-to-hub-${Date.now()}`;
    const res = await mcp.callTool("link_send", { to: HUB_NAME, message: body });
    assert.ok(res.result, JSON.stringify(res.error));
    assert.notStrictEqual(res.result.isError, true, res.result.content[0].text);
    assert.strictEqual(res.result.content[0].text, `Message sent to "${HUB_NAME}".`);
    assert.ok(
      await pollUntil(() => hubInbox.some((m) => m.text === body)),
      `the hub never received the message; inbox: ${JSON.stringify(hubInbox)}`,
    );
    const received = hubInbox.find((m) => m.text === body);
    assert.strictEqual(received.originPrincipalId, getOrCreateDeviceIdentity(mcpDir).principalId);
  });

  // `LinkNode.sendMessage` returns true for any name on a client, because all it did was hand
  // the frame to the hub. A surface that reports that as "Message sent" lies about a typo.
  test("link_send to an unknown peer refuses instead of reporting success", async () => {
    const res = await mcp.callTool("link_send", { to: "nobody-here", message: "x" });
    assert.strictEqual(res.result.isError, true, "an undeliverable message must not report success");
    const text = res.result.content[0].text;
    assert.match(text, /No agent named "nobody-here" is on the link, so nothing was sent/);
    assert.match(text, new RegExp(HUB_NAME), "the refusal must name who is actually reachable");
  });

  test("a peer message arriving with no tool running is delivered by the next link_status", async () => {
    const body = `hub-to-mcp-${Date.now()}`;
    assert.ok(hub.sendMessage(MCP_NAME, body), "test setup: the hub could not route to the MCP terminal");
    const delivered = await pollUntil(async () => {
      const res = await mcp.callTool("link_status", {});
      return (res.result.structuredContent.messages || []).some((m) => m.text === body);
    }, 8_000, 250);
    assert.ok(delivered, `link_status never surfaced the peer message; stderr:\n${mcp.stderrRaw}`);

    // Delivered once: a drained backlog must not be replayed as if it were new traffic.
    const again = await mcp.callTool("link_status", {});
    assert.ok(
      !(again.result.structuredContent.messages || []).some((m) => m.text === body),
      "a message already reported was reported a second time",
    );
  });

  test("link_exec inspects the hub's workspace over the mesh", async () => {
    const res = await mcp.callTool("link_exec", { to: HUB_NAME, action: "list_dir", filePath: "." });
    assert.ok(res.result, JSON.stringify(res.error));
    assert.notStrictEqual(res.result.isError, true, res.result.content[0].text);
    assert.ok(res.result.content[0].text.length > 0, "list_dir returned nothing at all");
  });

  test("link_exec against an unknown peer fails cleanly with no stack trace", async () => {
    const res = await mcp.callTool("link_exec", { to: "nobody-here", action: "git_status" });
    assert.strictEqual(res.result.isError, true);
    const text = res.result.content[0].text;
    assert.ok(!/\n\s+at /.test(text), `a stack trace leaked into a user-facing string: ${text}`);
  });

  test("stdout carried nothing but valid JSON-RPC frames across a live session", () => {
    assertStdoutIsPureJsonRpc(mcp);
  });

  test("SIGTERM stops the node and exits cleanly, and the hub sees the peer leave", async () => {
    const code = await mcp.signalAndWait("SIGTERM");
    assert.strictEqual(code, 0, `SIGTERM must exit 0, got ${code}\nstderr:\n${mcp.stderrRaw}`);
    assert.ok(
      await pollUntil(() => !hub.getConnectedTerminalsList().some((t) => t.name === MCP_NAME)),
      "the hub still lists the MCP terminal after it exited",
    );
  });
});

// ── Attaching to a room created after the host started the server ────────────

// An MCP host starts its servers once, when the session opens — normally before the operator has
// run `omp-link create`. If the server only ever attached at startup, that ordering would leave
// every tool permanently dead with no way back but restarting the editor, which is a wedge a
// viewer cannot debug and cannot fix from inside the host.
describe("REGRESSION R30: a room created after the MCP server started is picked up without a restart", () => {
  const MCP_NAME = "mcp-late";
  const HUB_NAME = "hub-late";

  let root;
  let hubDir;
  let mcpDir;
  let hub;
  let mcp;

  before(async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "omp-mcp-late-"));
    hubDir = path.join(root, "hub");
    mcpDir = path.join(root, "mcp");
    for (const dir of [hubDir, mcpDir]) fs.mkdirSync(dir, { recursive: true });
    setCustomAuditLogPath(path.join(root, "audit.log"));

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      customOmpDir: hubDir,
      terminalName: HUB_NAME,
      workspaceRoot: hubDir,
    });
    await hub.startHub();

    const mcpIdentity = getOrCreateDeviceIdentity(mcpDir);
    savePairedDevice(deviceRecord(mcpIdentity, MCP_NAME, FULL_PERMISSIONS), hubDir);
    savePairedDevice(deviceRecord(hub.identity, HUB_NAME, FULL_PERMISSIONS), mcpDir);

    // Deliberately no link.json: the server starts with nothing to attach to.
    mcp = new McpChild(mcpDir, ["--name", MCP_NAME]);
    const init = await mcp.handshake();
    assert.ok(init.result, `test setup: initialize failed ${JSON.stringify(init.error)}`);
  });

  after(async () => {
    await mcp?.close();
    if (hub) await hub.stop();
    setCustomAuditLogPath(null);
    if (root && fs.existsSync(root)) fs.rmSync(root, { recursive: true, force: true });
  });

  test("tools/list works and every call is actionable while no room exists", async () => {
    const list = await mcp.request("tools/list");
    assert.strictEqual(list.result.tools.length, EXPECTED_TOOLS.length, "the catalogue must not depend on connectivity");

    for (const [name, args] of [
      ["link_list", {}],
      ["link_send", { to: HUB_NAME, message: "x" }],
      ["link_exec", { to: HUB_NAME, action: "git_status" }],
      ["link_send_file", { to: HUB_NAME, filePath: path.join(mcpDir, "nothing.txt") }],
    ]) {
      const res = await mcp.callTool(name, args);
      assert.ok(res.result, `${name} answered with a protocol error instead of a result: ${JSON.stringify(res.error)}`);
      assert.strictEqual(res.result.isError, true, `${name} must report the dead link`);
      const text = res.result.content[0].text;
      assert.match(text, /No room is configured/, `${name} must say why, not just fail: ${text}`);
      assert.match(text, /omp-link create <name>/, `${name} must name the next action: ${text}`);
      assert.ok(!/\n\s+at /.test(text), `${name} leaked a stack trace: ${text}`);
    }
  });

  test("the room appearing in link.json is enough; the process is never restarted", async () => {
    const room = {
      roomId: hub.roomId,
      label: "late-room",
      hubPrincipalId: hub.identity.principalId,
      hubFingerprint: hub.identity.fingerprint,
      endpoint: `127.0.0.1:${hub.port}`,
      lastJoinedAt: Date.now(),
    };
    fs.writeFileSync(
      path.join(mcpDir, "link.json"),
      `${JSON.stringify({ configVersion: CONFIG_SCHEMA_VERSION, currentRoomId: room.roomId, rooms: [room] }, null, 2)}\n`,
    );

    const attached = await pollUntil(async () => {
      const res = await mcp.callTool("link_status", {});
      return res.result.structuredContent.state === "connected";
    }, 20_000, 500);
    assert.ok(attached, `the server never picked up the new room; stderr:\n${mcp.stderrRaw}`);
    assert.ok(!mcp.exited, "the server must not have needed a restart");

    const list = await mcp.callTool("link_list", {});
    assert.notStrictEqual(list.result.isError, true, list.result.content[0].text);
    assert.match(list.result.content[0].text, new RegExp(`- ${HUB_NAME}`));
  });

  test("stdout stayed pure across the off-then-on transition", () => {
    assertStdoutIsPureJsonRpc(mcp);
  });
});
