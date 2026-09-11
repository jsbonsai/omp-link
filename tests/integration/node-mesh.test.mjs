import { test, describe, before, after } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";

import { LinkNode } from "../../src/link-node.js";
import { FULL_PERMISSIONS, DEFAULT_PERMISSIONS, savePairedDevice } from "../../src/identity.js";
import { createExecGrant, checkAndConsumeExecGrant } from "../../src/authorization.js";

describe("OMP-LINK v5 Integration: Loopback Mesh & Node Coordination", () => {
  let hubDir;
  let clientDir;
  let workspaceDir;
  let hub;
  let client;
  let hubUrl;

  before(async () => {
    hubDir = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-hub-"));
    clientDir = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-client-"));
    // `registeredWorkspaces` is a process-global registry keyed by "default", so both nodes
    // resolve inspection RPCs to the same root. Point it at a scratch dir: no test may write
    // fixtures into the repository working tree.
    workspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-workspace-"));

    hub = new LinkNode({
      port: 0,
      bindHost: "127.0.0.1",
      customOmpDir: hubDir,
      terminalName: "hub-primary",
      sessionId: "integration-session",
      allowRemoteExec: true,
      workspaceRoot: workspaceDir,
    });

    client = new LinkNode({
      port: 0,
      customOmpDir: clientDir,
      terminalName: "client-secondary",
      sessionId: "integration-session",
      workspaceRoot: workspaceDir,
    });

    await hub.startHub();
    hubUrl = `wss://127.0.0.1:${hub.port}`;
  });

  after(async () => {
    if (client) await client.stop();
    if (hub) await hub.stop();
    if (hubDir && fs.existsSync(hubDir)) fs.rmSync(hubDir, { recursive: true, force: true });
    if (clientDir && fs.existsSync(clientDir)) fs.rmSync(clientDir, { recursive: true, force: true });
    if (workspaceDir && fs.existsSync(workspaceDir)) fs.rmSync(workspaceDir, { recursive: true, force: true });
  });

  test("Initial pairing handshake with Short Authentication String (SAS)", async () => {
    let pairingRequestedEvent = null;
    hub.onPairingRequested = (req) => {
      pairingRequestedEvent = req;
    };

    // Client connects without being pre-paired
    const outcome = await client.connectToHub(hubUrl);
    assert.strictEqual(outcome.state, "pairing-required");

    // Wait for client_hello and server pairing notification
    for (let i = 0; i < 20; i++) {
      if (pairingRequestedEvent) break;
      await new Promise((r) => setTimeout(r, 50));
    }

    assert.ok(pairingRequestedEvent, "Expected pairing request event on hub");
    assert.strictEqual(pairingRequestedEvent.displayName, "client-secondary");
    assert.match(pairingRequestedEvent.sasCode, /^[A-Z]+-[A-Z]+-[A-Z]+-[A-Z]+$/);

    // The code is never transmitted: each side derives it from its own view of the TLS
    // channel. Agreement is the whole proof, so the client's code — not the hub's own — is
    // what gets fed back for verification.
    assert.strictEqual(
      outcome.sasCode,
      pairingRequestedEvent.sasCode,
      "Hub and client derived different codes from the same TLS channel",
    );

    // Host approves pairing with FULL_PERMISSIONS and SAS verification
    const paired = hub.approvePairing(pairingRequestedEvent.id, FULL_PERMISSIONS, outcome.sasCode);
    assert.ok(paired);
    assert.strictEqual(paired.deviceName, "client-secondary");
    assert.strictEqual(paired.permissions.message, true);
    assert.strictEqual(paired.permissions.inspect, true);
    assert.strictEqual(paired.permissions.execRequest, true);

    // Wait for approval frame propagation
    await new Promise((r) => setTimeout(r, 100));
    assert.strictEqual(client.isAuthenticated, true, "Client must be authenticated once pairing is approved");

    // Pairing is mutual, capabilities are not: the client records its hub with
    // DEFAULT_PERMISSIONS and must grant inbound rights explicitly before the hub may inspect
    // it, request a compaction, or send it a file.
    const granted = client.updatePeerPermissions(hub.identity.principalId, FULL_PERMISSIONS);
    assert.strictEqual(granted, true, "Client must be able to grant its hub inbound capabilities");
  });

  test("Bi-directional authenticated message exchange", async () => {
    let hubReceived = null;
    let clientReceived = null;

    hub.onMessage = (msg) => { hubReceived = msg; };
    client.onMessage = (msg) => { clientReceived = msg; };

    // Client -> Hub
    const sentFromClient = client.sendMessage("hub-primary", "Hello from client!");
    assert.strictEqual(sentFromClient, true);

    for (let i = 0; i < 20; i++) {
      if (hubReceived) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.ok(hubReceived);
    assert.strictEqual(hubReceived.text, "Hello from client!");
    assert.strictEqual(hubReceived.from, "client-secondary");

    // Hub -> Client
    const sentFromHub = hub.sendMessage("client-secondary", "Hello from hub!");
    assert.strictEqual(sentFromHub, true);

    for (let i = 0; i < 20; i++) {
      if (clientReceived) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.ok(clientReceived);
    assert.strictEqual(clientReceived.text, "Hello from hub!");
    assert.strictEqual(clientReceived.from, "hub-primary");
  });

  test("Structured inspection RPC (git_status, read_file)", async () => {
    // Write a safe test file inside the exported workspace
    const testFile = path.join(workspaceDir, "test-inspect-safe.txt");
    fs.writeFileSync(testFile, "OMP-LINK Inspection Verification Token");

    try {
      // Client inspects hub
      const res = await client.executeRemoteRpc("hub-primary", "read_file", {
        filePath: "test-inspect-safe.txt",
      });

      assert.strictEqual(res.ok, true);
      assert.strictEqual(res.result, "OMP-LINK Inspection Verification Token");

      // Attempting to read sensitive file via RPC fails
      const sensitiveRes = await client.executeRemoteRpc("hub-primary", "read_file", {
        filePath: ".env",
      });
      assert.strictEqual(sensitiveRes.ok, false);
      assert.match(sensitiveRes.error, /Access to sensitive file or pattern/);
    } finally {
      try { fs.unlinkSync(testFile); } catch {}
    }
  });

  test("Shell execution RPC requires active execution grant", async () => {
    // 1. Without grant: exec fails
    const ungrantedRes = await client.executeRemoteRpc("hub-primary", "exec", {
      command: "echo 'should fail'",
    });
    assert.strictEqual(ungrantedRes.ok, false);
    assert.match(ungrantedRes.error, /No active execution grant found/);

    // 2. Grant single-use permission on hub, for this client's agent instance
    createExecGrant(client.identity.principalId, client.agentInstanceId, "client-secondary", {
      maxUses: 1,
      durationMs: 10_000,
    });

    // 3. With grant: exec succeeds
    const grantedRes = await client.executeRemoteRpc("hub-primary", "exec", {
      command: "echo 'execution permitted'",
    });
    assert.strictEqual(grantedRes.ok, true);
    assert.match(grantedRes.result, /execution permitted/);

    // 4. Second attempt fails (single use exhausted)
    const secondRes = await client.executeRemoteRpc("hub-primary", "exec", {
      command: "echo 'second try'",
    });
    assert.strictEqual(secondRes.ok, false);
    assert.match(secondRes.error, /No active execution grant found/);
  });

  test("Streaming file transfer with SHA-256 direct-to-disk verification", async () => {
    const srcFile = path.join(clientDir, "transfer-source.dat");
    const testData = crypto.randomBytes(256 * 1024); // 256KB = 4 chunks
    fs.writeFileSync(srcFile, testData);

    const transferRes = await client.sendFile("hub-primary", srcFile);
    assert.strictEqual(transferRes.ok, true);
  });

  test("Client reconnection with pinned certificate requires no re-pairing", async () => {
    await client.stop();
    assert.strictEqual(client.role, "disconnected");

    // Reconnect client with hub fingerprint pinned
    const outcome = await client.connectToHub(hubUrl, hub.identity.fingerprint);
    assert.deepStrictEqual(outcome, { state: "authenticated" });

    assert.strictEqual(client.role, "client");

    // Can immediately send messages without pending pairing request
    const msgSent = client.sendMessage("hub-primary", "Reconnected seamlessly!");
    assert.strictEqual(msgSent, true);
  });

  test("Detailed system_status RPC returns hub status to authenticated peer", async () => {
    const statusRes = await client.executeRemoteRpc("hub-primary", "system_status");
    assert.strictEqual(statusRes.ok, true);
    assert.ok(statusRes.result);
    assert.strictEqual(statusRes.result.service, "omp-link");
    assert.strictEqual(statusRes.result.protocolVersion, 5);
    assert.strictEqual(statusRes.result.hubPrincipalId, hub.identity.principalId);
    assert.strictEqual(statusRes.result.caller.principalId, client.identity.principalId);
    assert.strictEqual(statusRes.result.caller.displayName, "client-secondary");
  });

  test("Hub can execute remote inspection RPC on client terminal", async () => {
    const safeFile = path.join(workspaceDir, "test-client-inspect.txt");
    fs.writeFileSync(safeFile, "Client inspection safe token");

    try {
      const res = await hub.executeRemoteRpc("client-secondary", "read_file", {
        filePath: "test-client-inspect.txt",
      });
      assert.strictEqual(res.ok, true, `read_file failed with error: ${res.error}`);
      assert.strictEqual(res.result, "Client inspection safe token");
    } finally {
      try { fs.unlinkSync(safeFile); } catch {}
    }
  });

  test("Hub can stream file to client terminal with quarantine direct-to-disk verification", async () => {
    const srcFile = path.join(hubDir, "hub-to-client.dat");
    const testData = crypto.randomBytes(128 * 1024); // 128KB = 2 chunks
    fs.writeFileSync(srcFile, testData);

    const transferRes = await hub.sendFile("client-secondary", srcFile);
    assert.strictEqual(transferRes.ok, true);
  });

  test("Bi-directional remote compaction requests", async () => {
    let clientCompacted = false;
    let hubCompacted = false;

    client.onCompactRequest = async (req) => {
      clientCompacted = true;
      return { ok: true };
    };

    hub.onCompactRequest = async (req) => {
      hubCompacted = true;
      return { ok: true };
    };

    // 1. Hub requests client compact
    const hubReqRes = await hub.requestCompact("client-secondary", "Trim context for worker");
    assert.strictEqual(hubReqRes.ok, true);
    assert.strictEqual(clientCompacted, true);

    // 2. Client requests hub compact
    const clientReqRes = await client.requestCompact("hub-primary");
    assert.strictEqual(clientReqRes.ok, true);
    assert.strictEqual(hubCompacted, true);
  });

  test("Hub device revocation terminates connection and revokes grants immediately", async () => {
    // Verify client is connected
    assert.strictEqual(client.role, "client");

    // Host revokes client
    const revoked = hub.revokeDevice(client.identity.principalId);
    assert.strictEqual(revoked, true);

    // Wait for disconnect event on client
    await new Promise((r) => setTimeout(r, 200));

    assert.strictEqual(client.role, "disconnected");
  });
});
