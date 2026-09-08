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
  let hub;
  let client;
  const testPort = 19950;

  before(async () => {
    hubDir = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-hub-"));
    clientDir = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-client-"));

    hub = new LinkNode({
      port: testPort,
      customOmpDir: hubDir,
      terminalName: "hub-primary",
      sessionId: "integration-session",
    });

    client = new LinkNode({
      port: 0,
      customOmpDir: clientDir,
      terminalName: "client-secondary",
      sessionId: "integration-session",
    });

    await hub.startHub();
  });

  after(async () => {
    if (client) await client.stop();
    if (hub) await hub.stop();
    if (hubDir && fs.existsSync(hubDir)) fs.rmSync(hubDir, { recursive: true, force: true });
    if (clientDir && fs.existsSync(clientDir)) fs.rmSync(clientDir, { recursive: true, force: true });
  });

  test("Initial pairing handshake with Short Authentication String (SAS)", async () => {
    let pairingRequestedEvent = null;
    hub.onPairingRequested = (req) => {
      pairingRequestedEvent = req;
    };

    // Client connects without being pre-paired
    await client.connectToHub(`wss://127.0.0.1:${testPort}`);

    // Wait for client_hello and server pairing notification
    for (let i = 0; i < 20; i++) {
      if (pairingRequestedEvent) break;
      await new Promise((r) => setTimeout(r, 50));
    }

    assert.ok(pairingRequestedEvent, "Expected pairing request event on hub");
    assert.strictEqual(pairingRequestedEvent.displayName, "client-secondary");
    assert.match(pairingRequestedEvent.sasCode, /^[A-Z]+-[0-9]-[A-Z]+-[0-9]$/);

    // Host approves pairing with FULL_PERMISSIONS
    const paired = hub.approvePairing(pairingRequestedEvent.id, FULL_PERMISSIONS);
    assert.ok(paired);
    assert.strictEqual(paired.deviceName, "client-secondary");
    assert.strictEqual(paired.permissions.message, true);
    assert.strictEqual(paired.permissions.inspect, true);
    assert.strictEqual(paired.permissions.execRequest, true);

    // Wait for approval frame propagation
    await new Promise((r) => setTimeout(r, 100));
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
    // Write a safe test file in working directory
    const testFile = path.join(process.cwd(), "test-inspect-safe.txt");
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

    // 2. Grant single-use permission on hub
    createExecGrant(client.identity.principalId, "client-secondary", { maxUses: 1, durationMs: 10_000 });

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
    await client.connectToHub(`wss://127.0.0.1:${testPort}`, hub.identity.fingerprint);
    await new Promise((r) => setTimeout(r, 200));

    assert.strictEqual(client.role, "client");

    // Can immediately send messages without pending pairing request
    const msgSent = client.sendMessage("hub-primary", "Reconnected seamlessly!");
    assert.strictEqual(msgSent, true);
  });
});
