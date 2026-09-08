import { test, describe, before, after } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { WebSocketServer, WebSocket } from "ws";

// Import PRODUCTION modules directly
import {
  getOrCreateDeviceIdentity,
  fingerprintDer,
  normalizeFingerprint,
  loadPairedDevices,
  savePairedDevice,
  removePairedDevice,
  derivePairingSas,
  createInvite,
  verifyAndConsumeInvite,
  DEFAULT_PERMISSIONS,
  FULL_PERMISSIONS,
} from "../src/identity.js";

import {
  getServerTlsOptions,
  getClientTlsOptions,
  extractPeerCertificate,
} from "../src/tls.js";

import {
  PROTOCOL_VERSION,
  parseWireMessage,
  sanitizeDisplayName,
} from "../src/protocol-schema.js";

import {
  createConnectionContext,
  validateMessagePhase,
  checkMessageDeduplication,
  setConnectionPhase,
} from "../src/connection-state.js";

import {
  isActionPermitted,
  bindMessageOrigin,
  createExecGrant,
  checkAndConsumeExecGrant,
  revokeGrantsForPrincipal,
  revokeAllGrants,
  getActiveGrants,
} from "../src/authorization.js";

import {
  resolveConfinedPath,
  isSensitivePath,
  safeGitExecFile,
  safeGitStatus,
  safeGitDiff,
  safeGitGrep,
  safeReadFile,
  safeListDir,
  resolveTrustedGit,
} from "../src/inspection.js";

import { TransferReceiver, CHUNK_SIZE, MAX_FILE_SIZE } from "../src/transfer-receiver.js";
import { computeFileHashStreaming, streamFileChunks } from "../src/transfer-sender.js";
import { LinkNode } from "../src/link-node.js";
import { appendAuditLog, readAuditLogs, setCustomAuditLogPath } from "../src/audit.js";

describe("OMP-LINK v5 Security & Cryptography Suite", () => {
  let tempDir;

  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-sec-test-"));
    setCustomAuditLogPath(path.join(tempDir, "test-audit.log"));
  });

  after(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // ── 1. Device Identity & Pairing ──────────────────────────────────────────

  describe("1. Identity & Pairing Security", () => {
    test("Full SHA-256 SPKI fingerprint is 95 characters long (256-bit)", () => {
      const id = getOrCreateDeviceIdentity(tempDir);
      assert.strictEqual(typeof id.fingerprint, "string");
      assert.strictEqual(id.fingerprint.length, 95); // 32 pairs + 31 colons
      assert.match(id.fingerprint, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
      assert.ok(id.principalId.startsWith(`${id.keyType}-sha256:`));
    });

    test("Canonical fingerprint normalizes casing and separators", () => {
      const rawHex = "a0b1c2d3e4f50123456789abcdef0123456789abcdef0123456789abcdef0123";
      const normalized = normalizeFingerprint(rawHex);
      assert.strictEqual(normalized.length, 95);
      assert.strictEqual(normalizeFingerprint(normalized), normalized);
    });

    test("Reject invalid fingerprint length", () => {
      assert.throws(() => normalizeFingerprint("tooshort"), /Invalid SHA-256 fingerprint length/);
    });

    test("Paired devices store and retrieve strictly by canonical fingerprint", () => {
      const id = getOrCreateDeviceIdentity(tempDir);
      const pairedDev = {
        principalId: id.principalId,
        fingerprint: id.fingerprint,
        certPem: id.certPem,
        deviceName: "trusted-node",
        permissions: DEFAULT_PERMISSIONS,
        pairedAt: Date.now(),
      };
      savePairedDevice(pairedDev, tempDir);

      const loaded = loadPairedDevices(tempDir);
      const found = loaded.get(normalizeFingerprint(id.fingerprint));
      assert.ok(found);
      assert.strictEqual(found.principalId, id.principalId);
      assert.strictEqual(found.deviceName, "trusted-node");

      // Removing by principalId succeeds
      const removed = removePairedDevice(id.principalId, tempDir);
      assert.strictEqual(removed, true);
      const afterRemove = loadPairedDevices(tempDir);
      assert.strictEqual(afterRemove.has(normalizeFingerprint(id.fingerprint)), false);
    });

    test("Pairing SAS derivation is deterministic and resists MITM substitution", () => {
      const cert1 = Buffer.from("dummy-hub-cert-der");
      const cert2 = Buffer.from("dummy-client-cert-der");
      const sas1 = derivePairingSas(cert1, cert2, "hub-nonce-1", "cli-nonce-1");
      const sas2 = derivePairingSas(cert1, cert2, "hub-nonce-1", "cli-nonce-1");
      assert.strictEqual(sas1, sas2);

      // Tampered nonce yields completely different SAS
      const sasTampered = derivePairingSas(cert1, cert2, "tampered-nonce", "cli-nonce-1");
      assert.notStrictEqual(sas1, sasTampered);
    });

    test("One-time pairing invite is consumed and single-use", () => {
      const id = getOrCreateDeviceIdentity(tempDir);
      const invite = createInvite(id, { expiresInMs: 60_000 });
      assert.ok(invite.inviteCode);
      assert.strictEqual(invite.used, false);

      const firstConsume = verifyAndConsumeInvite(invite.secret);
      assert.strictEqual(firstConsume.valid, true);

      // Second attempt rejected
      const secondConsume = verifyAndConsumeInvite(invite.secret);
      assert.strictEqual(secondConsume.valid, false);
      assert.strictEqual(secondConsume.reason, "Invitation not found");
    });
  });

  // ── 2. Protocol State Machine & Schemas ────────────────────────────────────

  describe("2. Protocol v5 State Machine & Schema Guards", () => {
    test("Strict protocol version 5 enforcement (rejects legacy versions)", () => {
      const legacyMsg = JSON.stringify({ type: "register", version: 4, name: "legacy-node" });
      const parsed = parseWireMessage(legacyMsg);
      assert.strictEqual(parsed.ok, false);
      assert.strictEqual(parsed.closeCode, 4400);
      assert.match(parsed.error, /Unsupported protocol version/);
    });

    test("Rejects malformed JSON and oversized frames", () => {
      const malformed = parseWireMessage("{bad json");
      assert.strictEqual(malformed.ok, false);
      assert.strictEqual(malformed.closeCode, 4400);

      const hugeBuf = Buffer.alloc(3 * 1024 * 1024, "a");
      const oversized = parseWireMessage(hugeBuf);
      assert.strictEqual(oversized.ok, false);
      assert.strictEqual(oversized.closeCode, 4409);
    });

    test("Sanitizes control characters from display names (anti-ANSI injection)", () => {
      const maliciousName = "peer\x1B[31m-admin\x00\x07";
      const cleaned = sanitizeDisplayName(maliciousName);
      assert.strictEqual(cleaned, "peer-admin");
      assert.strictEqual(cleaned.includes("\x1B"), false);
    });

    test("Connection phase: tls-connected permits client_hello only", () => {
      const ctx = createConnectionContext({ socket: {} });
      assert.strictEqual(ctx.phase, "tls-connected");

      assert.strictEqual(validateMessagePhase(ctx, "client_hello").allowed, true);
      assert.strictEqual(validateMessagePhase(ctx, "chat").allowed, false);
      assert.strictEqual(validateMessagePhase(ctx, "rpc_request").allowed, false);

      // Duplicate hello rejected
      ctx.helloReceived = true;
      assert.strictEqual(validateMessagePhase(ctx, "client_hello").allowed, false);
    });

    test("Connection phase: awaiting-pairing strictly forbids application traffic", () => {
      const ctx = createConnectionContext({ socket: {} });
      ctx.phase = "awaiting-pairing";

      assert.strictEqual(validateMessagePhase(ctx, "chat").allowed, false);
      assert.strictEqual(validateMessagePhase(ctx, "file_offer").allowed, false);
      assert.strictEqual(validateMessagePhase(ctx, "rpc_request").allowed, false);
      assert.strictEqual(validateMessagePhase(ctx, "pair_verify").allowed, true);
    });

    test("Connection phase: authenticated forbids handshake frames", () => {
      const ctx = createConnectionContext({ socket: {} });
      setConnectionPhase(ctx, "authenticated");

      assert.strictEqual(validateMessagePhase(ctx, "client_hello").allowed, false);
      assert.strictEqual(validateMessagePhase(ctx, "pair_request").allowed, false);
      assert.strictEqual(validateMessagePhase(ctx, "chat").allowed, true);
      assert.strictEqual(validateMessagePhase(ctx, "rpc_request").allowed, true);
    });

    test("Per-connection message deduplication cache", () => {
      const ctx = createConnectionContext({ socket: {} });
      assert.strictEqual(checkMessageDeduplication(ctx, "msg-001"), true);
      assert.strictEqual(checkMessageDeduplication(ctx, "msg-001"), false);
      assert.strictEqual(checkMessageDeduplication(ctx, "msg-002"), true);
    });
  });

  // ── 3. Capability Enforcement & Execution Grants ──────────────────────────

  describe("3. Capability Enforcement & Execution Grants", () => {
    test("Action capability mapping strictly matches security policy", () => {
      const baseChat = { type: "chat", version: 5, id: "1", text: "hi", ts: Date.now() };
      assert.strictEqual(isActionPermitted({ ...DEFAULT_PERMISSIONS, message: true }, baseChat).permitted, true);
      assert.strictEqual(isActionPermitted({ ...DEFAULT_PERMISSIONS, message: false }, baseChat).permitted, false);

      const baseInspect = { type: "rpc_request", version: 5, id: "2", to: "hub", action: "git_status", ts: Date.now() };
      assert.strictEqual(isActionPermitted({ ...DEFAULT_PERMISSIONS, inspect: false }, baseInspect).permitted, false);
      assert.strictEqual(isActionPermitted({ ...DEFAULT_PERMISSIONS, inspect: true }, baseInspect).permitted, true);

      const baseExec = { type: "rpc_request", version: 5, id: "3", to: "hub", action: "exec", params: { command: "ls" }, ts: Date.now() };
      assert.strictEqual(isActionPermitted({ ...DEFAULT_PERMISSIONS, execRequest: false }, baseExec).permitted, false);
      assert.strictEqual(isActionPermitted({ ...DEFAULT_PERMISSIONS, execRequest: true }, baseExec).permitted, true);
    });

    test("Authoritative origin derivation ignores claimed sender in wire message", () => {
      const ctx = createConnectionContext({ socket: {} });
      ctx.principalId = "ed25519-sha256:AUTHENTICATED_KEY_123";
      ctx.displayName = "real-node";

      const spoofedMsg = {
        type: "chat",
        version: 5,
        id: "s-1",
        from: "spoofed-admin",
        to: "hub",
        text: "hello",
        ts: Date.now(),
      };

      const bound = bindMessageOrigin(spoofedMsg, ctx);
      assert.strictEqual(bound.from, "real-node");
      assert.strictEqual(bound.originPrincipalId, "ed25519-sha256:AUTHENTICATED_KEY_123");
    });

    test("Execution grants are keyed by principalId and expire after single use", () => {
      const principal = "ed25519-sha256:TEST_DEV_KEY";
      revokeAllGrants();

      // Blocked before grant
      assert.strictEqual(checkAndConsumeExecGrant(principal).allowed, false);

      // Create single-use grant
      const grant = createExecGrant(principal, "test-peer", { maxUses: 1, durationMs: 10_000 });
      assert.strictEqual(grant.principalId, principal);
      assert.strictEqual(grant.remainingUses, 1);

      // First use succeeds
      const check1 = checkAndConsumeExecGrant(principal);
      assert.strictEqual(check1.allowed, true);

      // Second use fails (single use exhausted)
      const check2 = checkAndConsumeExecGrant(principal);
      assert.strictEqual(check2.allowed, false);
      assert.match(check2.reason, /No active execution grant found/);
    });

    test("Execution grants revoked immediately on peer disconnect", () => {
      const principal = "ed25519-sha256:DISCONNECT_TEST";
      createExecGrant(principal, "peer-disc", { maxUses: 5, durationMs: 60_000 });
      assert.strictEqual(getActiveGrants().some((g) => g.principalId === principal), true);

      // Revoke on disconnect
      const revokedCount = revokeGrantsForPrincipal(principal, "Peer disconnected");
      assert.strictEqual(revokedCount, 1);
      assert.strictEqual(checkAndConsumeExecGrant(principal).allowed, false);
    });

    test("A new peer reusing the display name does NOT inherit another device's grant", () => {
      const oldPrincipal = "ed25519-sha256:OLD_DEVICE";
      const newPrincipal = "ed25519-sha256:NEW_DEVICE_SAME_NAME";
      createExecGrant(oldPrincipal, "worker-node", { maxUses: 5 });

      // Check with new principal fails even if display name was identical
      const check = checkAndConsumeExecGrant(newPrincipal);
      assert.strictEqual(check.allowed, false);
    });
  });

  // ── 4. Workspace Canonical Path Confinement & Inspection ───────────────────

  describe("4. Workspace Path Confinement & Inspection Security", () => {
    test("Blocks directory traversal and path escapes", () => {
      const res1 = resolveConfinedPath(tempDir, "../../etc/passwd");
      assert.strictEqual(res1.allowed, false);
      assert.match(res1.reason, /escape[sd]? workspace root/i);

      const res2 = resolveConfinedPath(tempDir, "valid-file.txt\0.js");
      assert.strictEqual(res2.allowed, false);
      assert.match(res2.reason, /Null bytes forbidden/);
    });

    test("Blocks sensitive file patterns (.env, keys, credentials)", () => {
      const sensitiveList = [
        ".env",
        ".env.production",
        "id_rsa",
        "id_ed25519",
        "cert.pem",
        "server.key",
        "credentials.json",
        ".git/config",
      ];
      for (const s of sensitiveList) {
        assert.strictEqual(isSensitivePath(s), true, `Expected sensitive: ${s}`);
        const res = resolveConfinedPath(tempDir, s);
        assert.strictEqual(res.allowed, false);
        assert.match(res.reason, /sensitive file or pattern/);
      }
    });

    test("safeGitExecFile sanitizes environment and enforces security flags", async () => {
      process.env.LD_PRELOAD = "/malicious/preload.so";
      process.env.NODE_OPTIONS = "--inspect";

      await new Promise((resolve) => {
        safeGitExecFile(["status", "--porcelain=v1"], { cwd: tempDir }, (err, stdout, stderr, cleanEnv, finalArgs) => {
          assert.strictEqual(cleanEnv.LD_PRELOAD, undefined);
          assert.strictEqual(cleanEnv.NODE_OPTIONS, undefined);
          assert.strictEqual(cleanEnv.GIT_CONFIG_NOSYSTEM, "1");
          assert.ok(finalArgs.includes("core.fsmonitor=false"));
          assert.ok(finalArgs.includes("diff.external="));
          delete process.env.LD_PRELOAD;
          delete process.env.NODE_OPTIONS;
          resolve();
        });
      });
    });

    test("safeReadFile bounds maximum byte read without allocating entire file", async () => {
      const testFile = path.join(tempDir, "large-test.txt");
      fs.writeFileSync(testFile, Buffer.alloc(100 * 1024, "X"));

      const readRes = await safeReadFile(tempDir, "large-test.txt", 1024);
      assert.strictEqual(readRes.ok, true);
      assert.strictEqual(readRes.content.length, 1024);
      assert.strictEqual(readRes.truncated, true);
    });

    test("safeGitGrep excludes sensitive files and limits pattern length", async () => {
      const hugePattern = "a".repeat(600);
      const longRes = await safeGitGrep(tempDir, hugePattern);
      assert.strictEqual(longRes.ok, false);
      assert.match(longRes.error, /exceeds 512 characters/);
    });
  });

  // ── 5. File Transfer Quarantine & Streaming ────────────────────────────────

  describe("5. File Transfer Quarantine & Streaming Hardening", () => {
    let receiver;

    before(() => {
      receiver = new TransferReceiver(tempDir);
    });

    test("Rejects invalid offer sizes, negative values, and chunk count mismatches", () => {
      const badSizeOffer = {
        type: "file_offer",
        version: 5,
        id: "1",
        transferId: "tx-bad-size",
        from: "peer",
        to: "hub",
        filename: "test.bin",
        sizeBytes: -10,
        totalChunks: 1,
        sha256: "a".repeat(64),
        ts: Date.now(),
      };
      assert.strictEqual(receiver.handleOffer(badSizeOffer).ok, false);

      const badChunkOffer = {
        ...badSizeOffer,
        transferId: "tx-bad-chunks",
        sizeBytes: 100_000,
        totalChunks: 999, // mismatch with Math.ceil(100000 / 65536) = 2
      };
      assert.strictEqual(receiver.handleOffer(badChunkOffer).ok, false);
    });

    test("Enforces sequential chunk order and binds sender to offer", () => {
      const content = Buffer.from("Hello Secure Mesh Chunk Ordering!");
      const sha256 = crypto.createHash("sha256").update(content).digest("hex");
      const offer = {
        type: "file_offer",
        version: 5,
        id: "off-1",
        transferId: "tx-order-test",
        from: "sender-a",
        to: "hub",
        filename: "data.txt",
        sizeBytes: content.length,
        totalChunks: 1,
        sha256,
        ts: Date.now(),
      };

      const offerRes = receiver.handleOffer(offer);
      assert.strictEqual(offerRes.ok, true);

      // Wrong sender rejected
      const wrongSenderChunk = {
        type: "file_chunk",
        version: 5,
        id: "c-1",
        transferId: "tx-order-test",
        from: "adversary",
        to: "hub",
        chunkIndex: 0,
        totalChunks: 1,
        data: content.toString("base64"),
        ts: Date.now(),
      };
      const resWrongSender = receiver.handleChunk(wrongSenderChunk);
      assert.strictEqual(resWrongSender.ok, false);
      assert.match(resWrongSender.error, /Sender does not match/);
    });

    test("Atomic move to quarantine outside workspace and verifies SHA-256", () => {
      const content = Buffer.from("Streaming transfer with direct-to-disk verification");
      const sha256 = crypto.createHash("sha256").update(content).digest("hex");
      const transferId = `tx-verify-${Date.now()}`;

      const offer = {
        type: "file_offer",
        version: 5,
        id: "off-2",
        transferId,
        from: "sender-valid",
        to: "hub",
        filename: "verify.txt",
        sizeBytes: content.length,
        totalChunks: 1,
        sha256,
        ts: Date.now(),
      };

      assert.strictEqual(receiver.handleOffer(offer).ok, true);

      const chunk = {
        type: "file_chunk",
        version: 5,
        id: "c-0",
        transferId,
        from: "sender-valid",
        to: "hub",
        chunkIndex: 0,
        totalChunks: 1,
        data: content.toString("base64"),
        ts: Date.now(),
      };

      const res = receiver.handleChunk(chunk);
      assert.strictEqual(res.complete, true);
      assert.strictEqual(res.ok, true);
      assert.ok(res.finalPath);
      assert.strictEqual(fs.readFileSync(res.finalPath, "utf8"), content.toString("utf8"));
      // Quarantine is inside ~/.omp/inbox, NOT inside working tree
      assert.ok(res.finalPath.includes(path.join(tempDir, "inbox")));
    });

    test("Sender computes streaming hash without allocating entire file", async () => {
      const srcFile = path.join(tempDir, "sender-test.bin");
      const buf = crypto.randomBytes(128 * 1024);
      fs.writeFileSync(srcFile, buf);

      const info = await computeFileHashStreaming(srcFile);
      const expectedSha = crypto.createHash("sha256").update(buf).digest("hex");
      assert.strictEqual(info.sha256, expectedSha);
      assert.strictEqual(info.sizeBytes, 128 * 1024);
      assert.strictEqual(info.totalChunks, 2);
    });
  });

  // ── 6. Discovery & Status Endpoint Sanitization ───────────────────────────

  describe("6. Discovery & Minimal Public Status", () => {
    test("Status headers include no-store, CSP none, and nosniff", async () => {
      const testPort = 19945;
      const node = new LinkNode({
        port: testPort,
        customOmpDir: tempDir,
      });

      await node.startHub();

      const https = await import("node:https");
      const agent = new https.Agent({ rejectUnauthorized: false, minVersion: "TLSv1.3" });

      const res = await new Promise((resolve, reject) => {
        https.get(`https://127.0.0.1:${testPort}/status`, { agent }, (resp) => {
          let data = "";
          resp.on("data", (chunk) => data += chunk);
          resp.on("end", () => resolve({ headers: resp.headers, body: JSON.parse(data) }));
          resp.on("error", reject);
        });
      });

      assert.strictEqual(res.headers["cache-control"], "no-store");
      assert.strictEqual(res.headers["content-security-policy"], "default-src 'none'");
      assert.strictEqual(res.headers["x-content-type-options"], "nosniff");

      // Payload is minimal & public
      assert.strictEqual(res.body.service, "omp-link");
      assert.strictEqual(res.body.protocolVersion, 5);
      assert.strictEqual(res.body.pairingAvailable, true);
      assert.strictEqual(res.body.transport, "wss");
      assert.strictEqual(typeof res.body.certificateFingerprint, "string");

      // NO terminals, NO cwds, NO paths, NO secrets leaked
      assert.strictEqual(res.body.terminals, undefined);
      assert.strictEqual(res.body.cwd, undefined);
      assert.strictEqual(res.body.pin, undefined);

      await node.stop();
    });
  });

  // ── 7. Mutual TLS Loopback Integration ────────────────────────────────────

  describe("7. Mutual TLS 1.3 Loopback Integration", () => {
    test("Hub and client perform full mutual TLS 1.3 handshake and exchange authenticated frames", async () => {
      const testPort = 19946;
      const hubDir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-dir-"));
      const clientDir = fs.mkdtempSync(path.join(os.tmpdir(), "client-dir-"));

      const hub = new LinkNode({
        port: testPort,
        customOmpDir: hubDir,
        terminalName: "hub-node",
      });

      const client = new LinkNode({
        port: 0,
        customOmpDir: clientDir,
        terminalName: "client-node",
      });

      await hub.startHub();

      // Pre-pair client on hub to allow immediate authentication
      const clientIdentity = client.identity;
      const pairedClient = {
        principalId: clientIdentity.principalId,
        fingerprint: clientIdentity.fingerprint,
        certPem: clientIdentity.certPem,
        deviceName: "client-node",
        permissions: FULL_PERMISSIONS,
        pairedAt: Date.now(),
      };
      savePairedDevice(pairedClient, hubDir);

      let receivedOnHub = null;
      hub.onMessage = (msg) => {
        receivedOnHub = msg;
      };

      await client.connectToHub(`wss://127.0.0.1:${testPort}`, hub.identity.fingerprint);

      // Wait for authentication
      await new Promise((r) => setTimeout(r, 200));

      // Client sends authenticated message to hub
      const sent = client.sendMessage("hub-node", "Hello from Mutual TLS client!");
      assert.strictEqual(sent, true);

      // Wait for receipt
      await new Promise((r) => setTimeout(r, 300));
      assert.ok(receivedOnHub);
      assert.strictEqual(receivedOnHub.text, "Hello from Mutual TLS client!");
      assert.strictEqual(receivedOnHub.from, "client-node");
      assert.strictEqual(receivedOnHub.originPrincipalId, clientIdentity.principalId);

      // Clean up
      await client.stop();
      await hub.stop();
      fs.rmSync(hubDir, { recursive: true, force: true });
      fs.rmSync(clientDir, { recursive: true, force: true });
    });
  });
});
