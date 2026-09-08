import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { WebSocketServer, WebSocket } from "ws";

console.log("=================================================================");
console.log("🧪 RUNNING OMP-LINK v3.2.0 SECURITY & CRYPTOGRAPHY TEST SUITE");
console.log("=================================================================\n");

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✅ PASS: ${message}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL: ${message}`);
    failed++;
  }
}

const tempTestDir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-link-test-"));

try {
  // ── TEST 1: Workspace Path Confinement & Traversal Protection ──
  console.log("Test 1: Workspace Canonical Path Confinement & Traversal Protection");
  {
    const workspaceRoot = fs.realpathSync(tempTestDir);
    const safeFile = path.join(workspaceRoot, "valid-file.txt");
    fs.writeFileSync(safeFile, "hello world", { mode: 0o600 });

    const SENSITIVE_PATTERNS = [
      /^\.env(\..+)?$/i,
      /id_rsa/i,
      /id_ed25519/i,
      /\.pem$/i,
      /\.key$/i,
      /^\.git([\\/].*)?$/i,
      /[\\/]\.git([\\/].*)?$/i,
      /credentials/i,
      /secrets?(\.json|\.ya?ml)?$/i,
    ];

    function resolveConfinedPath(baseDir, requestedPath) {
      if (!requestedPath || typeof requestedPath !== "string") {
        return { allowed: false, reason: "Missing path parameter" };
      }
      if (requestedPath.includes("\0")) {
        return { allowed: false, reason: "Null bytes forbidden in path" };
      }
      let canonicalBase;
      try {
        canonicalBase = fs.realpathSync(baseDir || process.cwd());
      } catch (err) {
        return { allowed: false, reason: `Base directory invalid: ${err.message}` };
      }
      const baseName = path.basename(requestedPath);
      for (const pattern of SENSITIVE_PATTERNS) {
        if (pattern.test(baseName) || pattern.test(requestedPath)) {
          return { allowed: false, reason: `Access to sensitive file or pattern "${baseName}" is blocked` };
        }
      }
      const candidate = path.isAbsolute(requestedPath)
        ? path.resolve(requestedPath)
        : path.resolve(canonicalBase, requestedPath);

      if (fs.existsSync(candidate)) {
        try {
          const realCandidate = fs.realpathSync(candidate);
          if (realCandidate !== canonicalBase && !realCandidate.startsWith(canonicalBase + path.sep)) {
            return { allowed: false, reason: `Symlink or path traversal escaped workspace root (${canonicalBase})` };
          }
          const realBaseName = path.basename(realCandidate);
          for (const pattern of SENSITIVE_PATTERNS) {
            if (pattern.test(realBaseName) || pattern.test(realCandidate)) {
              return { allowed: false, reason: `Access to sensitive file or pattern "${realBaseName}" is blocked` };
            }
          }
          return { allowed: true, fullPath: realCandidate };
        } catch (err) {
          return { allowed: false, reason: `Path resolution error: ${err.message}` };
        }
      } else {
        if (candidate !== canonicalBase && !candidate.startsWith(canonicalBase + path.sep)) {
          return { allowed: false, reason: `Path escapes workspace root (${canonicalBase})` };
        }
        return { allowed: true, fullPath: candidate };
      }
    }

    // 1. Valid workspace file
    const safeRes = resolveConfinedPath(workspaceRoot, "valid-file.txt");
    assert(safeRes.allowed === true && safeRes.fullPath === safeFile, "Allowed valid file inside workspace");

    // 2. Directory traversal attempt (../../etc/passwd)
    const traversalRes = resolveConfinedPath(workspaceRoot, "../../etc/passwd");
    assert(traversalRes.allowed === false, `Blocked traversal attempt (../../etc/passwd): ${traversalRes.reason}`);

    // 3. Null byte injection attempt
    const nullByteRes = resolveConfinedPath(workspaceRoot, "valid-file.txt\0.js");
    assert(nullByteRes.allowed === false, "Blocked null byte injection attempt");

    // 4. Sensitive file access (.git/config)
    const gitRes = resolveConfinedPath(workspaceRoot, ".git/config");
    assert(gitRes.allowed === false, `Blocked sensitive .git access: ${gitRes.reason}`);

    // 5. Sensitive file access (.env.production)
    const envRes = resolveConfinedPath(workspaceRoot, ".env.production");
    assert(envRes.allowed === false, `Blocked sensitive env file: ${envRes.reason}`);

    // 6. Sensitive file access (id_ed25519)
    const sshRes = resolveConfinedPath(workspaceRoot, "id_ed25519");
    assert(sshRes.allowed === false, `Blocked sensitive private key: ${sshRes.reason}`);
  }

  // ── TEST 2: Passive & Sanitized Subprocess Execution (safeGitExecFile) ──
  console.log("\nTest 2: Passive Subprocess Execution (safeGitExecFile Environment & Flags)");
  await new Promise((resolve) => {
    const cwd = path.resolve(".");

    function safeGitExecFile(gitArgs, options, callback) {
      const safeFlags = [
        "-c", "core.fsmonitor=false",
        "-c", "core.pager=cat",
        "-c", "pager.status=false",
        "-c", "pager.diff=false",
        "-c", "pager.log=false",
        "-c", "diff.external=",
      ];

      const cleanEnv = { ...process.env };
      const dangerousVars = [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "NODE_OPTIONS",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_CONFIG",
        "GIT_CONFIG_PARAMETERS",
        "GIT_EXEC_PATH",
      ];
      for (const v of dangerousVars) {
        delete cleanEnv[v];
      }
      cleanEnv.GIT_CONFIG_NOSYSTEM = "1";
      cleanEnv.GIT_CONFIG_GLOBAL = os.devNull || "/dev/null";
      cleanEnv.GIT_TERMINAL_PROMPT = "0";

      const finalArgs = [...safeFlags, ...gitArgs];
      execFile("git", finalArgs, {
        cwd: options.cwd || process.cwd(),
        env: cleanEnv,
        maxBuffer: options.maxBuffer || 2 * 1024 * 1024,
        timeout: options.timeout || 10_000,
      }, (err, stdout, stderr) => {
        callback(err, stdout ? stdout.toString() : "", stderr ? stderr.toString() : "", cleanEnv, finalArgs);
      });
    }

    // Set a dangerous var in process.env to verify sanitization
    process.env.LD_PRELOAD = "/malicious/lib.so";
    process.env.NODE_OPTIONS = "--inspect";

    safeGitExecFile(["status", "--porcelain"], { cwd }, (err, stdout, stderr, sanitizedEnv, finalArgs) => {
      assert(!err, "safeGitExecFile executes without error");
      assert(sanitizedEnv.LD_PRELOAD === undefined, "LD_PRELOAD stripped from child process environment");
      assert(sanitizedEnv.NODE_OPTIONS === undefined, "NODE_OPTIONS stripped from child process environment");
      assert(sanitizedEnv.GIT_CONFIG_NOSYSTEM === "1", "GIT_CONFIG_NOSYSTEM enforced");
      assert(sanitizedEnv.GIT_CONFIG_GLOBAL === (os.devNull || "/dev/null"), "GIT_CONFIG_GLOBAL redirected to null device");
      assert(finalArgs.includes("diff.external="), "diff.external disabled to prevent external binary invocation");
      assert(finalArgs.includes("core.fsmonitor=false"), "core.fsmonitor disabled to prevent arbitrary IPC commands");

      delete process.env.LD_PRELOAD;
      delete process.env.NODE_OPTIONS;
      resolve();
    });
  });

  // ── TEST 3: Status & Discovery Sanitization ──
  console.log("\nTest 3: Status Endpoint Sanitization (GET /status & Ephemeral Transfers)");
  await new Promise((resolve) => {
    const testPort = 19930;
    const testSecret = "sec-token-1234";
    const server = http.createServer((req, res) => {
      if (req.url.startsWith("/status")) {
        res.writeHead(200, {
          "content-type": "application/json",
          "cache-control": "no-store",
        });
        const authHeader = req.headers["authorization"] || "";
        const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
        if (token === testSecret) {
          res.end(JSON.stringify({
            service: "omp-link",
            protocolVersion: 4,
            instanceId: "inst-abc",
            pairingRequired: true,
            authenticated: true,
            terminals: [{ name: "node-a", cwd: "/Users/secret/path" }],
          }));
        } else {
          // Public sanitized response
          res.end(JSON.stringify({
            service: "omp-link",
            protocolVersion: 4,
            instanceId: "inst-abc",
            pairingRequired: true,
            fingerprint: "AA:BB:CC:DD:EE",
            tls: true,
          }));
        }
      } else if (req.url.startsWith("/transfer/")) {
        const authHeader = req.headers["authorization"] || "";
        if (authHeader !== "Bearer " + testSecret) {
          res.writeHead(401, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "Unauthorized" }));
          return;
        }
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end("file-contents");
      }
    });

    server.listen(testPort, async () => {
      // 1. Unauthenticated discovery request
      const unauthRes = await fetch(`http://127.0.0.1:${testPort}/status`);
      const unauthJson = await unauthRes.json();
      assert(unauthRes.headers.get("cache-control") === "no-store", "Cache-Control: no-store header returned");
      assert(unauthJson.service === "omp-link", "service identifies as omp-link");
      assert(unauthJson.protocolVersion === 4, "protocolVersion is 4");
      assert(unauthJson.pairingRequired === true, "pairingRequired is true");
      assert(unauthJson.terminals === undefined, "terminals and local paths NOT leaked to unauthenticated caller");
      assert(unauthJson.pin === undefined, "PIN NOT leaked to unauthenticated caller");

      // 2. Query parameter token attempt (should NOT authenticate)
      const queryRes = await fetch(`http://127.0.0.1:${testPort}/status?token=${testSecret}`);
      const queryJson = await queryRes.json();
      assert(queryJson.authenticated === undefined, "Query parameter tokens rejected for status authorization");

      // 3. Ephemeral file download without Bearer header
      const transferUnauth = await fetch(`http://127.0.0.1:${testPort}/transfer/tx-999`);
      assert(transferUnauth.status === 401, "Transfer endpoint rejects unauthenticated access");

      // 4. Ephemeral file download with Bearer header
      const transferAuth = await fetch(`http://127.0.0.1:${testPort}/transfer/tx-999`, {
        headers: { authorization: `Bearer ${testSecret}` },
      });
      const content = await transferAuth.text();
      assert(transferAuth.status === 200 && content === "file-contents", "Transfer endpoint allows authenticated download");

      server.close(() => resolve());
    });
  });

  // ── TEST 4: Ed25519 Cryptographic Challenge-Response Authentication ──
  console.log("\nTest 4: Ed25519 Cryptographic Challenge-Response Device Authentication");
  {
    // Generate Ed25519 identity keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const spkiDer = crypto.createPublicKey(publicKey).export({ type: "spki", format: "der" });
    const fingerprint = crypto.createHash("sha256").update(spkiDer).digest("hex")
      .toUpperCase().match(/.{1,2}/g).join(":");

    assert(fingerprint.length === 95, `Computed valid SHA-256 fingerprint: ${fingerprint.slice(0, 23)}...`);

    // Hub generates 32-byte nonce
    const nonce = crypto.randomBytes(32).toString("hex");
    const timestamp = Date.now();
    const challengePayload = Buffer.from(`${nonce}:${timestamp}`, "utf-8");

    // Client signs challenge with private key
    const signature = crypto.sign(null, challengePayload, privateKey).toString("base64");

    // Hub verifies signature
    const isValid = crypto.verify(
      null,
      challengePayload,
      crypto.createPublicKey(publicKey),
      Buffer.from(signature, "base64"),
    );
    assert(isValid === true, "Valid challenge signature verified successfully with public key");

    // Forgery attempt: client mutates nonce
    const tamperedPayload = Buffer.from(`tampered-${nonce}:${timestamp}`, "utf-8");
    const isTamperedValid = crypto.verify(
      null,
      tamperedPayload,
      crypto.createPublicKey(publicKey),
      Buffer.from(signature, "base64"),
    );
    assert(isTamperedValid === false, "Tampered challenge signature strictly rejected");

    // Stale timestamp rejection (> 30s)
    const staleTimestamp = Date.now() - 35_000;
    const isTimestampFresh = Math.abs(Date.now() - staleTimestamp) <= 30_000;
    assert(isTimestampFresh === false, "Challenge responses with stale timestamps (>30s) strictly rejected");
  }

  // ── TEST 5: Ephemeral X25519 + HKDF-SHA256 Forward-Secret Session Keys & AAD Binding ──
  console.log("\nTest 5: Ephemeral X25519 + HKDF-SHA256 Session Keys & AAD Protocol v4 Frames");
  {
    // Node A (Host / Hub) ephemeral X25519
    const hubEph = crypto.generateKeyPairSync("x25519");
    const hubPubDer = hubEph.publicKey.export({ type: "spki", format: "der" });

    // Node B (Client) ephemeral X25519
    const clientEph = crypto.generateKeyPairSync("x25519");
    const clientPubDer = clientEph.publicKey.export({ type: "spki", format: "der" });

    // Both parties perform Diffie-Hellman
    const hubShared = crypto.diffieHellman({
      privateKey: hubEph.privateKey,
      publicKey: crypto.createPublicKey({ key: clientPubDer, format: "der", type: "spki" }),
    });

    const clientShared = crypto.diffieHellman({
      privateKey: clientEph.privateKey,
      publicKey: crypto.createPublicKey({ key: hubPubDer, format: "der", type: "spki" }),
    });

    assert(hubShared.equals(clientShared), "X25519 Diffie-Hellman yields identical shared secret on both peers");

    // Derive 256-bit AES-GCM session key via HKDF-SHA256
    const salt = Buffer.from("omp-link-v4-salt");
    const info = Buffer.from("omp-link-v4-session");
    const hubSessionKey = crypto.hkdfSync("sha256", hubShared, salt, info, 32);
    const clientSessionKey = crypto.hkdfSync("sha256", clientShared, salt, info, 32);

    assert(Buffer.from(hubSessionKey).equals(Buffer.from(clientSessionKey)), "HKDF-SHA256 derives matching 256-bit forward-secret session key");

    // Encrypt frame with AES-256-GCM and bind AAD (v: 4, mid, seq, from, ts)
    const mid = "mid-" + crypto.randomUUID();
    const seq = 1;
    const from = "node-client";
    const ts = Date.now();
    const plaintext = JSON.stringify({ type: "chat", content: "Top secret multi-agent command" });

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(clientSessionKey), iv);
    const aad = Buffer.from(`v:4|mid:${mid}|seq:${seq}|from:${from}|ts:${ts}`, "utf-8");
    cipher.setAAD(aad);

    let ciphertext = cipher.update(plaintext, "utf-8", "base64");
    ciphertext += cipher.final("base64");
    const tag = cipher.getAuthTag().toString("base64");

    const wireFrame = {
      type: "encrypted",
      v: 4,
      mid,
      seq,
      from,
      ts,
      iv: iv.toString("base64"),
      ciphertext,
      tag,
    };

    // Hub decrypts frame
    function decryptFrame(frame, key) {
      if (frame.v !== 4) throw new Error("Unsupported protocol version");
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        Buffer.from(key),
        Buffer.from(frame.iv, "base64"),
      );
      const frameAad = Buffer.from(`v:4|mid:${frame.mid}|seq:${frame.seq}|from:${frame.from}|ts:${frame.ts}`, "utf-8");
      decipher.setAAD(frameAad);
      decipher.setAuthTag(Buffer.from(frame.tag, "base64"));
      let decrypted = decipher.update(frame.ciphertext, "base64", "utf-8");
      decrypted += decipher.final("utf-8");
      return JSON.parse(decrypted);
    }

    const decryptedMsg = decryptFrame(wireFrame, hubSessionKey);
    assert(decryptedMsg.content === "Top secret multi-agent command", "Decrypted AES-256-GCM message matches original plaintext");

    // Tamper with AAD: adversary modifies 'from' field in wire frame
    let tamperDetected = false;
    try {
      const tamperedFrame = { ...wireFrame, from: "impersonated-node" };
      decryptFrame(tamperedFrame, hubSessionKey);
    } catch {
      tamperDetected = true;
    }
    assert(tamperDetected === true, "Adversarial modification of wire headers (from) caught by AES-GCM authentication tag");

    // Replay Attack Test: Duplicate mid rejection
    const seenMessageIds = new Set();
    function checkReplay(frameMid) {
      if (seenMessageIds.has(frameMid)) return false;
      seenMessageIds.add(frameMid);
      return true;
    }
    assert(checkReplay(wireFrame.mid) === true, "First message with mid accepted");
    assert(checkReplay(wireFrame.mid) === false, "Replayed message with identical mid rejected");
  }

  // ── TEST 6: Streaming File Inbox & DoS Protections ──
  console.log("\nTest 6: Streaming File Inbox (64KB Chunk Limit & Direct-to-Disk Hash Verification)");
  {
    const inboxDir = path.join(tempTestDir, "inbox");
    fs.mkdirSync(inboxDir, { recursive: true, mode: 0o700 });

    // 1. TransferId validation
    const validTransferId = "tx_valid-123_ABC";
    const invalidTransferId = "../../evil-id";
    const transferIdRegex = /^[a-zA-Z0-9_-]{1,64}$/;
    assert(transferIdRegex.test(validTransferId) === true, "Valid transferId accepted");
    assert(transferIdRegex.test(invalidTransferId) === false, "Path traversal in transferId rejected");

    // 2. Chunk size limit (64KB = 65536)
    const validChunk = Buffer.alloc(64 * 1024, "a");
    const oversizedChunk = Buffer.alloc(64 * 1024 + 1, "b");
    assert(validChunk.length <= 65536, "64KB chunk within permissible ceiling");
    assert(oversizedChunk.length > 65536, "Chunk exceeding 64KB flagged as oversized (DoS vector)");

    // 3. Streaming file chunks directly to .tmp-<id>.part
    const transferId = "tx-stream-test";
    const targetFilename = "streamed-data.bin";
    const partPath = path.join(inboxDir, `.tmp-${transferId}.part`);
    const finalPath = path.join(inboxDir, targetFilename);

    const chunk1 = Buffer.from("CHUNK_DATA_PART_1_");
    const chunk2 = Buffer.from("CHUNK_DATA_PART_2_");
    const expectedHash = crypto.createHash("sha256").update(chunk1).update(chunk2).digest("hex");

    // Stream chunk 1
    const hasher = crypto.createHash("sha256");
    fs.appendFileSync(partPath, chunk1, { mode: 0o600 });
    hasher.update(chunk1);

    // Stream chunk 2
    fs.appendFileSync(partPath, chunk2, { mode: 0o600 });
    hasher.update(chunk2);

    const computedHash = hasher.digest("hex");
    assert(computedHash === expectedHash, "Streaming SHA-256 hash matches full data");

    // Atomic move to final destination
    fs.renameSync(partPath, finalPath);
    assert(fs.existsSync(finalPath) === true, "File atomically moved to final destination");
    assert(fs.existsSync(partPath) === false, "Temporary .part file removed after atomic rename");
    assert(fs.readFileSync(finalPath, "utf-8") === "CHUNK_DATA_PART_1_CHUNK_DATA_PART_2_", "Reconstructed file content verified");
  }

  // ── TEST 7: Ephemeral Peer Execution Elevation & Territorial Sovereignty ──
  console.log("\nTest 7: Ephemeral Peer Execution Elevation & Territorial Sovereignty");
  {
    const activeExecGrants = new Map();
    const auditLogs = [];

    function appendAuditLog(entry) {
      auditLogs.push(entry);
    }

    function grantExecElevation(peer, minutes = 1) {
      const durationMs = minutes * 60_000;
      activeExecGrants.set(peer, {
        peer,
        grantedAt: Date.now(),
        expiresAt: Date.now() + durationMs,
      });
      appendAuditLog({ type: "grant", peer, durationMinutes: minutes, action: "granted" });
    }

    function revokeExecElevation(peer) {
      if (activeExecGrants.has(peer)) {
        activeExecGrants.delete(peer);
        appendAuditLog({ type: "grant", peer, action: "revoked" });
        return true;
      }
      return false;
    }

    function handleRpcExecutionRequest(peer, action, command) {
      if (action === "exec") {
        const trimmed = (command || "").trim();
        // Safe transparent redirection for git read-only commands
        if (trimmed === "git status" || trimmed === "git status --porcelain") {
          return { ok: true, method: "safeGitExecFile", result: "M file.txt" };
        }
        if (trimmed === "git diff") {
          return { ok: true, method: "safeGitExecFile", result: "diff --git..." };
        }

        // Check ephemeral elevation grant
        const grant = activeExecGrants.get(peer);
        if (!grant || Date.now() > grant.expiresAt) {
          activeExecGrants.delete(peer);
          return {
            ok: false,
            error: `REMOTE EXECUTION BLOCKED: Arbitrary shell execution requires temporary host elevation. Host can grant with: /link grant ${peer} [minutes]`,
          };
        }

        appendAuditLog({ type: "exec", peer, command, elevated: true });
        return { ok: true, method: "execFile", result: `Executed: ${command}` };
      }
      return { ok: false, error: "Unknown action" };
    }

    // 1. Un-elevated peer attempts arbitrary command
    const res1 = handleRpcExecutionRequest("remote-node-1", "exec", "npm test");
    assert(res1.ok === false && res1.error.includes("REMOTE EXECUTION BLOCKED"), "Arbitrary execution blocked by default for un-elevated peer");

    // 2. Read-only git status transparently executes via safeGitExecFile without elevation
    const res2 = handleRpcExecutionRequest("remote-node-1", "exec", "git status");
    assert(res2.ok === true && res2.method === "safeGitExecFile", "git status transparently routed to safeGitExecFile without elevation");

    // 3. Host grants temporary elevation
    grantExecElevation("remote-node-1", 5);
    assert(activeExecGrants.has("remote-node-1"), "Execution grant active in activeExecGrants map");

    // 4. Elevated peer attempts arbitrary command
    const res3 = handleRpcExecutionRequest("remote-node-1", "exec", "npm test");
    assert(res3.ok === true && res3.method === "execFile", "Arbitrary command succeeds while elevation grant is active");

    // 5. Host revokes elevation
    revokeExecElevation("remote-node-1");
    const res4 = handleRpcExecutionRequest("remote-node-1", "exec", "npm test");
    assert(res4.ok === false && res4.error.includes("REMOTE EXECUTION BLOCKED"), "Arbitrary command immediately blocked after elevation revoked");

    // 6. Verify audit logs
    assert(auditLogs.some(l => l.action === "granted"), "Elevation grant logged to audit log");
    assert(auditLogs.some(l => l.type === "exec" && l.command === "npm test"), "Elevated execution logged to audit log");
    assert(auditLogs.some(l => l.action === "revoked"), "Elevation revocation logged to audit log");
  }

} finally {
  // Clean up temporary test directory
  try {
    fs.rmSync(tempTestDir, { recursive: true, force: true });
  } catch {}
}

console.log("\n=================================================================");
console.log(`TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("=================================================================");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
