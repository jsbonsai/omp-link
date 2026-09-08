import { test, describe } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";

import { parseWireMessage, PROTOCOL_VERSION, sanitizeDisplayName } from "../../src/protocol-schema.js";
import { createConnectionContext, validateMessagePhase, checkMessageDeduplication } from "../../src/connection-state.js";
import { TransferReceiver, MAX_FILE_SIZE } from "../../src/transfer-receiver.js";
import { resolveConfinedPath } from "../../src/inspection.js";

describe("OMP-LINK v5 Fuzzing & Boundary Hardening", () => {
  test("Protocol parser fuzz: rejects random garbage strings and binary", () => {
    for (let i = 0; i < 50; i++) {
      const garbage = crypto.randomBytes(64 + Math.floor(Math.random() * 512)).toString("binary");
      const res = parseWireMessage(garbage);
      assert.strictEqual(res.ok, false);
      assert.strictEqual(res.closeCode, 4400);
    }
  });

  test("Numeric boundary fuzz: NaN, Infinity, fractions, negative sizes", () => {
    const receiver = new TransferReceiver();
    const weirdNumbers = [
      NaN,
      Infinity,
      -Infinity,
      -1,
      0,
      1.5,
      3.14159,
      MAX_FILE_SIZE + 1,
      Number.MAX_SAFE_INTEGER + 1,
      Number.MIN_SAFE_INTEGER,
    ];

    for (const n of weirdNumbers) {
      const offer = {
        type: "file_offer",
        version: 5,
        id: "fuzz",
        transferId: `tx-fuzz-${Math.random()}`,
        from: "fuzzer",
        to: "hub",
        filename: "fuzz.bin",
        sizeBytes: n,
        totalChunks: 1,
        sha256: "a".repeat(64),
        ts: Date.now(),
      };
      const res = receiver.handleOffer(offer);
      assert.strictEqual(res.ok, false, `Expected rejection for sizeBytes = ${n}`);
    }
  });

  test("Display name sanitization: fuzzes control characters and ANSI sequences", () => {
    for (let i = 0; i < 32; i++) {
      const ctrlChar = String.fromCharCode(i);
      const input = `node${ctrlChar}peer`;
      const cleaned = sanitizeDisplayName(input);
      assert.strictEqual(cleaned.includes(ctrlChar), false);
    }

    const ansiCases = [
      "\x1B[31mRed\x1B[0m",
      "\x1B[2J\x1B[HClear",
      "\x1B]0;Title\x07",
    ];
    for (const a of ansiCases) {
      const cleaned = sanitizeDisplayName(a);
      assert.strictEqual(cleaned.includes("\x1B"), false);
    }
  });

  test("Path confinement fuzz: null bytes and deep traversal permutations", () => {
    const traversals = [
      "../../../../etc/passwd",
      "..\\..\\..\\windows\\system32",
      "foo/../../../../root",
      "test\0.txt",
      "valid/path/../../../secret",
      "/etc/shadow",
      "C:\\Windows\\System32",
    ];

    for (const t of traversals) {
      const res = resolveConfinedPath(process.cwd(), t);
      assert.strictEqual(res.allowed, false, `Expected path confinement rejection for: ${t}`);
    }
  });

  test("Message deduplication cache stress: 2,000 sequential message IDs", () => {
    const ctx = createConnectionContext({ socket: {} });
    for (let i = 0; i < 2000; i++) {
      const id = `msg-id-${i}`;
      assert.strictEqual(checkMessageDeduplication(ctx, id), true);
      assert.strictEqual(checkMessageDeduplication(ctx, id), false);
    }
    // Set size bounded
    assert.ok(ctx.seenMessageIds.size <= 1000);
  });
});
