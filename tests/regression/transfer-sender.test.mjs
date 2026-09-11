import { test, describe, before, after } from "node:test";
import assert from "node:assert";
import * as crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { computeFileHashStreaming, streamFileChunks } from "../../src/transfer-sender.js";
import { CHUNK_SIZE } from "../../src/transfer-receiver.js";
import { setCustomAuditLogPath } from "../../src/audit.js";

// Outbound transfers announce `sizeBytes`/`totalChunks`/`sha256` from one stat, then re-open the
// path and stream it. Everything here pins the sender to the numbers it already put on the wire:
// a file that changes between the two reads is a normal thing to hand this tool (an append-mode
// log, a partial download, a build artifact), and the two failure modes it used to produce were
// both silent. Growing made the sender emit `chunkIndex >= totalChunks` for as long as the file
// kept growing, at a receiver that aborted on the first extra chunk without closing the socket.
// Shrinking ended the stream early, so the receiver never completed and the caller sat on the
// 60 s ack timer before reporting a timeout instead of the truth.

/** `sendFile`'s pendingFileAcks timer in src/link-node.ts — the wait these failures used to incur. */
const ACK_TIMEOUT_MS = 60_000;
/** Generous ceiling for "fails fast": two orders of magnitude under the ack timer. */
const FAIL_FAST_BUDGET_MS = 5_000;

let tempDir;

before(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "omplink-sender-"));
  setCustomAuditLogPath(path.join(tempDir, "test-audit.log"));
});

after(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});

function makeFile(name, bytes) {
  const filePath = path.join(tempDir, name);
  fs.writeFileSync(filePath, crypto.randomBytes(bytes));
  return filePath;
}

/** Records every chunk the sender emits; `onChunk` runs after the chunk is accepted. */
function recorder(onChunk) {
  const sent = [];
  return {
    sent,
    send: async (msg) => {
      sent.push(msg);
      if (onChunk) await onChunk(sent.length - 1);
      return true;
    },
  };
}

function stream(filePath, info, sink) {
  return streamFileChunks(filePath, "transfer-1", "sender", "receiver", info.totalChunks, info.sizeBytes, sink.send);
}

describe("REGRESSION R31: a file that grows after the offer is refused, not streamed past its announcement", () => {
  test("growth before the stream opens sends nothing at all", async () => {
    const filePath = makeFile("grew-early.bin", 2 * CHUNK_SIZE);
    const info = await computeFileHashStreaming(filePath);
    assert.strictEqual(info.totalChunks, 2);

    fs.appendFileSync(filePath, crypto.randomBytes(CHUNK_SIZE));

    const sink = recorder();
    await assert.rejects(
      () => stream(filePath, info, sink),
      (err) => {
        assert.match(err.message, /changed on disk during transfer/i);
        assert.match(err.message, new RegExp(`${info.sizeBytes} bytes were announced`));
        // The old failure surfaced as "Transfer ack timeout". Naming the real cause is the fix.
        assert.doesNotMatch(err.message, /timeout/i);
        return true;
      },
    );
    assert.strictEqual(sink.sent.length, 0, "nothing may be sent once the size no longer matches the offer");
  });

  test("growth during the stream stops at the announced chunk count", async () => {
    const filePath = makeFile("grew-midstream.bin", 2 * CHUNK_SIZE);
    const info = await computeFileHashStreaming(filePath);

    // An append-mode log gaining a record while its first chunk is in flight.
    const sink = recorder((index) => {
      if (index === 0) fs.appendFileSync(filePath, crypto.randomBytes(2 * CHUNK_SIZE));
    });

    await assert.rejects(
      () => stream(filePath, info, sink),
      (err) => {
        assert.match(err.message, /changed on disk during transfer/i);
        assert.match(err.message, /grew past the announced/i);
        return true;
      },
    );

    assert.strictEqual(sink.sent.length, info.totalChunks, "the sender must stop at the chunk count it announced");
    for (const msg of sink.sent) {
      assert.ok(msg.chunkIndex < info.totalChunks, `emitted out-of-range chunkIndex ${msg.chunkIndex}`);
    }
  });
});

describe("REGRESSION R32: a file that shrinks fails immediately instead of waiting out the ack timeout", () => {
  test("truncation during the stream reports the short read, fast", async () => {
    const filePath = makeFile("shrank-midstream.bin", 3 * CHUNK_SIZE);
    const info = await computeFileHashStreaming(filePath);
    assert.strictEqual(info.totalChunks, 3);

    const sink = recorder((index) => {
      if (index === 0) fs.truncateSync(filePath, CHUNK_SIZE);
    });

    const started = Date.now();
    await assert.rejects(
      () => stream(filePath, info, sink),
      (err) => {
        assert.match(err.message, /changed on disk during transfer/i);
        assert.match(err.message, new RegExp(`of the announced ${info.sizeBytes} bytes`));
        assert.doesNotMatch(err.message, /timeout/i);
        return true;
      },
    );
    const elapsed = Date.now() - started;

    assert.ok(sink.sent.length < info.totalChunks, "a truncated file cannot have produced every announced chunk");
    assert.ok(
      elapsed < FAIL_FAST_BUDGET_MS,
      `took ${elapsed}ms; the point of the fix is not waiting the ${ACK_TIMEOUT_MS}ms ack timeout`,
    );
  });

  test("truncation before the stream opens sends nothing", async () => {
    const filePath = makeFile("shrank-early.bin", 3 * CHUNK_SIZE);
    const info = await computeFileHashStreaming(filePath);

    fs.truncateSync(filePath, CHUNK_SIZE);

    const sink = recorder();
    await assert.rejects(() => stream(filePath, info, sink), /changed on disk during transfer/i);
    assert.strictEqual(sink.sent.length, 0);
  });
});

describe("REGRESSION R33: the bytes on the wire come from the file that was hashed", () => {
  test("an unchanged file streams exactly what was announced", async () => {
    const filePath = makeFile("stable.bin", 2 * CHUNK_SIZE + 17);
    const info = await computeFileHashStreaming(filePath);
    assert.strictEqual(info.totalChunks, 3);

    const sink = recorder();
    await stream(filePath, info, sink);

    assert.strictEqual(sink.sent.length, info.totalChunks);
    const rebuilt = Buffer.concat(sink.sent.map((msg) => Buffer.from(msg.data, "base64")));
    assert.strictEqual(rebuilt.length, info.sizeBytes);
    assert.strictEqual(crypto.createHash("sha256").update(rebuilt).digest("hex"), info.sha256);
    assert.deepStrictEqual(
      sink.sent.map((msg) => msg.chunkIndex),
      [0, 1, 2],
    );
  });

  test("a symlink is refused by the streamer, not just by the hasher", async () => {
    const target = makeFile("symlink-target.bin", 1024);
    const link = path.join(tempDir, "symlink-to-target.bin");
    fs.symlinkSync(target, link);

    await assert.rejects(() => computeFileHashStreaming(link), /not a regular file/i);

    // The hasher always refused symlinks; the streamer used to follow one, so the offer could
    // describe one inode and the bytes come from another.
    const info = await computeFileHashStreaming(target);
    await assert.rejects(() => stream(link, info, recorder()), /not a regular file/i);
  });
});
