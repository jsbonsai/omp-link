import * as crypto from "node:crypto";
import * as fs from "node:fs";
import { type FileHandle } from "node:fs/promises";
import { CHUNK_SIZE, MAX_FILE_SIZE } from "./transfer-receiver.js";
import { type FileChunkMsg } from "./protocol-schema.js";

/**
 * `O_NOFOLLOW` makes the kernel refuse the open outright when the final path component is a
 * symlink. That is the refusal `lstat` used to make here, except the check and the read are now
 * the same syscall: the previous shape stat'ed with `lstat` (which does not follow) and then read
 * with `createReadStream` (which does), so a path swapped to a symlink in between was followed.
 * Platforms without the flag fall back to an explicit `lstat` pre-check.
 */
const O_NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

/**
 * Open a path for reading, refusing symlinks, and hand back the handle so every subsequent
 * decision (size, regular-file-ness, the bytes themselves) is made against one fd instead of
 * re-resolving the name. The handle is the caller's to close.
 */
async function openRegularFileNoFollow(filePath: string): Promise<FileHandle> {
  if (O_NOFOLLOW === 0) {
    const link = await fs.promises.lstat(filePath);
    if (link.isSymbolicLink()) {
      throw new Error(`Target is not a regular file: ${filePath}`);
    }
  }
  let handle: FileHandle;
  try {
    handle = await fs.promises.open(filePath, fs.constants.O_RDONLY | O_NOFOLLOW);
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ELOOP") {
      throw new Error(`Target is not a regular file: ${filePath}`);
    }
    throw err;
  }
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) {
      throw new Error(`Target is not a regular file: ${filePath}`);
    }
    return handle;
  } catch (err: unknown) {
    await handle.close().catch(() => {});
    throw err;
  }
}

export async function computeFileHashStreaming(
  filePath: string,
): Promise<{ sha256: string; sizeBytes: number; totalChunks: number }> {
  const handle = await openRegularFileNoFollow(filePath);
  try {
    const stat = await handle.stat();
    if (stat.size > MAX_FILE_SIZE) {
      throw new Error(`File size (${stat.size} bytes) exceeds maximum limit of ${MAX_FILE_SIZE} bytes (50MB)`);
    }
    if (stat.size === 0) {
      throw new Error("Cannot transfer empty file (0 bytes)");
    }

    const hasher = crypto.createHash("sha256");
    const stream = handle.createReadStream({ highWaterMark: CHUNK_SIZE, autoClose: false });
    let hashedBytes = 0;

    try {
      await new Promise<void>((resolve, reject) => {
        stream.on("data", (chunk: Buffer | string) => {
          hashedBytes += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk);
          hasher.update(chunk);
        });
        stream.on("end", () => resolve());
        stream.on("error", (err) => reject(err));
      });
    } finally {
      stream.destroy();
    }

    // The offer announces `sizeBytes` and `sha256` as one claim. If the file moved under the
    // read, they describe different content and the receiver would fail the digest after
    // accepting 50 MB of quota; say so here instead.
    if (hashedBytes !== stat.size) {
      throw new Error(
        `File changed on disk while it was being hashed: ${filePath} was ${stat.size} bytes at open, ${hashedBytes} bytes were read`,
      );
    }

    return { sha256: hasher.digest("hex"), sizeBytes: stat.size, totalChunks: Math.ceil(stat.size / CHUNK_SIZE) };
  } finally {
    await handle.close().catch(() => {});
  }
}

/**
 * Stream a file as `file_chunk` frames.
 *
 * `sizeBytes` and `totalChunks` are the values already announced in the `file_offer`, and this
 * function is the place they become binding. A file that grows between the hash and the stream
 * (an append-mode log, a partial download, a build artifact) would otherwise emit
 * `chunkIndex >= totalChunks` forever at a receiver that aborted on the first extra chunk, and a
 * file that shrank would end the stream early and leave the caller waiting out the full ack
 * timeout. Both now throw; `sendFile` turns the throw into `{ok:false,error}` and drops the
 * pending ack, so the caller learns the real cause immediately.
 *
 * The handle is opened once with `O_NOFOLLOW` and every byte comes from that fd, so the path
 * cannot be swapped for a symlink or another inode mid-stream. A same-size replacement made
 * before this call is still caught downstream by the receiver's sha256 check.
 */
export async function streamFileChunks(
  filePath: string,
  transferId: string,
  from: string,
  to: string,
  totalChunks: number,
  sizeBytes: number,
  sendChunk: (chunk: FileChunkMsg) => boolean | Promise<boolean>,
  checkSocketBuffer?: () => number,
): Promise<void> {
  const handle = await openRegularFileNoFollow(filePath);
  let chunkIndex = 0;
  let bytesSent = 0;

  try {
    const stat = await handle.stat();
    if (stat.size !== sizeBytes) {
      throw new Error(
        `File changed on disk during transfer: ${filePath} is now ${stat.size} bytes, ${sizeBytes} bytes were announced. Nothing was sent.`,
      );
    }

    const stream = handle.createReadStream({ highWaterMark: CHUNK_SIZE, autoClose: false });
    try {
      for await (const chunk of stream) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);

        if (chunkIndex >= totalChunks || bytesSent + buf.length > sizeBytes) {
          throw new Error(
            `File changed on disk during transfer: ${filePath} grew past the announced ${sizeBytes} bytes ` +
              `(${totalChunks} chunks). Stopped after ${chunkIndex} chunk(s); no further data was sent.`,
          );
        }

        const msg: FileChunkMsg = {
          type: "file_chunk",
          version: 5,
          id: `chunk-${transferId}-${chunkIndex}`,
          transferId,
          from,
          to,
          chunkIndex,
          totalChunks,
          data: buf.toString("base64"),
          ts: Date.now(),
        };

        // Backpressure handling
        if (checkSocketBuffer) {
          while (checkSocketBuffer() > 256 * 1024) {
            await new Promise((r) => setTimeout(r, 20));
          }
        }

        await sendChunk(msg);
        bytesSent += buf.length;
        chunkIndex++;
      }
    } finally {
      stream.destroy();
    }

    if (bytesSent !== sizeBytes) {
      throw new Error(
        `File changed on disk during transfer: ${filePath} ended after ${bytesSent} of the announced ${sizeBytes} bytes. ` +
          `The receiver cannot complete this transfer.`,
      );
    }
  } finally {
    await handle.close().catch(() => {});
  }
}
