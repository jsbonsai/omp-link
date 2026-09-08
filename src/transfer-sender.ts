import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { CHUNK_SIZE, MAX_FILE_SIZE } from "./transfer-receiver.js";
import { type FileOfferMsg, type FileChunkMsg } from "./protocol-schema.js";

export async function computeFileHashStreaming(
  filePath: string,
): Promise<{ sha256: string; sizeBytes: number; totalChunks: number }> {
  const stat = await fs.promises.lstat(filePath);
  if (!stat.isFile()) {
    throw new Error(`Target is not a regular file: ${filePath}`);
  }
  if (stat.size > MAX_FILE_SIZE) {
    throw new Error(`File size (${stat.size} bytes) exceeds maximum limit of ${MAX_FILE_SIZE} bytes (50MB)`);
  }
  if (stat.size === 0) {
    throw new Error("Cannot transfer empty file (0 bytes)");
  }

  const hasher = crypto.createHash("sha256");
  const stream = fs.createReadStream(filePath, { highWaterMark: CHUNK_SIZE });

  await new Promise<void>((resolve, reject) => {
    stream.on("data", (chunk: Buffer | string) => {
      hasher.update(chunk);
    });
    stream.on("end", () => resolve());
    stream.on("error", (err) => reject(err));
  });

  const sha256 = hasher.digest("hex");
  const totalChunks = Math.ceil(stat.size / CHUNK_SIZE);

  return { sha256, sizeBytes: stat.size, totalChunks };
}

export async function streamFileChunks(
  filePath: string,
  transferId: string,
  from: string,
  to: string,
  totalChunks: number,
  sendChunk: (chunk: FileChunkMsg) => boolean | Promise<boolean>,
  checkSocketBuffer?: () => number,
): Promise<void> {
  const stream = fs.createReadStream(filePath, { highWaterMark: CHUNK_SIZE });
  let chunkIndex = 0;

  for await (const chunk of stream) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const base64Data = buf.toString("base64");

    const msg: FileChunkMsg = {
      type: "file_chunk",
      version: 5,
      id: `chunk-${transferId}-${chunkIndex}`,
      transferId,
      from,
      to,
      chunkIndex,
      totalChunks,
      data: base64Data,
      ts: Date.now(),
    };

    // Backpressure handling
    if (checkSocketBuffer) {
      while (checkSocketBuffer() > 256 * 1024) {
        await new Promise((r) => setTimeout(r, 20));
      }
    }

    await sendChunk(msg);
    chunkIndex++;
  }
}
