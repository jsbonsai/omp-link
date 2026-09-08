import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getOmpDir } from "./identity.js";
import { type FileOfferMsg, type FileChunkMsg } from "./protocol-schema.js";

export const CHUNK_SIZE = 64 * 1024;
export const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
export const INACTIVITY_TIMEOUT_MS = 30_000;
export const ABSOLUTE_TIMEOUT_MS = 120_000;
export const MAX_CONCURRENT_TRANSFERS = 5;
export const MAX_IN_FLIGHT_PER_PEER = 2;
export const MAX_QUARANTINE_BYTES = 250 * 1024 * 1024; // 250MB

export interface IncomingTransfer {
  transferId: string;
  offer: FileOfferMsg;
  quarantineDir: string;
  tempPath: string;
  finalPath: string;
  fd: number;
  nextExpectedChunk: number;
  receivedBytes: number;
  hasher: crypto.Hash;
  startedAt: number;
  lastActivityAt: number;
  inactivityTimer: NodeJS.Timeout;
  absoluteTimer: NodeJS.Timeout;
}

export class TransferReceiver {
  private activeTransfers = new Map<string, IncomingTransfer>();
  private ompDir: string;

  constructor(customOmpDir?: string) {
    this.ompDir = customOmpDir || getOmpDir();
    this.cleanupStaleParts();
  }

  public getQuarantineDiskUsage(): number {
    const inboxRoot = path.join(this.ompDir, "inbox");
    if (!fs.existsSync(inboxRoot)) return 0;
    let totalBytes = 0;
    try {
      const walk = (dir: string) => {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            walk(full);
          } else if (entry.isFile()) {
            try {
              totalBytes += fs.statSync(full).size;
            } catch {}
          }
        }
      };
      walk(inboxRoot);
    } catch {}
    return totalBytes;
  }

  public cleanupStaleParts(): void {
    const inboxRoot = path.join(this.ompDir, "inbox");
    if (!fs.existsSync(inboxRoot)) return;

    try {
      const walkAndClean = (dir: string) => {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            walkAndClean(full);
            // remove empty dir
            try {
              if (fs.readdirSync(full).length === 0) fs.rmdirSync(full);
            } catch {}
          } else if (entry.name.endsWith(".part") || entry.name.startsWith(".tmp-")) {
            try {
              fs.unlinkSync(full);
            } catch {}
          }
        }
      };
      walkAndClean(inboxRoot);
    } catch {}
  }

  public handleOffer(
    offer: FileOfferMsg,
    workspaceId = "default",
  ): { ok: boolean; error?: string } {
    if (this.activeTransfers.size >= MAX_CONCURRENT_TRANSFERS) {
      return { ok: false, error: "Maximum concurrent transfers reached (max 5)" };
    }

    if (this.activeTransfers.has(offer.transferId)) {
      return { ok: false, error: `Transfer ID "${offer.transferId}" already active` };
    }

    // Per-peer in-flight transfer quota
    const senderId = offer.originPrincipalId || offer.from || "unknown";
    let inFlightForPeer = 0;
    for (const [_, t] of this.activeTransfers) {
      const tSender = t.offer.originPrincipalId || t.offer.from;
      if (tSender === senderId) inFlightForPeer++;
    }
    if (inFlightForPeer >= MAX_IN_FLIGHT_PER_PEER) {
      return { ok: false, error: `In-flight transfer limit reached for peer (max ${MAX_IN_FLIGHT_PER_PEER})` };
    }

    // Validate sizeBytes
    if (
      !Number.isSafeInteger(offer.sizeBytes) ||
      offer.sizeBytes < 1 ||
      offer.sizeBytes > MAX_FILE_SIZE
    ) {
      return { ok: false, error: `Invalid sizeBytes: must be integer between 1 and ${MAX_FILE_SIZE}` };
    }

    // Check quarantine disk quota
    const currentUsage = this.getQuarantineDiskUsage();
    if (currentUsage + offer.sizeBytes > MAX_QUARANTINE_BYTES) {
      return { ok: false, error: "Quarantine storage quota exceeded (max 250MB)" };
    }

    // Validate totalChunks
    const expectedChunks = Math.ceil(offer.sizeBytes / CHUNK_SIZE);
    if (!Number.isSafeInteger(offer.totalChunks) || offer.totalChunks !== expectedChunks) {
      return { ok: false, error: `Invalid totalChunks: expected ${expectedChunks}, got ${offer.totalChunks}` };
    }

    // Validate sha256
    if (!/^[a-fA-F0-9]{64}$/.test(offer.sha256)) {
      return { ok: false, error: "Invalid SHA-256 checksum format" };
    }

    // Sanitize filename
    const safeFilename = path.basename(offer.filename).replace(/[^a-zA-Z0-9._-]/g, "_");
    if (!safeFilename || safeFilename.startsWith(".")) {
      return { ok: false, error: "Invalid or dangerous filename" };
    }

    // Generate receiver-controlled quarantine directory outside workspace
    const safeWorkspace = workspaceId.replace(/[^a-zA-Z0-9_-]/g, "_");
    const inboxRoot = path.join(this.ompDir, "inbox", safeWorkspace);
    fs.mkdirSync(inboxRoot, { recursive: true, mode: 0o700 });

    const quarantineDir = fs.mkdtempSync(path.join(inboxRoot, "rx-"));
    const tempPath = path.join(quarantineDir, `${safeFilename}.part`);
    const finalPath = path.join(quarantineDir, safeFilename);

    let fd: number;
    try {
      fd = fs.openSync(tempPath, "wx", 0o600);
    } catch (err: any) {
      try { fs.rmdirSync(quarantineDir); } catch {}
      return { ok: false, error: `Failed to open temporary file exclusively: ${err.message}` };
    }

    const transfer: IncomingTransfer = {
      transferId: offer.transferId,
      offer: { ...offer, filename: safeFilename },
      quarantineDir,
      tempPath,
      finalPath,
      fd,
      nextExpectedChunk: 0,
      receivedBytes: 0,
      hasher: crypto.createHash("sha256"),
      startedAt: Date.now(),
      lastActivityAt: Date.now(),
      inactivityTimer: setTimeout(() => this.abortTransfer(offer.transferId, "Transfer timed out due to inactivity"), INACTIVITY_TIMEOUT_MS),
      absoluteTimer: setTimeout(() => this.abortTransfer(offer.transferId, "Absolute transfer timeout exceeded (120s)"), ABSOLUTE_TIMEOUT_MS),
    };

    this.activeTransfers.set(offer.transferId, transfer);
    return { ok: true };
  }

  public handleChunk(
    chunk: FileChunkMsg,
  ): {
    complete: boolean;
    ok: boolean;
    error?: string;
    finalPath?: string;
    sha256?: string;
  } {
    const transfer = this.activeTransfers.get(chunk.transferId);
    if (!transfer) {
      return { complete: false, ok: false, error: `Transfer "${chunk.transferId}" not found or already terminated` };
    }

    // Reset inactivity timer
    clearTimeout(transfer.inactivityTimer);
    transfer.inactivityTimer = setTimeout(
      () => this.abortTransfer(chunk.transferId, "Transfer timed out due to inactivity"),
      INACTIVITY_TIMEOUT_MS,
    );
    transfer.lastActivityAt = Date.now();

    // Verify chunk bindings to offer
    if (chunk.originPrincipalId && transfer.offer.originPrincipalId && chunk.originPrincipalId !== transfer.offer.originPrincipalId) {
      this.abortTransfer(chunk.transferId, "Sender principal mismatch for active transfer");
      return { complete: false, ok: false, error: "Sender principal does not match accepted transfer offer" };
    }

    if (chunk.from && transfer.offer.from && chunk.from !== transfer.offer.from) {
      this.abortTransfer(chunk.transferId, "Sender mismatch for active transfer");
      return { complete: false, ok: false, error: "Sender does not match accepted transfer offer" };
    }

    if (chunk.to && transfer.offer.to && chunk.to !== transfer.offer.to) {
      this.abortTransfer(chunk.transferId, "Recipient mismatch for active transfer");
      return { complete: false, ok: false, error: "Recipient does not match accepted transfer offer" };
    }

    if (chunk.totalChunks !== transfer.offer.totalChunks) {
      this.abortTransfer(chunk.transferId, "Total chunks count mismatch");
      return { complete: false, ok: false, error: "Total chunks mismatch with original offer" };
    }

    // Enforce strictly ordered sequential chunk delivery
    if (chunk.chunkIndex !== transfer.nextExpectedChunk) {
      this.abortTransfer(
        chunk.transferId,
        `Out of order or duplicate chunk: expected ${transfer.nextExpectedChunk}, received ${chunk.chunkIndex}`,
      );
      return {
        complete: false,
        ok: false,
        error: `Chunk order violation: expected index ${transfer.nextExpectedChunk}, got ${chunk.chunkIndex}`,
      };
    }

    // Decode chunk data
    let buf: Buffer;
    try {
      buf = Buffer.from(chunk.data, "base64");
    } catch {
      this.abortTransfer(chunk.transferId, "Malformed base64 payload");
      return { complete: false, ok: false, error: "Base64 payload decoding failed" };
    }

    if (buf.length === 0) {
      this.abortTransfer(chunk.transferId, "Zero-length chunk payload rejected");
      return { complete: false, ok: false, error: "Empty chunk payload is not permitted" };
    }

    if (buf.length > CHUNK_SIZE) {
      this.abortTransfer(chunk.transferId, `Chunk size ${buf.length} exceeds 64KB ceiling`);
      return { complete: false, ok: false, error: "Chunk payload exceeds 64KB ceiling" };
    }

    if (transfer.receivedBytes + buf.length > transfer.offer.sizeBytes) {
      this.abortTransfer(chunk.transferId, "Received bytes exceeds offered file size");
      return { complete: false, ok: false, error: "Received byte count exceeds offered file size" };
    }

    try {
      fs.writeSync(transfer.fd, buf, 0, buf.length);
      transfer.hasher.update(buf);
      transfer.receivedBytes += buf.length;
      transfer.nextExpectedChunk++;
    } catch (err: any) {
      this.abortTransfer(chunk.transferId, `Disk write failure: ${err.message}`);
      return { complete: false, ok: false, error: `Disk write error: ${err.message}` };
    }

    // Final chunk completion check
    if (transfer.nextExpectedChunk === transfer.offer.totalChunks) {
      clearTimeout(transfer.inactivityTimer);
      clearTimeout(transfer.absoluteTimer);
      this.activeTransfers.delete(chunk.transferId);

      try {
        fs.closeSync(transfer.fd);
      } catch {}

      if (transfer.receivedBytes !== transfer.offer.sizeBytes) {
        try { fs.unlinkSync(transfer.tempPath); } catch {}
        try { fs.rmdirSync(transfer.quarantineDir); } catch {}
        return {
          complete: true,
          ok: false,
          error: `File size mismatch: expected ${transfer.offer.sizeBytes} bytes, got ${transfer.receivedBytes}`,
        };
      }

      const computedSha256 = transfer.hasher.digest("hex");
      if (computedSha256.toLowerCase() !== transfer.offer.sha256.toLowerCase()) {
        try { fs.unlinkSync(transfer.tempPath); } catch {}
        try { fs.rmdirSync(transfer.quarantineDir); } catch {}
        return {
          complete: true,
          ok: false,
          error: `SHA-256 verification mismatch: expected ${transfer.offer.sha256}, got ${computedSha256}`,
        };
      }

      // Atomically move .part to finalPath
      try {
        fs.renameSync(transfer.tempPath, transfer.finalPath);
        return {
          complete: true,
          ok: true,
          finalPath: transfer.finalPath,
          sha256: computedSha256,
        };
      } catch (err: any) {
        try { fs.unlinkSync(transfer.tempPath); } catch {}
        try { fs.rmdirSync(transfer.quarantineDir); } catch {}
        return {
          complete: true,
          ok: false,
          error: `Failed to finalize file in quarantine: ${err.message}`,
        };
      }
    }

    return { complete: false, ok: true };
  }

  public abortTransfer(transferId: string, reason = "Transfer aborted"): void {
    const transfer = this.activeTransfers.get(transferId);
    if (!transfer) return;

    clearTimeout(transfer.inactivityTimer);
    clearTimeout(transfer.absoluteTimer);
    this.activeTransfers.delete(transferId);

    try {
      fs.closeSync(transfer.fd);
    } catch {}

    try {
      if (fs.existsSync(transfer.tempPath)) fs.unlinkSync(transfer.tempPath);
    } catch {}

    try {
      if (fs.existsSync(transfer.quarantineDir) && fs.readdirSync(transfer.quarantineDir).length === 0) {
        fs.rmdirSync(transfer.quarantineDir);
      }
    } catch {}
  }

  public cleanupPeerTransfers(peerNameOrPrincipal: string): void {
    for (const [id, t] of this.activeTransfers) {
      if (
        t.offer.from === peerNameOrPrincipal ||
        t.offer.originPrincipalId === peerNameOrPrincipal
      ) {
        this.abortTransfer(id, "Peer disconnected");
      }
    }
  }

  public abortAllTransfers(): void {
    for (const id of Array.from(this.activeTransfers.keys())) {
      this.abortTransfer(id, "Link shutdown");
    }
  }
}
