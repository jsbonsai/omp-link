import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { getOmpDir } from "./identity.js";
import { type LinkTimings, getTimings } from "./config.js";
import { type FileOfferMsg, type FileChunkMsg } from "./protocol-schema.js";

export const CHUNK_SIZE = 64 * 1024;
export const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
/**
 * Documented defaults. The live values are `transferInactivityMs` / `transferAbsoluteMs` in
 * `link.json`, resolved once per receiver in the constructor (`this.timings`) — never per chunk.
 * Both stay exported because tests and `bin/omp-link.mjs` reason about the default staging-idle
 * rule from them.
 */
export const INACTIVITY_TIMEOUT_MS = 30_000;
export const ABSOLUTE_TIMEOUT_MS = 120_000;
export const MAX_CONCURRENT_TRANSFERS = 5;
export const MAX_IN_FLIGHT_PER_PEER = 2;
export const MAX_QUARANTINE_BYTES = 250 * 1024 * 1024; // 250MB

// Staging directories are named `rx-<pid>-<rand>-XXXXXX` so that every `.part` file can be
// attributed to the process that owns it. Reclaiming a staging file another live terminal is
// still writing into silently destroys an in-flight transfer, so ownership is encoded in the
// path and garbage collection is strictly separated from live transfer state.
const STAGING_DIR_PATTERN = /^rx-(\d{1,10})-[0-9a-f]{8}-/;

function parseStagingOwnerPid(dirName: string): number | null {
  const match = STAGING_DIR_PATTERN.exec(dirName);
  if (!match) return null;
  const pid = Number(match[1]);
  return Number.isSafeInteger(pid) && pid > 0 ? pid : null;
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM means the process exists but is owned by another user: alive.
    // ESRCH (and any code we cannot interpret) is treated as dead; the mtime rule still applies.
    const code = err && typeof err === "object" && "code" in err ? err.code : undefined;
    return code === "EPERM";
  }
}

/**
 * The staging file must still be the inode we have been writing into. If a concurrent cleanup
 * unlinked or replaced it, every in-memory check (byte count, running sha256) still passes while
 * the bytes are gone - that has to surface as a failure, never as a completed transfer.
 */
function inspectStagingFile(fd: number, tempPath: string): { ok: boolean; error?: string } {
  let openStat: fs.Stats;
  try {
    openStat = fs.fstatSync(fd);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: `Staging file handle is no longer valid: ${message}` };
  }
  if (openStat.nlink === 0) {
    return { ok: false, error: "Staging file was deleted while the transfer was in flight; received data is lost" };
  }
  let pathStat: fs.Stats;
  try {
    pathStat = fs.statSync(tempPath);
  } catch {
    return { ok: false, error: "Staging file disappeared before finalize; received data is lost" };
  }
  if (pathStat.ino !== openStat.ino || pathStat.dev !== openStat.dev) {
    return { ok: false, error: "Staging file was replaced before finalize; received data is lost" };
  }
  return { ok: true };
}

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
  /** Bytes still owed to this transfer's quarantine quota reservation. */
  reservedBytes: number;
}

export class TransferReceiver {
  private activeTransfers = new Map<string, IncomingTransfer>();
  private ompDir: string;

  /**
   * Transfer deadlines, read once from `link.json` for this receiver's state directory. Every
   * value is already validated and floored by `getTimings`, so nothing below re-clamps.
   */
  private readonly timings: LinkTimings;

  private cachedDiskUsage: number | null = null;
  private lastDiskScan = 0;

  /** Bytes promised to accepted-but-unfinished transfers, on top of what the disk scan already sees. */
  private reservedBytes = 0;

  /** `<pid>-<rand>`, stamped into every staging directory this instance creates. */
  private readonly stagingOwner = `${process.pid}-${crypto.randomBytes(4).toString("hex")}`;

  constructor(customOmpDir?: string) {
    this.ompDir = customOmpDir || getOmpDir();
    // Before the sweep: `cleanupOrphanedParts` is held to the configured absolute deadline.
    this.timings = getTimings(customOmpDir);
    this.cleanupOrphanedParts();
    this.purgeQuarantineOlderThan(7 * 24 * 60 * 60 * 1000); // 7 days retention default
  }

  /** The deadlines this receiver resolved at construction. Lets a caller report what is live. */
  public getTransferTimeouts(): { inactivityMs: number; absoluteMs: number } {
    return { inactivityMs: this.timings.transferInactivityMs, absoluteMs: this.timings.transferAbsoluteMs };
  }

  /** Bytes this receiver has reserved against the quarantine quota for in-flight transfers. */
  public getReservedBytes(): number {
    return this.reservedBytes;
  }

  public getQuarantineDiskUsage(): number {
    const now = Date.now();
    if (this.cachedDiskUsage !== null && now - this.lastDiskScan < 5_000) {
      return this.cachedDiskUsage;
    }

    const inboxRoot = path.join(this.ompDir, "inbox");
    if (!fs.existsSync(inboxRoot)) {
      this.cachedDiskUsage = 0;
      this.lastDiskScan = now;
      return 0;
    }
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

    this.cachedDiskUsage = totalBytes;
    this.lastDiskScan = now;
    return totalBytes;
  }

  /**
   * Depth-first walk of the quarantine inbox that never descends into - nor removes - a staging
   * directory whose owning process is still alive. `ownerPid` is the pid encoded in the nearest
   * enclosing staging directory name, or null for legacy/unowned directories.
   */
  private walkQuarantine(
    dir: string,
    ownerPid: number | null,
    onFile: (fullPath: string, entryName: string, fileOwnerPid: number | null) => void,
  ): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        const nestedOwner = parseStagingOwnerPid(entry.name) ?? ownerPid;
        if (nestedOwner !== null && isProcessAlive(nestedOwner)) continue;
        this.walkQuarantine(full, nestedOwner, onFile);
        try {
          if (fs.readdirSync(full).length === 0) fs.rmdirSync(full);
        } catch {}
      } else if (entry.isFile()) {
        onFile(full, entry.name, ownerPid);
      }
    }
  }

  /**
   * Retention sweep for *completed* quarantined files. In-progress staging files belong to
   * `cleanupOrphanedParts`, and staging directories owned by a live process are skipped entirely.
   */
  public purgeQuarantineOlderThan(maxAgeMs = 7 * 24 * 60 * 60 * 1000): number {
    const inboxRoot = path.join(this.ompDir, "inbox");
    if (!fs.existsSync(inboxRoot)) return 0;
    let purgedCount = 0;
    const now = Date.now();

    this.walkQuarantine(inboxRoot, null, (full, entryName) => {
      if (entryName.endsWith(".part") || entryName.startsWith(".tmp-")) return;
      try {
        const stat = fs.statSync(full);
        if (now - stat.mtimeMs > maxAgeMs) {
          fs.unlinkSync(full);
          purgedCount++;
        }
      } catch {}
    });

    this.cachedDiskUsage = null;
    return purgedCount;
  }

  /**
   * Reclaim staging files abandoned by processes that are gone. A `.part` / `.tmp-*` file is
   * removed only when BOTH hold: the pid that owns its staging directory is no longer alive, and
   * the file has been idle longer than the absolute transfer deadline. Legacy directories carrying
   * no owner pid fall back to the idle rule alone. Directories owned by a live pid are never
   * touched - several terminals on one machine share this inbox, and their in-flight transfers
   * must survive another terminal starting up.
   */
  public cleanupOrphanedParts(): void {
    const inboxRoot = path.join(this.ompDir, "inbox");
    if (!fs.existsSync(inboxRoot)) return;
    const now = Date.now();

    this.walkQuarantine(inboxRoot, null, (full, entryName, fileOwnerPid) => {
      if (!entryName.endsWith(".part") && !entryName.startsWith(".tmp-")) return;
      if (fileOwnerPid !== null && isProcessAlive(fileOwnerPid)) return;
      try {
        const stat = fs.statSync(full);
        if (now - stat.mtimeMs <= this.timings.transferAbsoluteMs) return;
        fs.unlinkSync(full);
      } catch {}
    });

    this.cachedDiskUsage = null;
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

    // Quarantine quota: bytes already on disk plus bytes reserved by in-flight offers. The disk
    // scan is cached for 5s, so reservations - not the scan - are what keep concurrent offers honest.
    const currentUsage = this.getQuarantineDiskUsage();
    if (currentUsage + this.reservedBytes + offer.sizeBytes > MAX_QUARANTINE_BYTES) {
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

    const quarantineDir = fs.mkdtempSync(path.join(inboxRoot, `rx-${this.stagingOwner}-`));
    const tempPath = path.join(quarantineDir, `${safeFilename}.part`);
    const finalPath = path.join(quarantineDir, safeFilename);

    let fd: number;
    try {
      fd = fs.openSync(tempPath, "wx", 0o600);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      try { fs.rmdirSync(quarantineDir); } catch {}
      return { ok: false, error: `Failed to open temporary file exclusively: ${message}` };
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
      inactivityTimer: setTimeout(
        () => this.abortTransfer(offer.transferId, "Transfer timed out due to inactivity"),
        this.timings.transferInactivityMs,
      ),
      absoluteTimer: setTimeout(
        () => this.abortTransfer(
          offer.transferId,
          `Absolute transfer timeout exceeded (${Math.round(this.timings.transferAbsoluteMs / 1000)}s)`,
        ),
        this.timings.transferAbsoluteMs,
      ),
      reservedBytes: offer.sizeBytes,
    };

    this.activeTransfers.set(offer.transferId, transfer);
    this.reservedBytes += transfer.reservedBytes;
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
      this.timings.transferInactivityMs,
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
      // Bytes that have landed are now visible to the quarantine scan; drop them from the reservation.
      const consumed = Math.min(transfer.reservedBytes, buf.length);
      transfer.reservedBytes -= consumed;
      this.reservedBytes = Math.max(0, this.reservedBytes - consumed);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.abortTransfer(chunk.transferId, `Disk write failure: ${message}`);
      return { complete: false, ok: false, error: `Disk write error: ${message}` };
    }

    // Final chunk completion check
    if (transfer.nextExpectedChunk === transfer.offer.totalChunks) {
      clearTimeout(transfer.inactivityTimer);
      clearTimeout(transfer.absoluteTimer);
      this.activeTransfers.delete(chunk.transferId);
      this.releaseReservation(transfer);

      // Byte count and hash are computed in memory, so they pass even if the staging file was
      // unlinked underneath us. Confirm the bytes are still on disk before declaring success.
      const staging = inspectStagingFile(transfer.fd, transfer.tempPath);
      try {
        fs.closeSync(transfer.fd);
      } catch {}

      if (!staging.ok) {
        // The path is not ours any more (deleted or replaced) - do not unlink whatever sits there.
        this.discardStagingDir(transfer, false);
        return { complete: true, ok: false, error: staging.error };
      }

      if (transfer.receivedBytes !== transfer.offer.sizeBytes) {
        this.discardStagingDir(transfer, true);
        return {
          complete: true,
          ok: false,
          error: `File size mismatch: expected ${transfer.offer.sizeBytes} bytes, got ${transfer.receivedBytes}`,
        };
      }

      const computedSha256 = transfer.hasher.digest("hex");
      if (computedSha256.toLowerCase() !== transfer.offer.sha256.toLowerCase()) {
        this.discardStagingDir(transfer, true);
        return {
          complete: true,
          ok: false,
          error: `SHA-256 verification mismatch: expected ${transfer.offer.sha256}, got ${computedSha256}`,
        };
      }

      // Atomically move .part to finalPath
      try {
        fs.renameSync(transfer.tempPath, transfer.finalPath);
        this.cachedDiskUsage = null;
        return {
          complete: true,
          ok: true,
          finalPath: transfer.finalPath,
          sha256: computedSha256,
        };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        this.discardStagingDir(transfer, true);
        return {
          complete: true,
          ok: false,
          error: `Failed to finalize file in quarantine: ${message}`,
        };
      }
    }

    return { complete: false, ok: true };
  }

  public abortTransfer(transferId: string, _reason = "Transfer aborted"): void {
    const transfer = this.activeTransfers.get(transferId);
    if (!transfer) return;

    clearTimeout(transfer.inactivityTimer);
    clearTimeout(transfer.absoluteTimer);
    this.activeTransfers.delete(transferId);
    this.releaseReservation(transfer);

    // Only reclaim the staging path while it is still the inode this transfer owns.
    const staging = inspectStagingFile(transfer.fd, transfer.tempPath);
    try {
      fs.closeSync(transfer.fd);
    } catch {}
    this.discardStagingDir(transfer, staging.ok);
  }

  /** Release the unwritten remainder of a reservation: completion, cancellation, timeout, abort. */
  private releaseReservation(transfer: IncomingTransfer): void {
    if (transfer.reservedBytes <= 0) {
      transfer.reservedBytes = 0;
      return;
    }
    this.reservedBytes = Math.max(0, this.reservedBytes - transfer.reservedBytes);
    transfer.reservedBytes = 0;
  }

  /** Drop a dead transfer's staging file (when the path is still ours) plus its emptied directory. */
  private discardStagingDir(transfer: IncomingTransfer, unlinkTemp: boolean): void {
    if (unlinkTemp) {
      try {
        fs.unlinkSync(transfer.tempPath);
      } catch {}
    }
    try {
      if (fs.readdirSync(transfer.quarantineDir).length === 0) fs.rmdirSync(transfer.quarantineDir);
    } catch {}
    this.cachedDiskUsage = null;
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
