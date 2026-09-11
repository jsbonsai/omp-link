/**
 * The audit log: JSONL at `<OMP_DIR>/audit.log` (0600, directory 0700), one object per line,
 * append-only, never rotated by this module.
 *
 * It has two jobs, and both of them mean a lost line is a real defect:
 *   1. It is the **security oracle** — every denial, pairing verdict, grant and origin mismatch
 *      is recorded here, and the test suite asserts against it.
 *   2. It is the **user's receipt** — `/link shared` renders it to answer "what did that other
 *      terminal actually do on my machine?".
 *
 * Writes are still best-effort (an audit failure must never break a security decision that has
 * already been taken), but a failure is now *recorded*: `getAuditLogStatus()` reports it so
 * `/link doctor` can say "audit log not writable" instead of showing an empty, reassuring
 * receipt on a read-only or full state directory.
 *
 * ## Record shape
 *
 * ```jsonc
 * { "type": "pairing_approved",     // AuditEventType — the declared vocabulary below
 *   "timestamp": 1757462400000,     // ms since epoch, filled in if the caller omits it
 *   "logSeq": 42,                   // monotonic within this process; gaps mean a lost write
 *   "agentInstanceId": "…uuid…",    // which terminal wrote it (siblings share one log file)
 *   … event-specific fields …       // open bag, deliberately untyped per event
 * }
 * ```
 *
 * `logSeq` and `agentInstanceId` exist for one reason: several terminals on one machine append to
 * the same file, interleaved. Without them two sibling agents' lines are indistinguishable, and
 * "which terminal approved this?" has no answer. `logSeq` restarts at 1 per process, so it orders
 * one terminal's lines and never claims to order the file.
 *
 * ## Event vocabulary
 *
 * `AuditEventType` is the closed list of what `src/` and `index.ts` actually emit — grep before
 * adding one, and add it here in the same commit. It is a union rather than an enum so the
 * strings on the wire and in tests stay literal. `type` accepts a free string too, because
 * `link-node.ts` composes `${kind}_origin_mismatch`; the union is the documentation and the
 * autocomplete, not a lock.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { getOmpDir } from "./identity.js";

/**
 * Every event type emitted by this codebase, grouped by what it tells the reader.
 * `/link shared` renders the subset a human cares about (see `RECEIPT_EVENT_TYPES` in index.ts);
 * everything else is for `doctor` and for tests.
 */
export type AuditEventType =
  // Pairing and device trust
  | "pairing_approved"
  | "pairing_denied"
  | "pairing_rejected_invalid_sas"
  | "pairing_rejected_missing_sas"
  | "pairing_aborted_no_channel_binding"
  | "local_sibling_admitted"
  | "display_name_collision"
  | "device_revoked"
  | "permissions_updated"
  | "paired_store_reset"
  | "hub_pin_mismatch"
  // Execution grants
  | "grant_created"
  | "grant_used"
  | "grant_expired"
  | "grant_revoked"
  | "exec_executed"
  | "exec_blocked"
  // Inbound gate refusals
  | "authorization_denied"
  | "client_frame_rejected"
  | "client_phase_violation"
  | "client_unexpected_handshake_frame"
  | "unexpected_handshake_frame"
  | "roster_update_rejected"
  // Correlated-response origin checks (composed as `${kind}_origin_mismatch`)
  | "rpc_response_origin_mismatch"
  | "compact_response_origin_mismatch"
  | "file_ack_origin_mismatch"
  // Transfers
  | "file_transfer_received"
  // Node lifecycle
  | "hub_started"
  | "hub_start_failed"
  | "hub_server_error"
  | "local_hub_succession"
  | "peer_disconnected"
  | "peer_liveness_timeout"
  | "peer_connection_superseded"
  | "hub_liveness_timeout"
  | "message_dispatch_failed"
  | "client_message_dispatch_failed";

export interface AuditRecord {
  type: AuditEventType | (string & {});
  timestamp: number;
  /** Monotonic within the emitting process; set by `appendAuditLog`. */
  /** Monotonic within the writing process; set by the log, gaps mean a lost write. */
  logSeq?: number;
  /** The terminal that emitted the line. Set globally via `setAuditAgentInstanceId`. */
  agentInstanceId?: string;
  /** Event-specific fields. Deliberately open: each event carries its own evidence. */
  [key: string]: any;
}

export interface AuditLogStatus {
  /** False once a write has failed and no later write has succeeded. */
  writable: boolean;
  /** Why the last failure happened, for `doctor`. Null while healthy. */
  error: string | null;
  /** The file that was (or would be) written. */
  path: string;
  /** Lines this process has successfully appended. */
  written: number;
}

let customAuditFile: string | null = null;
let sequence = 0;
let writtenCount = 0;
let lastWriteError: string | null = null;
let processAgentInstanceId: string | null = null;

function auditFilePath(): string {
  return customAuditFile || path.join(getOmpDir(), "audit.log");
}

export function setCustomAuditLogPath(logPath: string | null): void {
  customAuditFile = logPath;
  // A new destination has a new fate: do not carry a previous path's failure into it.
  lastWriteError = null;
}

/**
 * Stamp every subsequent line with the terminal that wrote it. Called once by the extension after
 * its LinkNode exists; unset in the CLI, where there is only one writer anyway.
 */
export function setAuditAgentInstanceId(agentInstanceId: string | null): void {
  processAgentInstanceId = agentInstanceId;
}

/**
 * One `write(2)` on an `O_APPEND` descriptor, so concurrent writers from sibling terminals
 * interleave whole lines rather than fragments. The descriptor is kept open for the life of the
 * process: re-opening per record cost a syscall pair on a hot path and turned any transient
 * open failure into a silently dropped record, which is unacceptable for the one file that is
 * both the security oracle and the user's receipt.
 */
let auditFd: number | null = null;
let auditFdPath: string | null = null;

function openAuditFd(file: string): number {
  const dir = path.dirname(file);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  const fd = fs.openSync(file, "a", 0o600);
  auditFd = fd;
  auditFdPath = file;
  return fd;
}

export function closeAuditLog(): void {
  if (auditFd !== null) {
    try { fs.closeSync(auditFd); } catch {}
  }
  auditFd = null;
  auditFdPath = null;
}

export function appendAuditLog(record: AuditRecord): void {
  sequence += 1;
  let file = "";
  try {
    file = auditFilePath();
    const line = JSON.stringify({
      ...record,
      timestamp: record.timestamp || Date.now(),
      // Deliberately NOT `seq`: an event is free to carry its own sequence number, and the log
      // silently overwriting a caller's field would corrupt the record it exists to preserve.
      logSeq: sequence,
      ...(processAgentInstanceId && !record.agentInstanceId
        ? { agentInstanceId: processAgentInstanceId }
        : {}),
    }) + "\n";
    const payload = Buffer.from(line, "utf8");

    if (auditFd === null || auditFdPath !== file) {
      closeAuditLog();
      openAuditFd(file);
    }

    try {
      fs.writeSync(auditFd!, payload, 0, payload.length);
    } catch {
      // The descriptor went stale (log rotated, directory recreated, fd exhausted earlier).
      // Re-open once and retry before giving up, so a recoverable blip does not lose the line.
      closeAuditLog();
      const fd = openAuditFd(file);
      fs.writeSync(fd, payload, 0, payload.length);
    }

    writtenCount += 1;
    lastWriteError = null;
  } catch (err: unknown) {
    // Never throw: the security decision this line describes has already been taken, and an
    // unwritable log must not turn a clean denial into a crash. The failure is remembered
    // instead, so `/link doctor` can tell the user their receipt is not being kept.
    closeAuditLog();
    const reason = err instanceof Error ? err.message : String(err);
    lastWriteError = `${file || "audit.log"}: ${reason}`;
  }
}

export function getAuditLogStatus(): AuditLogStatus {
  let file: string;
  try {
    file = auditFilePath();
  } catch {
    file = "audit.log";
  }
  return { writable: lastWriteError === null, error: lastWriteError, path: file, written: writtenCount };
}

export function readAuditLogs(limit = 100): AuditRecord[] {
  try {
    const file = auditFilePath();
    if (!fs.existsSync(file)) return [];
    const content = fs.readFileSync(file, "utf8");
    const lines = content.split("\n").filter(Boolean);
    const records: AuditRecord[] = [];
    for (const line of lines.slice(-limit)) {
      try {
        records.push(JSON.parse(line));
      } catch {}
    }
    return records;
  } catch {
    return [];
  }
}
