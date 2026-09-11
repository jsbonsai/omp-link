/**
 * omp-link configuration and operational tunables — the single source of truth for both.
 *
 * ## The file
 *
 * `<OMP_DIR>/link.json`, written by `atomicWriteSecureFile` (0600). It is *state*, not a secret:
 * losing it costs the room list and the terminal name, nothing cryptographic. Paired devices and
 * the device key live elsewhere and are never mirrored here.
 *
 * ```jsonc
 * {
 *   "configVersion": 1,               // CONFIG_SCHEMA_VERSION; absent in files written by <= 3.4.0
 *   "terminalName": "mac-studio",     // display name; --link-name still wins for one launch
 *   "network": "lan",                 // "lan" | "tailscale"
 *   "currentRoomId": "…uuid…",        // must match a rooms[] entry to be usable
 *   "rooms": [                        // RoomRecord[]; entries that cannot route are dropped
 *     { "roomId": "…", "label": "backend", "hubPrincipalId": "…", "hubFingerprint": "…",
 *       "endpoint": "192.168.1.5:9900", "lastJoinedAt": 1757462400000 }
 *   ],
 *   "timings": { "heartbeatIntervalMs": 20000 }   // optional; per-key override of DEFAULT_TIMINGS
 * }
 * ```
 *
 * Rules this module guarantees, because a config file is the one thing a stranger cloning the
 * repo will hand-edit:
 *
 * 1. **Loading never throws.** Missing, empty, truncated, `null`, an array, a string, a `rooms`
 *    object instead of a list — every one of those yields `DEFAULT_TIMINGS` plus an untouched
 *    default config and a human-readable `warning` that names the next action. An extension that
 *    cannot load because of a stray comma is worse than one with no rooms remembered.
 * 2. **Unknown keys are preserved.** Other tools write here; a round trip through `saveConfig`
 *    must not silently amputate keys this build does not know about.
 * 3. **A v3.4.0 file (no `configVersion`) is migrated silently and forward.** Its shape is a
 *    strict subset of v1, so there is nothing to warn about and nothing a user could do with the
 *    warning. This is deliberate and is *not* the paired-device store's policy: that store is a
 *    security oracle whose pre-v3 records were forgeable, so it is archived and reset rather than
 *    migrated (`PAIRED_DEVICES_SCHEMA_VERSION`). A room list is not an authorization decision —
 *    joining a room still requires a pinned fingerprint — so a silent forward migration is
 *    correct here and a scary prompt would only teach the user to ignore prompts.
 * 4. **A file from a newer build is preserved, not rewritten.** Values still validate individually
 *    and the user is told once, so downgrading a terminal for a demo does not eat its rooms.
 *
 * ## The tunables
 *
 * `LinkTimings` collects the timings that an operator can reasonably want to change on a slow
 * link or a busy machine. Constants that are protocol or safety limits (chunk size, max file
 * size, dedupe cache size, rate-limit windows, roster cap) are deliberately *not* here: they are
 * part of the wire contract or the security model, and a config file must not be able to widen
 * them.
 *
 * `getTimings()` caches per resolved state directory, and callers (`LinkNode`) read it once at
 * construction, so an edit to `link.json` takes effect the next time the terminal starts.
 *
 * Heartbeat semantics are owned by `link-node.ts` and stated here so the two cannot drift: every
 * `heartbeatIntervalMs` a side sends `socket.ping()`; any inbound traffic (a pong or any frame)
 * marks the peer alive; a peer is dropped once `heartbeatMissesBeforeDrop` consecutive intervals
 * elapse with no inbound traffic at all, i.e. the dead-detection budget is
 * `heartbeatIntervalMs * (heartbeatMissesBeforeDrop + 1)` worst case.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { atomicWriteSecureFile, getOmpDir } from "./identity.js";

/** Bumped only for a change no forward-compatible read can absorb. */
export const CONFIG_SCHEMA_VERSION = 1;

export const CONFIG_FILE_NAME = "link.json";

/**
 * A room is an opaque id bound to the identity of the host that created it. The label is for
 * humans; two machines that both create "backend" have created two different rooms.
 */
export interface RoomRecord {
  roomId: string;
  label: string;
  hubPrincipalId: string;
  hubFingerprint: string;
  endpoint: string;
  lastJoinedAt: number;
}

/** Operator-tunable timings. Every value is a positive integer of milliseconds unless named otherwise. */
export interface LinkTimings {
  /** TLS connected -> authenticated or paired. Exceeding it closes 4408. */
  handshakeTimeoutMs: number;
  /** How long a pairing request waits for a human to compare four words. */
  pairingWindowMs: number;
  /** Interval between liveness pings on an authenticated connection. Floors at 1000. */
  heartbeatIntervalMs: number;
  /** Consecutive silent intervals tolerated before the peer is dropped. Floors at 1 (a count, not ms). */
  heartbeatMissesBeforeDrop: number;
  /** Client-side: no pong and no frame from the hub for this long means the hub is gone. */
  clientHubSilenceTimeoutMs: number;
  /** How long a `link_exec` / `link_send` style request waits for its correlated response. */
  rpcTimeoutMs: number;
  /** No chunk for this long fails an in-flight transfer. */
  transferInactivityMs: number;
  /** Hard ceiling on one transfer regardless of progress. */
  transferAbsoluteMs: number;
  /** Budget for one discovery sweep (loopback probe, UDP broadcast, tailscale). */
  discoveryProbeMs: number;
  /** Lifetime of an execution grant when the approver does not specify one. */
  grantDefaultMs: number;
}

export const DEFAULT_TIMINGS: Readonly<LinkTimings> = Object.freeze({
  handshakeTimeoutMs: 10_000,
  pairingWindowMs: 60_000,
  heartbeatIntervalMs: 15_000,
  heartbeatMissesBeforeDrop: 2,
  clientHubSilenceTimeoutMs: 45_000,
  rpcTimeoutMs: 30_000,
  transferInactivityMs: 30_000,
  transferAbsoluteMs: 120_000,
  discoveryProbeMs: 1_200,
  grantDefaultMs: 600_000,
});

/** Lowest accepted value per key: a typo must degrade to "slow", never to "unusable". */
const TIMING_FLOORS: Readonly<Record<keyof LinkTimings, number>> = Object.freeze({
  handshakeTimeoutMs: 1_000,
  pairingWindowMs: 5_000,
  heartbeatIntervalMs: 1_000,
  heartbeatMissesBeforeDrop: 1,
  clientHubSilenceTimeoutMs: 1_000,
  rpcTimeoutMs: 1_000,
  transferInactivityMs: 1_000,
  transferAbsoluteMs: 1_000,
  discoveryProbeMs: 100,
  grantDefaultMs: 1_000,
});

export interface LinkConfig {
  configVersion?: number;
  terminalName?: string;
  network?: "lan" | "tailscale";
  currentRoomId?: string;
  /** Always an array after `loadConfig`, never undefined. */
  rooms?: RoomRecord[];
  timings?: Partial<LinkTimings>;
  /** Keys this build does not know about are carried through untouched. */
  [key: string]: unknown;
}

export interface LoadedConfig {
  /** Never null. Defaults plus whatever the file could contribute. */
  config: LinkConfig;
  /** Fully populated: every key present, every value a positive integer. */
  timings: LinkTimings;
  /** Absolute path of the file that was read (or would be written). */
  path: string;
  /** The file existed on disk. */
  exists: boolean;
  /** No recognised setting came from the file, so pure defaults are in force. */
  usedDefaults: boolean;
  /** A pre-`configVersion` (<= 3.4.0) file was read and forward-migrated in memory. */
  migrated: boolean;
  /** Human-readable, already naming the next action. Null when the file was clean. */
  warning: string | null;
}

/** A room record is only usable if every field routing depends on is a real string. */
function validRoom(value: unknown): RoomRecord | null {
  if (!value || typeof value !== "object") return null;
  const r = value as Record<string, unknown>;
  if (typeof r.roomId !== "string" || !r.roomId) return null;
  if (typeof r.hubPrincipalId !== "string" || typeof r.hubFingerprint !== "string") return null;
  if (typeof r.endpoint !== "string" || !r.endpoint) return null;
  return {
    roomId: r.roomId,
    label: typeof r.label === "string" && r.label ? r.label : "link",
    hubPrincipalId: r.hubPrincipalId,
    hubFingerprint: r.hubFingerprint,
    endpoint: r.endpoint,
    lastJoinedAt: typeof r.lastJoinedAt === "number" ? r.lastJoinedAt : 0,
  };
}

/**
 * Per-key coercion: one bad entry never poisons its neighbours, and callers are promised
 * positive integers so nobody re-clamps at the use site.
 */
function coerceTimings(raw: unknown): { timings: LinkTimings; rejected: string[] } {
  const timings = { ...DEFAULT_TIMINGS } as LinkTimings;
  const rejected: string[] = [];
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    if (raw !== undefined) rejected.push("timings");
    return { timings, rejected };
  }
  const bag = raw as Record<string, unknown>;
  for (const key of Object.keys(DEFAULT_TIMINGS) as (keyof LinkTimings)[]) {
    const value = bag[key];
    if (value === undefined) continue;
    if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
      rejected.push(key);
      continue;
    }
    const floored = Math.floor(value);
    timings[key] = floored < TIMING_FLOORS[key] ? TIMING_FLOORS[key] : floored;
  }
  return { timings, rejected };
}

function configPathFor(customOmpDir?: string): string {
  return path.join(customOmpDir || getOmpDir(), CONFIG_FILE_NAME);
}

function defaultsResult(file: string, warning: string | null, exists: boolean): LoadedConfig {
  return {
    config: { configVersion: CONFIG_SCHEMA_VERSION, rooms: [] },
    timings: { ...DEFAULT_TIMINGS },
    path: file,
    exists,
    usedDefaults: true,
    migrated: false,
    warning,
  };
}

/**
 * Read, validate, report and merge over defaults. Never throws: every failure mode degrades to
 * defaults plus a warning the caller shows once.
 */
export function loadConfig(customOmpDir?: string): LoadedConfig {
  let file: string;
  try {
    file = configPathFor(customOmpDir);
  } catch {
    // getOmpDir() touches the filesystem; a hostile HOME must not take the extension down.
    return defaultsResult(path.join(".", CONFIG_FILE_NAME), null, false);
  }

  let text: string;
  try {
    if (!fs.existsSync(file)) return defaultsResult(file, null, false);
    text = fs.readFileSync(file, "utf8");
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    return defaultsResult(
      file,
      `${file} could not be read (${reason}), so defaults are in force. Fix the file's permissions or delete it to start clean.`,
      true,
    );
  }

  if (!text.trim()) {
    return defaultsResult(
      file,
      `${file} is empty, so defaults are in force. Use /link create <name> or /link join <ip:port>.`,
      true,
    );
  }

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return defaultsResult(
      file,
      `${file} is not valid JSON, so it was ignored. Rooms and terminal name are stored there; delete the file to start clean.`,
      true,
    );
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return defaultsResult(
      file,
      `${file} does not contain a JSON object, so it was ignored. Delete the file to start clean.`,
      true,
    );
  }

  let warning: string | null = null;

  // Unknown keys are preserved: this file is also written by other tools.
  const config = { ...(raw as Record<string, unknown>) } as LinkConfig;

  const declaredVersion = typeof config.configVersion === "number" && Number.isFinite(config.configVersion)
    ? Math.floor(config.configVersion)
    : null;
  // A pre-3.5 file has no configVersion. Its shape is a subset of v1, so it is adopted silently.
  const migrated = declaredVersion === null;
  if (declaredVersion !== null && declaredVersion > CONFIG_SCHEMA_VERSION) {
    warning = `${file} was written by a newer omp-link (configVersion ${declaredVersion}); its settings are preserved but anything this build does not understand is ignored.`;
  }
  config.configVersion = CONFIG_SCHEMA_VERSION;

  const hadTerminalName = typeof config.terminalName === "string" && config.terminalName.trim() !== "";
  if (!hadTerminalName) delete config.terminalName;
  else config.terminalName = (config.terminalName as string).trim();

  const hadNetwork = config.network === "lan" || config.network === "tailscale";
  if (!hadNetwork) delete config.network;

  const hadCurrentRoom = typeof config.currentRoomId === "string" && config.currentRoomId !== "";
  if (!hadCurrentRoom) delete config.currentRoomId;

  const declared = Array.isArray(config.rooms) ? config.rooms : [];
  const rooms = declared.map(validRoom).filter((r): r is RoomRecord => r !== null);
  if (config.rooms !== undefined && !Array.isArray(config.rooms)) {
    warning = `${file} has a "rooms" value that is not a list, so no room was loaded. Use /link create <name> or /link join <ip:port>.`;
  } else if (rooms.length < declared.length) {
    warning = `${file} contains ${declared.length - rooms.length} unusable room record(s); they were skipped. Use /link create <name> or /link join <ip:port>.`;
  }
  config.rooms = rooms;

  const { timings, rejected } = coerceTimings(config.timings);
  if (rejected.length > 0) {
    warning = `${file} has unusable timing value(s) (${rejected.join(", ")}); the built-in default was used for each. Timings must be positive numbers of milliseconds.`;
  }
  if (config.timings !== undefined) config.timings = { ...(config.timings as Partial<LinkTimings>) };

  const usedDefaults =
    !hadTerminalName && !hadNetwork && !hadCurrentRoom && rooms.length === 0 && rejected.length === 0
    && config.timings === undefined;

  return { config, timings, path: file, exists: true, usedDefaults, migrated, warning };
}

/**
 * Merge `partial` over what is on disk and write it back atomically at 0600. Read-modify-write:
 * the caller supplies only the keys it owns, and unknown keys survive.
 */
export function saveConfig(partial: Partial<LinkConfig>, customOmpDir?: string): void {
  const file = configPathFor(customOmpDir);
  const merged: LinkConfig = {
    ...loadConfig(customOmpDir).config,
    ...partial,
    configVersion: CONFIG_SCHEMA_VERSION,
  };
  atomicWriteSecureFile(file, JSON.stringify(merged, null, 2) + "\n");
  timingsCache.delete(file);
}

/** The room `currentRoomId` points at, or null when it is unset or names a room that is gone. */
export function resolveCurrentRoom(config: LinkConfig): RoomRecord | null {
  if (!config.currentRoomId) return null;
  return (config.rooms || []).find((r) => r.roomId === config.currentRoomId) || null;
}

export function getCurrentRoom(customOmpDir?: string): RoomRecord | null {
  return resolveCurrentRoom(loadConfig(customOmpDir).config);
}

const timingsCache = new Map<string, LinkTimings>();

/**
 * Sync, never throws, fully populated. Cached per resolved state directory: a running terminal
 * reads its timings once, so editing `link.json` takes effect on the next start.
 */
export function getTimings(customOmpDir?: string): LinkTimings {
  let key: string;
  try {
    key = configPathFor(customOmpDir);
  } catch {
    return { ...DEFAULT_TIMINGS };
  }
  const cached = timingsCache.get(key);
  if (cached) return { ...cached };
  const timings = loadConfig(customOmpDir).timings;
  timingsCache.set(key, timings);
  return { ...timings };
}

/** Tests and `/link doctor` re-read after a write; production code never needs this. */
export function clearTimingsCache(): void {
  timingsCache.clear();
}
