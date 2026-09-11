import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { appendAuditLog } from "./audit.js";

export interface DevicePermissions {
  observe: boolean;
  message: boolean;
  compact: boolean;
  inspectMetadata: boolean;
  readContent: boolean;
  readDiff: boolean;
  fileInbox: boolean;
  execRequest: boolean;
  inspect?: boolean; // legacy compatibility alias
}

export const NO_PERMISSIONS: DevicePermissions = {
  observe: false,
  message: false,
  compact: false,
  inspectMetadata: false,
  readContent: false,
  readDiff: false,
  fileInbox: false,
  execRequest: false,
  inspect: false,
};

export const DEFAULT_PERMISSIONS: DevicePermissions = {
  observe: true,
  message: true,
  compact: false,
  inspectMetadata: false,
  readContent: false,
  readDiff: false,
  fileInbox: false,
  execRequest: false,
  inspect: false,
};

export const FULL_PERMISSIONS: DevicePermissions = {
  observe: true,
  message: true,
  compact: true,
  inspectMetadata: true,
  readContent: true,
  readDiff: true,
  fileInbox: true,
  execRequest: true,
  inspect: true,
};

export interface DeviceIdentity {
  certPem: string;
  keyPem: string;
  certDer: Buffer;
  spkiDer: Buffer;
  fingerprint: string;
  principalId: string;
  deviceName: string;
  keyType: string;
}

export interface PairedDevice {
  principalId: string;
  fingerprint: string;
  certPem: string;
  deviceName: string;
  permissions: DevicePermissions;
  pairedAt: number;
  lastSeen?: number;
  lastAddress?: string;
  workspaces?: string[];
}

export interface PairingInvite {
  inviteCode: string;
  secret: string;
  hubEndpoint?: string;
  hubFingerprint: string;
  hubPrincipalId: string;
  expiresAt: number;
  protocolVersion: number;
  sessionId?: string;
  used: boolean;
}

export const PAIRED_DEVICES_SCHEMA_VERSION = 3;

/** Bounds on the cross-process lock guarding paired-device read-modify-writes. */
const PAIRED_STORE_LOCK_WAIT_MS = 2_000;
const PAIRED_STORE_LOCK_STALE_MS = 10_000;

/** How long a process that lost the identity claim waits for the winner's certificate. */
const IDENTITY_CLAIM_WAIT_MS = 1_500;

/** Ownership evidence for the identity claim: who linked the key, recorded next to it. */
const IDENTITY_CLAIM_FILE = "device-key.claim.json";

/**
 * How long a claim with no live owner and no published certificate may sit before it counts as
 * abandoned. Only consulted when the claim record cannot prove liveness itself: written by an
 * older build, written on another host, or lost to a crash between `link()` and the claim write.
 */
const IDENTITY_CLAIM_ABANDONED_MS = 60_000;

/**
 * Shortest fingerprint prefix `resolvePairedDevice` will act on. Below this a typo matches an
 * arbitrary device: 4 bytes is short enough to type and long enough that a collision inside one
 * paired store is a deliberate act rather than an accident.
 */
export const DEVICE_PREFIX_MIN_HEX = 8;

// Wire encoding, not a display list: `encodeSasWords` maps raw bytes 0-255 to indices, so the
// length must stay exactly 256 and existing indices must never be reordered or removed. New
// entries are appended (252-255 were previously out of range and rendered `undefined`).
export const SAS_WORD_LIST: readonly string[] = Object.freeze([
  "ACORN", "ALARM", "ALPHA", "AMBER", "ANCHOR", "APEX", "APPLE", "ARROW",
  "ATLAS", "ATOM", "AVENUE", "AXIOM", "AZURE", "BADGE", "BANNER", "BARON",
  "BASIN", "BEACON", "BERYL", "BISON", "BLAZE", "BLOSSOM", "BOLT", "BONSAI",
  "BOULDER", "BRAVO", "BREEZE", "BRIDGE", "BRONZE", "BROOK", "CABIN", "CABLE",
  "CACTUS", "CANYON", "CARBON", "CASTLE", "CEDAR", "CHALK", "CHIME", "CHORUS",
  "CHROME", "CIDER", "CIRRUS", "CLIFF", "CLOAK", "CLOVER", "COBALT", "COMET",
  "COMPASS", "CONCORD", "COPPER", "CORAL", "COSMIC", "CRAG", "CRATER", "CREEK",
  "CREST", "CRYSTAL", "CYPRESS", "DAWN", "DELTA", "DUNE", "EAGLE", "ECHO",
  "EMBER", "EMERALD", "EPOCH", "FALCON", "FERN", "FINCH", "FJORD", "FLAME",
  "FLINT", "FLORA", "FORGE", "FOSSIL", "FROST", "GALAXY", "GARNET", "GEYSER",
  "GLADE", "GLACIER", "GLOW", "GRANITE", "GROVE", "HARBOR", "HAZEL", "HELMET",
  "HORIZON", "IGLOO", "INDIGO", "INLET", "IONIC", "ISLAND", "IVORY", "JADE",
  "JASPER", "JUNIPER", "KAPPA", "KELP", "KINETIC", "LAGOON", "LARCH", "LASER",
  "LAUREL", "LAVA", "LEGEND", "LEMON", "LIGHT", "LILAC", "LIME", "LINEN",
  "LIZARD", "LODGE", "LOTUS", "LUNAR", "MAGNET", "MANGO", "MANTLE", "MAPLE",
  "MARBLE", "MARINE", "MATRIX", "MEADOW", "MERCURY", "METEOR", "MINERAL", "MINT",
  "MIRAGE", "MIST", "MONARCH", "MOSS", "MYTHIC", "NEBULA", "NEPTUNE", "NICKEL",
  "NIMBUS", "NITRO", "NOVA", "OASIS", "OCEAN", "OLIVE", "OMEGA", "ONYX",
  "OPAL", "ORBIT", "ORCHID", "ORIGIN", "OSPREY", "OXYGEN", "PACIFIC", "PALM",
  "PANDA", "PANTHER", "PEBBLE", "PENGUIN", "PETAL", "PHOENIX", "PILLAR", "PINE",
  "PLANET", "PLASMA", "PLATINUM", "PLOVER", "POLAR", "POPPY", "PORTAL", "PRISM",
  "PROTON", "PULSAR", "PYRITE", "QUARTZ", "QUIVER", "RADAR", "RADIAN", "RAINBOW",
  "RAVEN", "REEF", "RELIC", "RIDGE", "RIVER", "ROBOT", "ROCKET", "RUBY",
  "RUSTIC", "SABLE", "SAHARA", "SAPPHIRE", "SATURN", "SCENIC", "SCORPIO", "SHADOW",
  "SIERRA", "SIGNAL", "SILVER", "SOLAR", "SONAR", "SPARK", "SPIRIT", "SPRING",
  "SPRUCE", "STAR", "SUMMIT", "SUNSET", "TALON", "TANDEM", "TARTAN", "TAURUS",
  "TELESCOPE", "TEMPLE", "TERRA", "THISTLE", "THUNDER", "TIDAL", "TIGER", "TIMBER",
  "TITAN", "TOPAZ", "TORCH", "TORNADO", "TOWER", "TRACK", "TRAIL", "TROPIC",
  "TUNDRA", "TURQUOISE", "ULTRA", "URANIUM", "URBAN", "VALLEY", "VALOR", "VELVET",
  "VENTURE", "VESSEL", "VIOLET", "VORTEX", "VOYAGE", "VULCAN", "WALNUT", "WAVE",
  "WILLOW", "WIND", "WINTER", "WOLF", "WONDER", "XENON", "YARROW", "YONDER",
  "ZENITH", "ZEPHYR", "ZINC", "ZODIAC",
  "BUNKER", "DIESEL", "FABRIC", "KETTLE",
]);

export function getOmpDir(): string {
  if (process.env.OMP_DIR) return process.env.OMP_DIR;
  const home = os.homedir();
  const ompDir = path.join(home, ".omp");
  if (fs.existsSync(ompDir)) return ompDir;
  const piDir = path.join(home, ".pi");
  if (fs.existsSync(piDir)) return piDir;
  return ompDir;
}

export function atomicWriteSecureFile(filePath: string, content: string | Buffer): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  const tmpPath = `${filePath}.tmp.${crypto.randomBytes(6).toString("hex")}`;
  fs.writeFileSync(tmpPath, content, { mode: 0o600 });
  try {
    fs.chmodSync(tmpPath, 0o600);
  } catch {}
  fs.renameSync(tmpPath, filePath);
}

export function fingerprintDer(der: Buffer): string {
  return crypto
    .createHash("sha256")
    .update(der)
    .digest("hex")
    .toUpperCase()
    .match(/.{2}/g)!
    .join(":");
}

export function canonicalSpkiDer(certPemOrDer: string | Buffer): Buffer {
  const cert = new crypto.X509Certificate(certPemOrDer);
  return cert.publicKey.export({ format: "der", type: "spki" }) as Buffer;
}

export function fingerprintPublicKey(spkiDer: Buffer): string {
  if (spkiDer.length > 512) {
    throw new Error("Public key too large");
  }
  return fingerprintDer(spkiDer);
}

export function normalizeFingerprint(fp: string): string {
  const cleaned = fp.replace(/[^a-fA-F0-9]/g, "").toUpperCase();
  if (cleaned.length !== 64) {
    throw new Error(`Invalid SHA-256 fingerprint length: expected 64 hex characters, got ${cleaned.length}`);
  }
  return cleaned.match(/.{2}/g)!.join(":");
}

export interface CertificateIdentity {
  cert: crypto.X509Certificate;
  certDer: Buffer;
  spkiDer: Buffer;
  keyType: string;
  fingerprint: string;
  principalId: string;
}

export function identityFromCertificate(certPemOrDer: string | Buffer): CertificateIdentity {
  const cert = new crypto.X509Certificate(certPemOrDer);
  const keyType = cert.publicKey.asymmetricKeyType;

  if (keyType !== "ed25519" && keyType !== "ec") {
    throw new Error(`Unsupported identity key type: ${keyType}`);
  }

  const spkiDer = cert.publicKey.export({
    format: "der",
    type: "spki",
  }) as Buffer;

  const spkiFingerprint = fingerprintDer(spkiDer);

  return {
    cert,
    certDer: cert.raw,
    spkiDer,
    keyType,
    fingerprint: spkiFingerprint,
    principalId: `${keyType}-sha256:${spkiFingerprint}`,
  };
}

/**
 * Block this thread without spawning anything. Used only on cold paths (lock contention, waiting
 * for another process to publish an identity) where the alternative would be a subprocess per
 * poll and a hard dependency on `sleep` being on PATH.
 */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** Liveness of another process; the only honest evidence that a claim or lock is abandoned. */
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err: unknown) {
    // EPERM means the process exists but is owned by another user: alive.
    const code = typeof err === "object" && err !== null && "code" in err ? err.code : undefined;
    return code === "EPERM";
  }
}

/** Error text for a message an operator will read, from a `catch` binding of unknown shape. */
function describeError(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

interface IdentityClaim {
  pid: number;
  host: string;
  at: number;
}

function identityClaimPath(keyPath: string): string {
  return path.join(path.dirname(keyPath), IDENTITY_CLAIM_FILE);
}

/** Record who owns the claim, so a later starter can ask whether that process is still running. */
function writeIdentityClaim(keyPath: string): void {
  try {
    atomicWriteSecureFile(
      identityClaimPath(keyPath),
      JSON.stringify({ pid: process.pid, host: os.hostname(), at: Date.now() }),
    );
  } catch {}
}

function readIdentityClaim(keyPath: string): IdentityClaim | null {
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(identityClaimPath(keyPath), "utf8"));
    if (typeof parsed !== "object" || parsed === null || !("pid" in parsed)) return null;
    const pid = parsed.pid;
    if (typeof pid !== "number" || !Number.isSafeInteger(pid) || pid <= 0) return null;
    const host = "host" in parsed ? parsed.host : undefined;
    const at = "at" in parsed ? parsed.at : undefined;
    return {
      pid,
      host: typeof host === "string" ? host : "",
      at: typeof at === "number" ? at : 0,
    };
  } catch {
    return null;
  }
}

/**
 * May this process take over a claim that has published no certificate?
 *
 * A missing certificate proves the claimant is slow, not dead: stealing on a timeout is exactly
 * how a directory ends up holding this process's key beside the winner's certificate, a pair
 * that fails inside `tls.createSecureContext` on every later start. So the claim is broken only
 * on evidence that its owner is gone — never on patience alone.
 *
 * The evidence is the claim record, written immediately after `link()` and before the
 * certificate. A live claimant on this build therefore always has one by the time a loser has
 * waited out a full claim window, which is what makes its absence conclusive: no record means a
 * process that died inside the two-step window (C9) or a pre-3.4 leftover, and in both cases a
 * key nobody holds a certificate for is unusable and must not wedge the directory for ever. A
 * record written on another host says nothing about local pids — a shared or synced home — so
 * that case falls back to age.
 */
function identityClaimIsAbandoned(keyPath: string): boolean {
  const claim = readIdentityClaim(keyPath);
  if (!claim) return true;
  if (claim.host !== os.hostname()) return Date.now() - claim.at > IDENTITY_CLAIM_ABANDONED_MS;
  return !isProcessAlive(claim.pid);
}

/** Take the identity claim atomically. Returns false when another process already holds it. */
function claimIdentityKey(stageKey: string, keyPath: string): boolean {
  try {
    fs.linkSync(stageKey, keyPath);
    return true;
  } catch (err: unknown) {
    const code = typeof err === "object" && err !== null && "code" in err ? err.code : undefined;
    if (code === "EEXIST") return false;
    throw err;
  }
}

/**
 * Generate the device keypair into a private staging directory and claim it atomically.
 *
 * Two terminals starting for the first time at the same moment each mint a keypair; without an
 * exclusive claim the later `rename` wins and the two processes end up disagreeing about their
 * own device principal, which breaks pinning for every peer that already paired with the loser.
 * `link()` is atomic and fails with EEXIST, so exactly one process installs its pair and the
 * others discard theirs and adopt the winner's.
 *
 * Returns the key type of the identity now on disk, and whether this process created it.
 */
export function generateDeviceCertificate(
  keyPath: string,
  certPath: string,
): { keyType: string; created: boolean } {
  const stageDir = fs.mkdtempSync(path.join(path.dirname(keyPath), ".genid-"));
  const stageKey = path.join(stageDir, "key.pem");
  const stageCert = path.join(stageDir, "cert.pem");
  let keyType = "ed25519";

  const argsFor = (algo: string[]) => [
    "req", "-x509",
    "-newkey", ...algo,
    "-nodes",
    "-keyout", stageKey,
    "-out", stageCert,
    "-days", "3650",
    "-subj", "/CN=omp-link-device",
  ];

  try {
    try {
      execFileSync("openssl", argsFor(["ed25519"]), { stdio: "pipe" });
    } catch {
      keyType = "ec";
      execFileSync("openssl", argsFor(["ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]), { stdio: "pipe" });
    }

    try {
      fs.chmodSync(stageKey, 0o600);
      fs.chmodSync(stageCert, 0o600);
    } catch {}

    // The key is the exclusive claim: whoever links it first owns the identity.
    if (!claimIdentityKey(stageKey, keyPath)) {
      // Two rounds. Losing the reclaim means another process took the claim in the same
      // microsecond and is about to publish a certificate, so waiting again is the honest
      // response; only a second failure is a real dead end.
      for (let attempt = 0; attempt < 2; attempt++) {
        const deadline = Date.now() + IDENTITY_CLAIM_WAIT_MS;
        while (Date.now() < deadline) {
          try {
            const certPem = fs.readFileSync(certPath, "utf8");
            if (certPem.includes("BEGIN CERTIFICATE")) {
              return { keyType: identityFromCertificate(certPem).keyType, created: false };
            }
          } catch {}
          sleepSync(20);
        }
        if (fs.existsSync(certPath)) continue;
        // Running out of patience is not evidence that the claimant died; the claim record is.
        if (!identityClaimIsAbandoned(keyPath)) continue;
        try { fs.unlinkSync(keyPath); } catch {}
        if (claimIdentityKey(stageKey, keyPath)) {
          writeIdentityClaim(keyPath);
          fs.renameSync(stageCert, certPath);
          appendAuditLog({
            type: "identity_claim_reclaimed",
            timestamp: Date.now(),
            keyPath,
            reason: "previous claimant is not running and published no certificate",
          });
          return { keyType, created: true };
        }
      }
      const holder = readIdentityClaim(keyPath);
      throw new Error(
        `Another process${holder ? ` (pid ${holder.pid} on ${holder.host || "this host"})` : ""} holds the `
        + `device identity claim at ${keyPath} but has published no certificate. Stop that process, or `
        + `delete ${keyPath} if it is gone, and start again.`,
      );
    }
    // Claim won. Record the owner before publishing the matching certificate; overwriting is safe
    // because only the winner reaches this line.
    writeIdentityClaim(keyPath);
    fs.renameSync(stageCert, certPath);
    return { keyType, created: true };
  } finally {
    try { fs.rmSync(stageDir, { recursive: true, force: true }); } catch {}
  }
}

type IdentityPairLoad =
  | { status: "ok"; certPem: string; keyPem: string; info: CertificateIdentity }
  | { status: "absent" }
  | { status: "invalid"; reason: string };

/**
 * Load the on-disk pair and prove the private key belongs to the certificate.
 *
 * Existence is not validity: a broken claim, a half-restored backup or a hand-copied file can
 * leave one process's key beside another's certificate. Nothing downstream notices —
 * `identityFromCertificate` parses the certificate alone — so the first symptom is
 * `error:0B080074:...:key values mismatch` out of `tls.createSecureContext`, verbatim, on every
 * start for ever. Deriving the SPKI from the key and comparing it is the one cheap place to
 * catch that while it is still recoverable.
 */
function readIdentityPair(keyPath: string, certPath: string): IdentityPairLoad {
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) return { status: "absent" };

  let certPem: string;
  let keyPem: string;
  try {
    certPem = fs.readFileSync(certPath, "utf8");
    keyPem = fs.readFileSync(keyPath, "utf8");
  } catch (err: unknown) {
    return { status: "invalid", reason: `identity files are unreadable: ${describeError(err)}` };
  }

  let info: CertificateIdentity;
  try {
    info = identityFromCertificate(certPem);
  } catch (err: unknown) {
    return { status: "invalid", reason: `certificate is unusable: ${describeError(err)}` };
  }

  let keySpkiDer: Buffer;
  try {
    keySpkiDer = crypto.createPublicKey(keyPem).export({ format: "der", type: "spki" }) as Buffer;
  } catch (err: unknown) {
    return { status: "invalid", reason: `private key is unusable: ${describeError(err)}` };
  }

  if (!keySpkiDer.equals(info.spkiDer)) {
    return { status: "invalid", reason: "private key does not match the certificate" };
  }

  return { status: "ok", certPem, keyPem, info };
}

/**
 * Move an unusable pair aside so generation can start clean. A mismatched or unparseable pair
 * cannot serve TLS and cannot have been pinned by any peer, so keeping it only wedges every
 * future start; it is archived rather than deleted because it is evidence of what went wrong.
 */
function archiveBrokenIdentity(identityDir: string, keyPath: string, certPath: string, reason: string): void {
  const archiveDir = path.join(identityDir, `broken-${Date.now()}`);
  try {
    fs.mkdirSync(archiveDir, { recursive: true, mode: 0o700 });
    for (const file of [keyPath, certPath, identityClaimPath(keyPath)]) {
      if (!fs.existsSync(file)) continue;
      fs.renameSync(file, path.join(archiveDir, path.basename(file)));
    }
  } catch (err: unknown) {
    throw new Error(
      `The device identity in ${identityDir} is unusable (${reason}) and could not be archived: `
      + `${describeError(err)}. Move ${identityDir} aside and start again.`,
    );
  }
  appendAuditLog({
    type: "identity_pair_archived",
    timestamp: Date.now(),
    reason,
    archivedTo: archiveDir,
  });
}

/**
 * The identity directory holds this device's private key. `OMP_DIR` is honoured unconditionally
 * and the runbook tells people to point it at a scratch path, so a directory owned by another
 * local user is reachable by accident — and whoever owns it can pre-plant a keypair that this
 * hub then serves TLS under while the attacker holds the private half. Ownership is the check
 * that matters; a mode looser than 0700 is tightened, and refused when it cannot be.
 */
function ensureIdentityDirIsPrivate(identityDir: string): void {
  if (!fs.existsSync(identityDir)) {
    fs.mkdirSync(identityDir, { recursive: true, mode: 0o700 });
  }

  const getuid = process.getuid;
  if (typeof getuid !== "function") return; // No uid model (Windows): nothing to compare against.
  const uid = getuid.call(process);

  let stat = fs.statSync(identityDir);
  if (stat.uid !== uid) {
    appendAuditLog({
      type: "identity_dir_foreign_owner",
      timestamp: Date.now(),
      path: identityDir,
      ownerUid: stat.uid,
      expectedUid: uid,
    });
    throw new Error(
      `Refusing to use the device identity in ${identityDir}: it is owned by uid ${stat.uid}, not `
      + `uid ${uid}. Another local user could plant the private key this device would serve TLS `
      + `under. Point OMP_DIR at a directory you own.`,
    );
  }

  if ((stat.mode & 0o077) !== 0) {
    const previousMode = (stat.mode & 0o777).toString(8);
    try { fs.chmodSync(identityDir, 0o700); } catch {}
    stat = fs.statSync(identityDir);
    if ((stat.mode & 0o077) !== 0) {
      throw new Error(
        `Refusing to use the device identity in ${identityDir}: mode 0${(stat.mode & 0o777).toString(8)} `
        + `leaves the private key reachable by other local users and it could not be tightened to 0700.`,
      );
    }
    appendAuditLog({
      type: "identity_dir_permissions_tightened",
      timestamp: Date.now(),
      path: identityDir,
      previousMode: `0${previousMode}`,
    });
  }
}

export function getOrCreateDeviceIdentity(customOmpDir?: string): DeviceIdentity {
  const baseDir = customOmpDir || getOmpDir();
  const identityDir = path.join(baseDir, "identity");
  const certPath = path.join(identityDir, "device-cert.pem");
  const keyPath = path.join(identityDir, "device-key.pem");
  const metaPath = path.join(identityDir, "metadata.json");

  ensureIdentityDirIsPrivate(identityDir);

  let loaded = readIdentityPair(keyPath, certPath);
  if (loaded.status === "invalid") {
    // Self-heal: an unusable pair is archived and replaced rather than surfacing as an OpenSSL
    // error on every start that only hand-deleting the directory can clear.
    archiveBrokenIdentity(identityDir, keyPath, certPath, loaded.reason);
    loaded = { status: "absent" };
  }
  if (loaded.status === "absent") {
    generateDeviceCertificate(keyPath, certPath);
    loaded = readIdentityPair(keyPath, certPath);
    if (loaded.status !== "ok") {
      const reason = loaded.status === "invalid" ? loaded.reason : "the files are missing";
      throw new Error(
        `The device identity in ${identityDir} is still unusable after generating a new pair `
        + `(${reason}). Move ${identityDir} aside and start again.`,
      );
    }
  }

  const { certPem, keyPem, info } = loaded;
  let deviceName = os.hostname() || "omp-node";

  if (fs.existsSync(metaPath)) {
    try {
      const meta: unknown = JSON.parse(fs.readFileSync(metaPath, "utf8"));
      if (typeof meta === "object" && meta !== null && "deviceName" in meta) {
        const stored = meta.deviceName;
        if (typeof stored === "string" && stored) deviceName = stored;
      }
    } catch {}
  }

  atomicWriteSecureFile(
    metaPath,
    JSON.stringify(
      {
        deviceName,
        createdAt: Date.now(),
        principalId: info.principalId,
        fingerprint: info.fingerprint,
      },
      null,
      2,
    ),
  );

  return {
    certPem,
    keyPem,
    certDer: info.certDer,
    spkiDer: info.spkiDer,
    fingerprint: info.fingerprint,
    principalId: info.principalId,
    deviceName,
    keyType: info.keyType,
  };
}

let pairedStoreWasReset = false;

export function wasPairedStoreReset(): boolean {
  return pairedStoreWasReset;
}

export function loadPairedDevices(customOmpDir?: string): Map<string, PairedDevice> {
  const baseDir = customOmpDir || getOmpDir();
  const file = path.join(baseDir, "paired-devices.json");
  const map = new Map<string, PairedDevice>();
  if (!fs.existsSync(file)) return map;

  try {
    const data: unknown = JSON.parse(fs.readFileSync(file, "utf8"));
    let version = 1;
    let rawItems: unknown[] = [];

    if (Array.isArray(data)) {
      rawItems = data;
    } else if (typeof data === "object" && data !== null) {
      const declaredVersion = "version" in data ? data.version : undefined;
      const declaredDevices = "devices" in data ? data.devices : undefined;
      if (typeof declaredVersion === "number" && Array.isArray(declaredDevices)) {
        version = declaredVersion;
        rawItems = declaredDevices;
      } else {
        rawItems = Object.values(data);
      }
    }

    // There is no migration path: older stores were written by a build whose pairing could be
    // spoofed (unbound SAS) and whose permission records are not trustworthy today. Archive the
    // old file for forensics, start empty, and let the user re-pair.
    if (version < PAIRED_DEVICES_SCHEMA_VERSION) {
      const backupFile = path.join(baseDir, `paired-devices.v${version}.bak.json`);
      try {
        fs.renameSync(file, backupFile);
      } catch {}
      pairedStoreWasReset = true;
      appendAuditLog({
        type: "paired_store_reset",
        timestamp: Date.now(),
        fromVersion: version,
        toVersion: PAIRED_DEVICES_SCHEMA_VERSION,
        discardedDevices: rawItems.length,
        backupFile,
      });
      return map;
    }

    for (const item of rawItems) {
      if (typeof item !== "object" || item === null) continue;
      const certPem = "certPem" in item ? item.certPem : undefined;
      const storedFingerprint = "fingerprint" in item ? item.fingerprint : undefined;
      if (!certPem || typeof storedFingerprint !== "string" || !storedFingerprint) continue;
      const canonicalFp = normalizeFingerprint(storedFingerprint);
      const storedPermissions = "permissions" in item ? item.permissions : undefined;
      // Fields beyond the two validated here are carried through unchanged: this store is
      // written by this module, and everything security-relevant is re-derived on use (the
      // permissions below, the certificate at pin time).
      const record = item as PairedDevice;
      map.set(canonicalFp, {
        ...record,
        fingerprint: canonicalFp,
        permissions: {
          ...DEFAULT_PERMISSIONS,
          ...(typeof storedPermissions === "object" && storedPermissions !== null ? storedPermissions : {}),
        },
      });
    }
  } catch {}

  return map;
}

interface PairedStoreLockOwner {
  pid: number;
  token: string;
}

function parsePairedStoreLock(raw: string): PairedStoreLockOwner | null {
  const separator = raw.indexOf(":");
  if (separator <= 0) return null;
  const pid = Number(raw.slice(0, separator));
  const token = raw.slice(separator + 1).trim();
  if (!Number.isSafeInteger(pid) || pid <= 0 || !token) return null;
  return { pid, token };
}

function readPairedStoreLock(lockPath: string): string | null {
  try {
    return fs.readFileSync(lockPath, "utf8");
  } catch {
    return null;
  }
}

/**
 * Break a lock only with evidence that its owner is gone: the recorded pid is dead, or the file
 * carries no usable owner at all (an older build, a truncated write) and has aged past the stale
 * window. Age alone is not evidence — a slow holder is still a holder.
 */
function breakStalePairedStoreLock(lockPath: string): void {
  const raw = readPairedStoreLock(lockPath);
  if (raw === null) return;
  let ageMs: number;
  try {
    ageMs = Date.now() - fs.statSync(lockPath).mtimeMs;
  } catch {
    return;
  }

  const owner = parsePairedStoreLock(raw);
  if (owner ? isProcessAlive(owner.pid) : ageMs <= PAIRED_STORE_LOCK_STALE_MS) return;
  // Re-read before unlinking: if the contents moved, another writer already broke and retook it.
  if (readPairedStoreLock(lockPath) !== raw) return;
  try {
    fs.unlinkSync(lockPath);
  } catch {
    return;
  }
  appendAuditLog({
    type: "paired_store_lock_broken",
    timestamp: Date.now(),
    lockPath,
    ownerPid: owner ? owner.pid : null,
    ageMs,
  });
}

/**
 * Serialise a read-modify-write of the paired-device store across processes.
 *
 * `atomicWriteSecureFile` makes each write atomic but does nothing about two terminals reading
 * the same snapshot and writing back different supersets: the later write silently drops the
 * other's device. Sibling terminals share one store, so this is reachable whenever two of them
 * pair at the same moment.
 *
 * The lock file carries its owner (`${pid}:${token}`) because a local `held` flag does not
 * survive being stolen: a holder whose lock was broken would unlink the *thief's* lock on the
 * way out and admit a third writer. So the file is only broken with proof its owner is gone, and
 * only removed by the process whose token is still in it. A caller that cannot take the lock
 * before the deadline still performs its update — losing the lock must never lose a device — and
 * audits that the write was not serialised so `doctor` can show it.
 *
 * Exported because invariant 24 applies to every paired-store mutator, including ones written
 * later, and because the regression suite drives the steal-and-release rules through it.
 */
export function withPairedStoreLock<T>(baseDir: string, mutate: () => T): T {
  if (!fs.existsSync(baseDir)) {
    try { fs.mkdirSync(baseDir, { recursive: true, mode: 0o700 }); } catch {}
  }
  const lockPath = path.join(baseDir, "paired-devices.lock");
  const token = `${process.pid}:${crypto.randomBytes(12).toString("hex")}`;
  const deadline = Date.now() + PAIRED_STORE_LOCK_WAIT_MS;
  let held = false;

  while (Date.now() < deadline) {
    try {
      const fd = fs.openSync(lockPath, "wx", 0o600);
      try {
        fs.writeSync(fd, token);
      } finally {
        fs.closeSync(fd);
      }
      held = true;
      break;
    } catch {
      breakStalePairedStoreLock(lockPath);
      sleepSync(10);
    }
  }

  if (!held) {
    const owner = parsePairedStoreLock(readPairedStoreLock(lockPath) || "");
    appendAuditLog({
      type: "paired_store_lock_timeout",
      timestamp: Date.now(),
      lockPath,
      waitedMs: PAIRED_STORE_LOCK_WAIT_MS,
      holderPid: owner ? owner.pid : null,
    });
  }

  try {
    return mutate();
  } finally {
    // Only remove a lock that is still ours. If it was broken and retaken, the file belongs to
    // another writer now and unlinking it would let a third in behind their back.
    if (held && readPairedStoreLock(lockPath) === token) {
      try { fs.unlinkSync(lockPath); } catch {}
    }
  }
}

export function savePairedDevice(device: PairedDevice, customOmpDir?: string): void {
  const baseDir = customOmpDir || getOmpDir();
  const file = path.join(baseDir, "paired-devices.json");
  withPairedStoreLock(baseDir, () => {
    // Re-read INSIDE the lock: a snapshot taken before it was held may already be stale.
    const devices = loadPairedDevices(customOmpDir);
    const canonicalFp = normalizeFingerprint(device.fingerprint);
    devices.set(canonicalFp, { ...device, fingerprint: canonicalFp });
    atomicWriteSecureFile(
      file,
      JSON.stringify({ version: PAIRED_DEVICES_SCHEMA_VERSION, devices: Array.from(devices.values()) }, null, 2) + "\n",
    );
  });
}

/**
 * How an operator's argument resolves to exactly one paired device.
 *
 * `/link revoke <name>` used to take the first record whose fingerprint started with the input —
 * no length floor, no ambiguity check — so a one-character argument unpaired an arbitrary device
 * and reported success. The contract is now, in order, first tier that matches anything wins:
 *
 *   1. an exact `principalId`;
 *   2. a full 64-hex-digit fingerprint in any separator style;
 *   3. an exact `deviceName`;
 *   4. a fingerprint prefix of at least `DEVICE_PREFIX_MIN_HEX` hex digits.
 *
 * A tier matching more than one record is `ambiguous` and resolves to nothing: two devices
 * sharing a name, or a prefix shared by two fingerprints, is for the operator to disambiguate,
 * never for this code to guess.
 */
export type DeviceLookupReason = "matched" | "not-found" | "ambiguous" | "prefix-too-short";

export interface DeviceLookup {
  /** Set only when exactly one record matched. */
  device?: PairedDevice;
  /** Every record the input matched; more than one means the lookup refused. */
  matches: PairedDevice[];
  reason: DeviceLookupReason;
}

export interface PairedDeviceRemoval extends DeviceLookup {
  removed: boolean;
}

function decideLookup(matches: PairedDevice[]): DeviceLookup {
  if (matches.length === 0) return { matches, reason: "not-found" };
  if (matches.length > 1) return { matches, reason: "ambiguous" };
  return { device: matches[0], matches, reason: "matched" };
}

function resolveFromStore(input: string, devices: Map<string, PairedDevice>): DeviceLookup {
  const query = input.trim();
  if (!query) return { matches: [], reason: "not-found" };
  const all = Array.from(devices.values());

  const byPrincipal = all.filter((dev) => dev.principalId === query);
  if (byPrincipal.length > 0) return decideLookup(byPrincipal);

  let canonical: string | null = null;
  try {
    canonical = normalizeFingerprint(query);
  } catch {}
  if (canonical) return decideLookup(all.filter((dev) => dev.fingerprint === canonical));

  const byName = all.filter((dev) => dev.deviceName === query);
  if (byName.length > 0) return decideLookup(byName);

  // Only an all-hex argument (colons, spaces and dashes allowed as separators) is read as a
  // fingerprint prefix; a device name that happens to contain hex letters is not one.
  if (!/^[0-9a-fA-F][0-9a-fA-F:\s-]*$/.test(query)) return { matches: [], reason: "not-found" };
  const hex = query.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
  if (hex.length < DEVICE_PREFIX_MIN_HEX) return { matches: [], reason: "prefix-too-short" };
  return decideLookup(all.filter((dev) => dev.fingerprint.replace(/:/g, "").startsWith(hex)));
}

export function resolvePairedDevice(fingerprintOrPrincipal: string, customOmpDir?: string): DeviceLookup {
  return resolveFromStore(fingerprintOrPrincipal, loadPairedDevices(customOmpDir));
}

/**
 * Remove one paired device. Refuses — removing nothing — when the argument matches more than one
 * record or is too short to identify one; `reason` says which, and the refusal is audited.
 */
export function removePairedDeviceResult(
  fingerprintOrPrincipal: string,
  customOmpDir?: string,
): PairedDeviceRemoval {
  const baseDir = customOmpDir || getOmpDir();
  const file = path.join(baseDir, "paired-devices.json");
  return withPairedStoreLock(baseDir, () => {
    const devices = loadPairedDevices(customOmpDir);
    const found = resolveFromStore(fingerprintOrPrincipal, devices);

    if (!found.device) {
      if (found.reason !== "not-found") {
        appendAuditLog({
          type: "device_removal_refused",
          timestamp: Date.now(),
          reason: found.reason,
          query: fingerprintOrPrincipal,
          matched: found.matches.map((dev) => dev.principalId),
        });
      }
      return { ...found, removed: false };
    }

    devices.delete(found.device.fingerprint);
    atomicWriteSecureFile(
      file,
      JSON.stringify({ version: PAIRED_DEVICES_SCHEMA_VERSION, devices: Array.from(devices.values()) }, null, 2) + "\n",
    );
    return { ...found, removed: true };
  });
}

/**
 * Boolean form, for the call sites that only branch on success. A caller that needs to tell "no
 * such device" from "that argument could mean two devices" must use `removePairedDeviceResult`.
 */
export function removePairedDevice(fingerprintOrPrincipal: string, customOmpDir?: string): boolean {
  return removePairedDeviceResult(fingerprintOrPrincipal, customOmpDir).removed;
}

export function getPairedDevice(fingerprintOrPrincipal: string, customOmpDir?: string): PairedDevice | undefined {
  return resolveFromStore(fingerprintOrPrincipal, loadPairedDevices(customOmpDir)).device;
}

export function encodeSasWords(hash: Buffer): string {
  const w1 = SAS_WORD_LIST[hash[0]];
  const w2 = SAS_WORD_LIST[hash[1]];
  const w3 = SAS_WORD_LIST[hash[2]];
  const w4 = SAS_WORD_LIST[hash[3]];
  return `${w1}-${w2}-${w3}-${w4}`;
}

export interface TlsExporterSocket {
  exportKeyingMaterial?: (length: number, label: string, context: Buffer) => Buffer;
}

// The SAS must be bound to the TLS channel, so there is deliberately no fallback: any key an
// offline path could derive would come only from public handshake values (SPKIs and nonces),
// which a MITM terminating two TLS sessions also knows — it could then make both displayed codes
// agree. A runtime without RFC 5705 keying-material export cannot pair; it must fail closed.
export function deriveLocalSas(
  socket: TlsExporterSocket | null | undefined,
  hubSpki: Buffer,
  clientSpki: Buffer,
  hubNonce: Buffer,
  clientNonce: Buffer,
): string {
  if (!socket || typeof socket.exportKeyingMaterial !== "function") {
    throw new Error("PAIRING_UNSUPPORTED_RUNTIME");
  }

  const context = crypto
    .createHash("sha256")
    .update("omp-link/pairing/v5\0")
    .update(hubSpki)
    .update(clientSpki)
    .update(hubNonce)
    .update(clientNonce)
    .digest();

  const key = socket.exportKeyingMaterial(
    32,
    "EXPORTER-omp-link-pairing-v5",
    context,
  );

  const value = crypto
    .createHmac("sha256", key)
    .update(context)
    .digest();

  return encodeSasWords(value);
}

const activeInvites = new Map<string, PairingInvite>();

export function createInvite(
  hubIdentity: DeviceIdentity,
  options: { expiresInMs?: number; endpoint?: string; sessionId?: string } = {},
): PairingInvite {
  const expiresInMs = options.expiresInMs || 300_000;
  const secret = crypto.randomBytes(32).toString("hex");
  const inviteCode = `omp-${crypto.randomBytes(4).toString("hex")}-${secret.slice(0, 8)}`;
  const invite: PairingInvite = {
    inviteCode,
    secret,
    hubEndpoint: options.endpoint,
    hubFingerprint: hubIdentity.fingerprint,
    hubPrincipalId: hubIdentity.principalId,
    expiresAt: Date.now() + expiresInMs,
    protocolVersion: 5,
    sessionId: options.sessionId,
    used: false,
  };
  activeInvites.set(secret, invite);
  return invite;
}

export function verifyAndConsumeInvite(secret: string): { valid: boolean; reason?: string; invite?: PairingInvite } {
  const invite = activeInvites.get(secret);
  if (!invite) {
    return { valid: false, reason: "Invitation not found" };
  }
  if (invite.used) {
    return { valid: false, reason: "Invitation already consumed" };
  }
  if (Date.now() > invite.expiresAt) {
    activeInvites.delete(secret);
    return { valid: false, reason: "Invitation expired" };
  }
  invite.used = true;
  activeInvites.delete(secret);
  return { valid: true, invite };
}

export function getActiveInvite(secret: string): PairingInvite | undefined {
  const inv = activeInvites.get(secret);
  if (inv && Date.now() > inv.expiresAt) {
    activeInvites.delete(secret);
    return undefined;
  }
  return inv;
}

export function clearActiveInvites(): void {
  activeInvites.clear();
}
