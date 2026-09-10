import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";

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

export const PAIRED_DEVICES_SCHEMA_VERSION = 2;

export const SAS_WORD_LIST = [
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
];

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

export function identityFromCertificate(certPemOrDer: string | Buffer): {
  cert: crypto.X509Certificate;
  certDer: Buffer;
  spkiDer: Buffer;
  keyType: string;
  fingerprint: string;
  principalId: string;
} {
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

export function principalFromCertificate(certPemOrDer: string | Buffer): string {
  return identityFromCertificate(certPemOrDer).principalId;
}

export function generateDeviceCertificate(keyPath: string, certPath: string): { keyType: string } {
  let keyType = "ed25519";
  try {
    execFileSync("openssl", [
      "req", "-x509",
      "-newkey", "ed25519",
      "-nodes",
      "-keyout", keyPath,
      "-out", certPath,
      "-days", "3650",
      "-subj", "/CN=omp-link-device",
    ], { stdio: "pipe" });
  } catch {
    keyType = "ec";
    execFileSync("openssl", [
      "req", "-x509",
      "-newkey", "ec",
      "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-nodes",
      "-keyout", keyPath,
      "-out", certPath,
      "-days", "3650",
      "-subj", "/CN=omp-link-device",
    ], { stdio: "pipe" });
  }

  try {
    fs.chmodSync(keyPath, 0o600);
    fs.chmodSync(certPath, 0o600);
  } catch {}

  return { keyType };
}

export function getOrCreateDeviceIdentity(customOmpDir?: string): DeviceIdentity {
  const baseDir = customOmpDir || getOmpDir();
  const identityDir = path.join(baseDir, "identity");
  const certPath = path.join(identityDir, "device-cert.pem");
  const keyPath = path.join(identityDir, "device-key.pem");
  const metaPath = path.join(identityDir, "metadata.json");

  if (!fs.existsSync(identityDir)) {
    fs.mkdirSync(identityDir, { recursive: true, mode: 0o700 });
  }

  let deviceName = os.hostname() || "omp-node";

  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    try {
      const certPem = fs.readFileSync(certPath, "utf8");
      const keyPem = fs.readFileSync(keyPath, "utf8");
      const info = identityFromCertificate(certPem);

      if (fs.existsSync(metaPath)) {
        try {
          const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
          if (meta.deviceName) deviceName = meta.deviceName;
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
    } catch {}
  }

  const { keyType } = generateDeviceCertificate(keyPath, certPath);
  const certPem = fs.readFileSync(certPath, "utf8");
  const keyPem = fs.readFileSync(keyPath, "utf8");
  const info = identityFromCertificate(certPem);

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

export function loadPairedDevices(customOmpDir?: string): Map<string, PairedDevice> {
  const baseDir = customOmpDir || getOmpDir();
  const file = path.join(baseDir, "paired-devices.json");
  const map = new Map<string, PairedDevice>();
  if (!fs.existsSync(file)) return map;

  try {
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    let version = 1;
    let rawItems: any[] = [];

    if (Array.isArray(data)) {
      rawItems = data;
    } else if (data && typeof data === "object") {
      if (typeof data.version === "number" && Array.isArray(data.devices)) {
        version = data.version;
        rawItems = data.devices;
      } else {
        rawItems = Object.values(data);
      }
    }

    let needsSave = version < PAIRED_DEVICES_SCHEMA_VERSION;

    for (const item of rawItems) {
      if (item && item.certPem) {
        let canonicalFp = item.fingerprint ? normalizeFingerprint(item.fingerprint) : "";
        let principalId = item.principalId;

        if (version < 2) {
          try {
            const info = identityFromCertificate(item.certPem);
            canonicalFp = info.fingerprint;
            principalId = info.principalId;
            needsSave = true;
          } catch {}
        }

        if (canonicalFp) {
          map.set(canonicalFp, {
            ...item,
            fingerprint: canonicalFp,
            principalId: principalId || item.principalId,
            permissions: {
              ...DEFAULT_PERMISSIONS,
              ...(item.permissions || {}),
              ...(item.permissions?.inspect
                ? { inspectMetadata: true, readContent: true, readDiff: true }
                : {}),
            },
          });
        }
      }
    }

    if (needsSave && map.size > 0) {
      const arr = Array.from(map.values());
      atomicWriteSecureFile(
        file,
        JSON.stringify({ version: PAIRED_DEVICES_SCHEMA_VERSION, devices: arr }, null, 2) + "\n",
      );
    }
  } catch {}

  return map;
}

export function savePairedDevice(device: PairedDevice, customOmpDir?: string): void {
  const baseDir = customOmpDir || getOmpDir();
  const file = path.join(baseDir, "paired-devices.json");
  const devices = loadPairedDevices(customOmpDir);
  const canonicalFp = normalizeFingerprint(device.fingerprint);
  devices.set(canonicalFp, {
    ...device,
    fingerprint: canonicalFp,
  });

  const arr = Array.from(devices.values());
  atomicWriteSecureFile(
    file,
    JSON.stringify({ version: PAIRED_DEVICES_SCHEMA_VERSION, devices: arr }, null, 2) + "\n",
  );
}

export function removePairedDevice(fingerprintOrPrincipal: string, customOmpDir?: string): boolean {
  const baseDir = customOmpDir || getOmpDir();
  const file = path.join(baseDir, "paired-devices.json");
  const devices = loadPairedDevices(customOmpDir);

  let targetFp: string | null = null;
  for (const [fp, dev] of devices) {
    if (dev.principalId === fingerprintOrPrincipal) {
      targetFp = fp;
      break;
    }
    if (dev.deviceName === fingerprintOrPrincipal) {
      targetFp = fp;
      break;
    }
    try {
      if (normalizeFingerprint(fingerprintOrPrincipal) === fp) {
        targetFp = fp;
        break;
      }
    } catch {}
    if (fp.startsWith(fingerprintOrPrincipal.toUpperCase())) {
      targetFp = fp;
      break;
    }
  }

  if (!targetFp || !devices.has(targetFp)) {
    return false;
  }

  devices.delete(targetFp);
  const arr = Array.from(devices.values());
  atomicWriteSecureFile(
    file,
    JSON.stringify({ version: PAIRED_DEVICES_SCHEMA_VERSION, devices: arr }, null, 2) + "\n",
  );
  return true;
}

export function getPairedDevice(fingerprintOrPrincipal: string, customOmpDir?: string): PairedDevice | undefined {
  const devices = loadPairedDevices(customOmpDir);
  for (const [fp, dev] of devices) {
    if (dev.principalId === fingerprintOrPrincipal) return dev;
    if (dev.deviceName === fingerprintOrPrincipal) return dev;
    try {
      if (normalizeFingerprint(fingerprintOrPrincipal) === fp) return dev;
    } catch {}
    if (fp.startsWith(fingerprintOrPrincipal.toUpperCase())) return dev;
  }
  return undefined;
}

export function encodeSasWords(hash: Buffer): string {
  const w1 = SAS_WORD_LIST[hash[0]];
  const w2 = SAS_WORD_LIST[hash[1]];
  const w3 = SAS_WORD_LIST[hash[2]];
  const w4 = SAS_WORD_LIST[hash[3]];
  return `${w1}-${w2}-${w3}-${w4}`;
}

export function deriveLocalSas(
  socket: any,
  hubSpki: Buffer,
  clientSpki: Buffer,
  hubNonce: Buffer,
  clientNonce: Buffer,
): string {
  const context = crypto
    .createHash("sha256")
    .update("omp-link/pairing/v5\0")
    .update(hubSpki)
    .update(clientSpki)
    .update(hubNonce)
    .update(clientNonce)
    .digest();

  let key: Buffer;
  if (socket && typeof socket.exportKeyingMaterial === "function") {
    key = socket.exportKeyingMaterial(
      32,
      "EXPORTER-omp-link-pairing-v5",
      context,
    );
  } else {
    key = crypto.createHmac("sha256", "omp-link-pairing-offline-fallback").update(context).digest();
  }

  const value = crypto
    .createHmac("sha256", key)
    .update(context)
    .digest();

  return encodeSasWords(value);
}

export function derivePairingSas(
  hubCertOrSpki: Buffer,
  clientCertOrSpki: Buffer,
  hubNonce: string,
  clientNonce: string,
): string {
  let hubSpki = hubCertOrSpki;
  let clientSpki = clientCertOrSpki;
  try {
    hubSpki = canonicalSpkiDer(hubCertOrSpki);
  } catch {}
  try {
    clientSpki = canonicalSpkiDer(clientCertOrSpki);
  } catch {}

  const hash = crypto
    .createHash("sha256")
    .update(Buffer.from("omp-link/pairing/v5\0"))
    .update(hubSpki)
    .update(clientSpki)
    .update(Buffer.from(hubNonce, "utf8"))
    .update(Buffer.from(clientNonce, "utf8"))
    .digest();

  return encodeSasWords(hash);
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
