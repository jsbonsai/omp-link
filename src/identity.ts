import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";

export interface DevicePermissions {
  observe: boolean;
  message: boolean;
  compact: boolean;
  inspect: boolean;
  fileInbox: boolean;
  execRequest: boolean;
}

export const DEFAULT_PERMISSIONS: DevicePermissions = {
  observe: true,
  message: true,
  compact: false,
  inspect: false,
  fileInbox: false,
  execRequest: false,
};

export const FULL_PERMISSIONS: DevicePermissions = {
  observe: true,
  message: true,
  compact: true,
  inspect: true,
  fileInbox: true,
  execRequest: true,
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
  expiresAt: number;
  protocolVersion: number;
  used: boolean;
}

const WORD_LIST = [
  "AMBER", "BERYL", "COBALT", "DELTA", "ECHO", "FERN", "GARNET",
  "HAZEL", "INDIGO", "JADE", "KAPPA", "LUNAR", "METEOR", "NOVA",
  "ONYX", "PRISM", "QUARTZ", "RIVER", "SOLAR", "TOPAZ", "URBAN",
  "VALLEY", "WILLOW", "XENON", "YARROW", "ZENITH",
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
      const cert = new crypto.X509Certificate(certPem);
      const certDer = cert.raw;
      const spkiDer = cert.publicKey.export({ format: "der", type: "spki" }) as Buffer;
      const fingerprint = fingerprintDer(certDer);
      const keyType = cert.publicKey.asymmetricKeyType || "unknown";
      const principalId = `${keyType}-sha256:${fingerprint}`;

      if (fs.existsSync(metaPath)) {
        try {
          const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
          if (meta.deviceName) deviceName = meta.deviceName;
        } catch {}
      }

      return {
        certPem,
        keyPem,
        certDer,
        spkiDer,
        fingerprint,
        principalId,
        deviceName,
        keyType,
      };
    } catch {}
  }

  const { keyType } = generateDeviceCertificate(keyPath, certPath);
  const certPem = fs.readFileSync(certPath, "utf8");
  const keyPem = fs.readFileSync(keyPath, "utf8");
  const cert = new crypto.X509Certificate(certPem);
  const certDer = cert.raw;
  const spkiDer = cert.publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const fingerprint = fingerprintDer(certDer);
  const principalId = `${keyType}-sha256:${fingerprint}`;

  atomicWriteSecureFile(
    metaPath,
    JSON.stringify({ deviceName, createdAt: Date.now(), principalId, fingerprint }, null, 2),
  );

  return {
    certPem,
    keyPem,
    certDer,
    spkiDer,
    fingerprint,
    principalId,
    deviceName,
    keyType,
  };
}

export function loadPairedDevices(customOmpDir?: string): Map<string, PairedDevice> {
  const baseDir = customOmpDir || getOmpDir();
  const file = path.join(baseDir, "paired-devices.json");
  const map = new Map<string, PairedDevice>();
  if (!fs.existsSync(file)) return map;

  try {
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    const items = Array.isArray(data) ? data : Object.values(data);
    for (const item of items) {
      if (item && item.fingerprint && item.certPem) {
        const canonicalFp = normalizeFingerprint(item.fingerprint);
        map.set(canonicalFp, {
          ...item,
          fingerprint: canonicalFp,
          permissions: {
            ...DEFAULT_PERMISSIONS,
            ...(item.permissions || {}),
          },
        });
      }
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
  atomicWriteSecureFile(file, JSON.stringify(arr, null, 2) + "\n");
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
  atomicWriteSecureFile(file, JSON.stringify(arr, null, 2) + "\n");
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

export function derivePairingSas(
  hubCertDer: Buffer,
  clientCertDer: Buffer,
  hubNonce: string,
  clientNonce: string,
): string {
  const hash = crypto
    .createHash("sha256")
    .update(Buffer.from("omp-link/pairing/v5"))
    .update(hubCertDer)
    .update(clientCertDer)
    .update(Buffer.from(hubNonce, "utf8"))
    .update(Buffer.from(clientNonce, "utf8"))
    .digest();

  const w1 = WORD_LIST[hash[0] % WORD_LIST.length];
  const d1 = (hash[1] % 9) + 1;
  const w2 = WORD_LIST[hash[2] % WORD_LIST.length];
  const d2 = (hash[3] % 9) + 1;

  return `${w1}-${d1}-${w2}-${d2}`;
}

const activeInvites = new Map<string, PairingInvite>();

export function createInvite(
  hubIdentity: DeviceIdentity,
  options: { expiresInMs?: number; endpoint?: string } = {},
): PairingInvite {
  const expiresInMs = options.expiresInMs || 300_000;
  const secret = crypto.randomBytes(32).toString("hex");
  const inviteCode = `omp-${crypto.randomBytes(4).toString("hex")}-${secret.slice(0, 8)}`;
  const invite: PairingInvite = {
    inviteCode,
    secret,
    hubEndpoint: options.endpoint,
    hubFingerprint: hubIdentity.fingerprint,
    expiresAt: Date.now() + expiresInMs,
    protocolVersion: 5,
    used: false,
  };
  activeInvites.set(secret, invite);
  return invite;
}

export function verifyAndConsumeInvite(secret: string): { valid: boolean; reason?: string } {
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
  return { valid: true };
}

export function clearActiveInvites(): void {
  activeInvites.clear();
}
