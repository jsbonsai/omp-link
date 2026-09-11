import { test, describe, before, after } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";

import {
  DEFAULT_PERMISSIONS,
  DEVICE_PREFIX_MIN_HEX,
  generateDeviceCertificate,
  getOrCreateDeviceIdentity,
  getPairedDevice,
  identityFromCertificate,
  loadPairedDevices,
  normalizeFingerprint,
  removePairedDevice,
  removePairedDeviceResult,
  resolvePairedDevice,
  savePairedDevice,
  withPairedStoreLock,
} from "../../src/identity.js";
import { readAuditLogs, setCustomAuditLogPath } from "../../src/audit.js";

// Third-pass hardening of `src/identity.ts`: the failure modes that leave a stranger's machine
// wedged behind a raw OpenSSL error, unpair a device they did not name, or hand the device key
// to whoever owns the state directory.

const tempDirs = [];

function makeStateDir(label) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `omplink-${label}-`));
  tempDirs.push(dir);
  return dir;
}

function auditTypes() {
  return readAuditLogs(500).map((entry) => entry.type);
}

function auditEntries(type) {
  return readAuditLogs(500).filter((entry) => entry.type === type);
}

/** A pid that is certainly not running: a child that has already exited. */
function deadPid() {
  const done = spawnSync(process.execPath, ["-e", ""], { stdio: "ignore" });
  assert.ok(done.pid > 0, "could not spawn a throwaway child to harvest a dead pid");
  return done.pid;
}

function spkiOfKey(keyPem) {
  return crypto.createPublicKey(keyPem).export({ format: "der", type: "spki" });
}

describe("REGRESSION R40: a key/cert mismatch self-heals instead of wedging every future start", () => {
  let auditDir;

  before(() => {
    auditDir = makeStateDir("r40-audit");
    setCustomAuditLogPath(path.join(auditDir, "test-audit.log"));
  });

  after(() => {
    setCustomAuditLogPath(null);
    for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true });
  });

  test("a loaded pair is proven to match, not merely to exist", () => {
    const dir = makeStateDir("r40-ok");
    const first = getOrCreateDeviceIdentity(dir);
    const second = getOrCreateDeviceIdentity(dir);

    assert.strictEqual(second.principalId, first.principalId, "a valid identity must be stable");
    assert.ok(spkiOfKey(second.keyPem).equals(identityFromCertificate(second.certPem).spkiDer));
  });

  test("a mismatched pair is archived and regenerated, never surfaced as an OpenSSL error", () => {
    const victim = makeStateDir("r40-mismatch");
    const other = makeStateDir("r40-other");
    const original = getOrCreateDeviceIdentity(victim);
    const foreign = getOrCreateDeviceIdentity(other);
    assert.notStrictEqual(original.principalId, foreign.principalId);

    // Exactly what a steal-then-late-rename leaves behind: the loser's key, the winner's cert.
    const keyPath = path.join(victim, "identity", "device-key.pem");
    const certPath = path.join(victim, "identity", "device-cert.pem");
    fs.writeFileSync(keyPath, foreign.keyPem, { mode: 0o600 });

    // The scenario is real: this pair is what reaches the operator today.
    assert.throws(
      () => tls.createSecureContext({ key: foreign.keyPem, cert: original.certPem }),
      /key values mismatch|KEY_VALUES_MISMATCH/i,
      "fixture is not actually a mismatched pair",
    );

    const healed = getOrCreateDeviceIdentity(victim);

    assert.ok(
      spkiOfKey(healed.keyPem).equals(identityFromCertificate(healed.certPem).spkiDer),
      "the regenerated pair must match",
    );
    assert.doesNotThrow(() => tls.createSecureContext({ key: healed.keyPem, cert: healed.certPem }));
    assert.notStrictEqual(healed.principalId, original.principalId, "a fresh identity, not the broken one");
    assert.notStrictEqual(healed.principalId, foreign.principalId, "and not the planted key's identity");

    const archives = fs.readdirSync(path.join(victim, "identity")).filter((name) => name.startsWith("broken-"));
    assert.strictEqual(archives.length, 1, "the unusable pair is kept as evidence");
    const archived = fs.readdirSync(path.join(victim, "identity", archives[0])).sort();
    assert.ok(archived.includes("device-key.pem") && archived.includes("device-cert.pem"));
    assert.strictEqual(
      fs.readFileSync(path.join(victim, "identity", archives[0], "device-cert.pem"), "utf8"),
      original.certPem,
    );

    const archivedEvents = auditEntries("identity_pair_archived");
    assert.ok(archivedEvents.length >= 1, "the self-heal is a security decision and must be audited");
    assert.match(archivedEvents.at(-1).reason, /does not match/);

    // Still healed on the next start, with no second archive.
    const again = getOrCreateDeviceIdentity(victim);
    assert.strictEqual(again.principalId, healed.principalId);
    assert.strictEqual(
      fs.readdirSync(path.join(victim, "identity")).filter((name) => name.startsWith("broken-")).length,
      1,
    );

    // The live key/cert files themselves must be intact, not the archived ones.
    assert.strictEqual(fs.readFileSync(certPath, "utf8"), healed.certPem);
    assert.strictEqual(fs.readFileSync(keyPath, "utf8"), healed.keyPem);
  });

  test("an unparseable certificate heals the same way rather than throwing at the caller", () => {
    const dir = makeStateDir("r40-garbage");
    const created = getOrCreateDeviceIdentity(dir);
    fs.writeFileSync(path.join(dir, "identity", "device-cert.pem"), "not a certificate\n", { mode: 0o600 });

    const healed = getOrCreateDeviceIdentity(dir);
    assert.notStrictEqual(healed.principalId, created.principalId);
    assert.ok(spkiOfKey(healed.keyPem).equals(identityFromCertificate(healed.certPem).spkiDer));
  });
});

describe("REGRESSION R41: an identity claim is only stolen from a process proven dead", () => {
  let auditDir;
  let donorKeyPem;

  before(() => {
    auditDir = makeStateDir("r41-audit");
    setCustomAuditLogPath(path.join(auditDir, "test-audit.log"));
    donorKeyPem = getOrCreateDeviceIdentity(makeStateDir("r41-donor")).keyPem;
  });

  after(() => {
    setCustomAuditLogPath(null);
    for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true });
  });

  /** A claimed key with no certificate yet: the winner is mid-generation. */
  function stageUnpublishedClaim(label, claim) {
    const dir = makeStateDir(label);
    const identityDir = path.join(dir, "identity");
    fs.mkdirSync(identityDir, { recursive: true, mode: 0o700 });
    const keyPath = path.join(identityDir, "device-key.pem");
    fs.writeFileSync(keyPath, donorKeyPem, { mode: 0o600 });
    if (claim) {
      fs.writeFileSync(path.join(identityDir, "device-key.claim.json"), JSON.stringify(claim), { mode: 0o600 });
    }
    return { keyPath, certPath: path.join(identityDir, "device-cert.pem") };
  }

  test("a live claimant's key survives: slow is not dead", () => {
    const { keyPath, certPath } = stageUnpublishedClaim("r41-live", {
      pid: process.pid,
      host: os.hostname(),
      at: Date.now(),
    });

    assert.throws(
      () => generateDeviceCertificate(keyPath, certPath),
      /holds the device identity claim/,
      "stealing on a timeout is what produces the mismatched pair",
    );
    assert.strictEqual(fs.readFileSync(keyPath, "utf8"), donorKeyPem, "the live claimant's key must be untouched");
    assert.strictEqual(fs.existsSync(certPath), false);
  });

  test("a fresh claim recorded on another host is not stolen: local pids say nothing about it", () => {
    const { keyPath, certPath } = stageUnpublishedClaim("r41-remote", {
      pid: process.pid,
      host: `${os.hostname()}-over-there`,
      at: Date.now(),
    });

    assert.throws(() => generateDeviceCertificate(keyPath, certPath), /holds the device identity claim/);
    assert.strictEqual(fs.readFileSync(keyPath, "utf8"), donorKeyPem);
  });

  test("a long-stale claim from another host is reclaimed", () => {
    const { keyPath, certPath } = stageUnpublishedClaim("r41-remote-stale", {
      pid: process.pid,
      host: `${os.hostname()}-over-there`,
      at: Date.now() - 10 * 60_000,
    });

    assert.strictEqual(generateDeviceCertificate(keyPath, certPath).created, true);
    assert.notStrictEqual(fs.readFileSync(keyPath, "utf8"), donorKeyPem);
  });

  // The other half of the rule, and the one C9 in concurrency.test.mjs depends on: the claim
  // record is written before the certificate, so a live claimant on this build always has one
  // by the time a loser has waited a full claim window. Its absence is therefore conclusive —
  // a crash inside the two-step window — and must not wedge the directory for ever.
  test("a claim with no owner record at all is reclaimed rather than wedging the directory", () => {
    const { keyPath, certPath } = stageUnpublishedClaim("r41-orphan", null);

    assert.strictEqual(generateDeviceCertificate(keyPath, certPath).created, true);
    assert.ok(spkiOfKey(fs.readFileSync(keyPath, "utf8")).equals(
      identityFromCertificate(fs.readFileSync(certPath, "utf8")).spkiDer,
    ));
  });

  test("a dead claimant's key is reclaimed, so a crash does not wedge the directory", () => {
    const { keyPath, certPath } = stageUnpublishedClaim("r41-dead", {
      pid: deadPid(),
      host: os.hostname(),
      at: Date.now(),
    });

    const result = generateDeviceCertificate(keyPath, certPath);
    assert.strictEqual(result.created, true);
    assert.ok(fs.existsSync(certPath));
    assert.notStrictEqual(fs.readFileSync(keyPath, "utf8"), donorKeyPem, "the dead claim was replaced");
    assert.ok(spkiOfKey(fs.readFileSync(keyPath, "utf8")).equals(
      identityFromCertificate(fs.readFileSync(certPath, "utf8")).spkiDer,
    ), "a reclaim must still leave a matching pair");
    assert.ok(auditTypes().includes("identity_claim_reclaimed"));
  });

  test("the winner records itself, so a later starter can see who holds the claim", () => {
    const dir = makeStateDir("r41-winner");
    getOrCreateDeviceIdentity(dir);
    const claim = JSON.parse(fs.readFileSync(path.join(dir, "identity", "device-key.claim.json"), "utf8"));
    assert.strictEqual(claim.pid, process.pid);
    assert.strictEqual(claim.host, os.hostname());
  });
});

describe("REGRESSION R42: an ambiguous device argument refuses instead of unpairing a guess", () => {
  let dir;
  const sharedPrefix = "AABBCCDD";
  let twinA;
  let twinB;
  let solo;

  function seedDevice(fingerprintHex, deviceName) {
    const fingerprint = normalizeFingerprint(fingerprintHex);
    const device = {
      principalId: `ed25519-sha256:${fingerprint}`,
      fingerprint,
      certPem: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n",
      deviceName,
      permissions: { ...DEFAULT_PERMISSIONS },
      pairedAt: Date.now(),
    };
    savePairedDevice(device, dir);
    return device;
  }

  before(() => {
    dir = makeStateDir("r42");
    setCustomAuditLogPath(path.join(dir, "test-audit.log"));
    twinA = seedDevice(sharedPrefix + crypto.randomBytes(28).toString("hex"), "twin");
    twinB = seedDevice(sharedPrefix + crypto.randomBytes(28).toString("hex"), "twin");
    solo = seedDevice("FEDCBA98" + crypto.randomBytes(28).toString("hex"), "solo");
    assert.strictEqual(loadPairedDevices(dir).size, 3);
  });

  after(() => {
    setCustomAuditLogPath(null);
    for (const d of tempDirs) fs.rmSync(d, { recursive: true, force: true });
  });

  test("a duplicated device name resolves to nothing and removes nothing", () => {
    const lookup = resolvePairedDevice("twin", dir);
    assert.strictEqual(lookup.reason, "ambiguous");
    assert.strictEqual(lookup.matches.length, 2);
    assert.strictEqual(lookup.device, undefined);
    assert.strictEqual(getPairedDevice("twin", dir), undefined);

    const removal = removePairedDeviceResult("twin", dir);
    assert.strictEqual(removal.removed, false);
    assert.strictEqual(removal.reason, "ambiguous");
    assert.strictEqual(removePairedDevice("twin", dir), false, "the boolean form must refuse too");
    assert.strictEqual(loadPairedDevices(dir).size, 3, "a refusal removes nothing");

    const refusals = auditEntries("device_removal_refused");
    assert.ok(refusals.some((entry) => entry.reason === "ambiguous" && entry.matched.length === 2));
  });

  test("a one-character fingerprint prefix is refused, not matched to an arbitrary device", () => {
    const short = removePairedDeviceResult("A", dir);
    assert.strictEqual(short.removed, false);
    assert.strictEqual(short.reason, "prefix-too-short");

    const stillShort = removePairedDeviceResult(sharedPrefix.slice(0, DEVICE_PREFIX_MIN_HEX - 1), dir);
    assert.strictEqual(stillShort.reason, "prefix-too-short");

    const ambiguousPrefix = removePairedDeviceResult(sharedPrefix, dir);
    assert.strictEqual(ambiguousPrefix.removed, false);
    assert.strictEqual(ambiguousPrefix.reason, "ambiguous");

    assert.strictEqual(removePairedDeviceResult("nosuchdevice", dir).reason, "not-found");
    assert.strictEqual(loadPairedDevices(dir).size, 3);
    assert.ok(auditEntries("device_removal_refused").some((entry) => entry.reason === "prefix-too-short"));
  });

  test("an exact principal id, a full fingerprint and a unique prefix each still work", () => {
    assert.strictEqual(removePairedDevice(twinA.principalId, dir), true);
    assert.strictEqual(loadPairedDevices(dir).size, 2);

    // With its twin gone the name is unique again.
    assert.strictEqual(getPairedDevice("twin", dir)?.principalId, twinB.principalId);

    const byFingerprint = removePairedDeviceResult(twinB.fingerprint, dir);
    assert.strictEqual(byFingerprint.removed, true);
    assert.strictEqual(byFingerprint.device.principalId, twinB.principalId);

    const uniquePrefix = solo.fingerprint.replace(/:/g, "").slice(0, DEVICE_PREFIX_MIN_HEX);
    assert.strictEqual(removePairedDevice(uniquePrefix, dir), true);
    assert.strictEqual(loadPairedDevices(dir).size, 0);
    assert.strictEqual(removePairedDevice(solo.principalId, dir), false, "already gone");
  });
});

describe("REGRESSION R43: the paired-store lock is owned, and the state dir must be ours", () => {
  let dir;

  before(() => {
    dir = makeStateDir("r43");
    setCustomAuditLogPath(path.join(dir, "test-audit.log"));
  });

  after(() => {
    setCustomAuditLogPath(null);
    for (const d of tempDirs) fs.rmSync(d, { recursive: true, force: true });
  });

  test("a holder releases only its own lock, never the one that replaced it", () => {
    const lockPath = path.join(dir, "paired-devices.lock");
    const thiefToken = `${process.pid}:thief-token`;
    let observed = null;

    withPairedStoreLock(dir, () => {
      observed = fs.readFileSync(lockPath, "utf8");
      // What a steal looks like from the victim's side: the file is now someone else's.
      fs.writeFileSync(lockPath, thiefToken);
    });

    assert.match(observed, /^\d+:[0-9a-f]{24}$/, "the lock must carry pid and a random token");
    assert.strictEqual(observed.split(":")[0], String(process.pid));
    assert.strictEqual(
      fs.readFileSync(lockPath, "utf8"),
      thiefToken,
      "a victim must not unlink the thief's lock and admit a third writer",
    );

    fs.unlinkSync(lockPath);
    withPairedStoreLock(dir, () => {});
    assert.strictEqual(fs.existsSync(lockPath), false, "an untouched lock is still released normally");
  });

  test("a live holder's lock is left alone and the unserialised write is audited", () => {
    const lockDir = makeStateDir("r43-live-lock");
    const lockPath = path.join(lockDir, "paired-devices.lock");
    const livingLock = `${process.pid}:someone-elses-token`;
    fs.writeFileSync(lockPath, livingLock, { mode: 0o600 });

    const fingerprint = normalizeFingerprint(crypto.randomBytes(32).toString("hex"));
    savePairedDevice(
      {
        principalId: `ed25519-sha256:${fingerprint}`,
        fingerprint,
        certPem: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n",
        deviceName: "blocked-writer",
        permissions: { ...DEFAULT_PERMISSIONS },
        pairedAt: Date.now(),
      },
      lockDir,
    );

    assert.strictEqual(fs.readFileSync(lockPath, "utf8"), livingLock, "a live pid's lock is not stealable");
    assert.strictEqual(loadPairedDevices(lockDir).size, 1, "losing the lock must not lose the device");
    const timeouts = auditEntries("paired_store_lock_timeout");
    assert.ok(timeouts.length >= 1, "doctor must be able to see that a write was not serialised");
    assert.strictEqual(timeouts.at(-1).holderPid, process.pid);
  });

  test("a dead holder's lock is broken, with the break audited", () => {
    const lockDir = makeStateDir("r43-dead-lock");
    const lockPath = path.join(lockDir, "paired-devices.lock");
    fs.writeFileSync(lockPath, `${deadPid()}:abandoned-token`, { mode: 0o600 });

    withPairedStoreLock(lockDir, () => {
      assert.match(fs.readFileSync(lockPath, "utf8"), new RegExp(`^${process.pid}:`), "we took it over");
    });

    assert.strictEqual(fs.existsSync(lockPath), false);
    assert.ok(auditEntries("paired_store_lock_broken").some((entry) => entry.lockPath === lockPath));
  });

  test("an over-permissive identity directory is tightened to 0700", () => {
    const loose = makeStateDir("r43-loose");
    const identityDir = path.join(loose, "identity");
    fs.mkdirSync(identityDir, { recursive: true });
    fs.chmodSync(identityDir, 0o755);

    getOrCreateDeviceIdentity(loose);

    assert.strictEqual(fs.statSync(identityDir).mode & 0o777, 0o700);
    assert.ok(auditEntries("identity_dir_permissions_tightened").some((entry) => entry.path === identityDir));
  });

  test("an identity directory owned by another user is refused, with nothing written into it", (t) => {
    if (typeof process.getuid !== "function") {
      t.skip("no uid model on this platform");
      return;
    }
    // A world-writable directory owned by root is the shape of the attack: a shared OMP_DIR
    // another local user can pre-plant a key in.
    const shared = "/tmp";
    let sharedStat;
    try {
      sharedStat = fs.statSync(shared);
    } catch {
      t.skip("no shared directory available to borrow");
      return;
    }
    if (sharedStat.uid === process.getuid()) {
      t.skip(`${shared} is owned by this user; cannot stage a foreign-owned state dir`);
      return;
    }

    const host = makeStateDir("r43-foreign");
    fs.symlinkSync(shared, path.join(host, "identity"));

    assert.throws(
      () => getOrCreateDeviceIdentity(host),
      (err) => /owned by uid/.test(err.message) && /OMP_DIR/.test(err.message),
      "a state directory owned by another user must never become this device's identity",
    );
    assert.strictEqual(fs.existsSync(path.join(shared, "device-key.pem")), false, "nothing was written");
    assert.ok(auditEntries("identity_dir_foreign_owner").some((entry) => entry.ownerUid === sharedStat.uid));
  });
});
