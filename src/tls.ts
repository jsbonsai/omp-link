import * as crypto from "node:crypto";
import type { TLSSocket } from "node:tls";
import type { ServerOptions as HttpsServerOptions } from "node:https";
import type { ClientOptions as WsClientOptions } from "ws";
import {
  type DeviceIdentity,
  fingerprintDer,
  fingerprintPublicKey,
  normalizeFingerprint,
  canonicalSpkiDer,
} from "./identity.js";

export interface PeerCertificateInfo {
  certDer: Buffer;
  certPem: string;
  fingerprint: string;
  spkiDer: Buffer;
  principalId: string;
  keyType: string;
}

export function getServerTlsOptions(identity: DeviceIdentity): HttpsServerOptions {
  return {
    key: identity.keyPem,
    cert: identity.certPem,
    minVersion: "TLSv1.3",
    requestCert: true,
    rejectUnauthorized: false,
  };
}

export function getClientTlsOptions(
  identity: DeviceIdentity,
  options: {
    pinnedFingerprint?: string;
    caCertPem?: string;
    allowUnpaired?: boolean;
    onServerCertificate?: (certInfo: PeerCertificateInfo) => void;
  } = {},
): WsClientOptions {
  const isPairedPinned = Boolean(options.pinnedFingerprint && options.caCertPem && !options.allowUnpaired);
  const opts: WsClientOptions = {
    key: identity.keyPem,
    cert: identity.certPem,
    minVersion: "TLSv1.3",
    rejectUnauthorized: isPairedPinned,
    checkServerIdentity: (_host: string, cert: any) => {
      let rawDer: Buffer | null = null;
      if (cert.raw && Buffer.isBuffer(cert.raw)) {
        rawDer = cert.raw;
      } else if (cert.raw) {
        rawDer = Buffer.from(cert.raw);
      }

      if (!rawDer) {
        throw new Error("No server certificate presented during TLS handshake");
      }

      const spkiDer = canonicalSpkiDer(rawDer);
      const serverFp = fingerprintPublicKey(spkiDer);
      const x509 = new crypto.X509Certificate(rawDer);
      const certPem = x509.toString();
      const keyType = x509.publicKey.asymmetricKeyType || "unknown";
      const principalId = `${keyType}-sha256:${serverFp}`;

      const certInfo: PeerCertificateInfo = {
        certDer: rawDer,
        certPem,
        fingerprint: serverFp,
        spkiDer,
        principalId,
        keyType,
      };

      if (options.onServerCertificate) {
        options.onServerCertificate(certInfo);
      }

      if (options.pinnedFingerprint) {
        const canonicalPinned = normalizeFingerprint(options.pinnedFingerprint);
        const serverBuf = Buffer.from(serverFp, "utf8");
        const pinnedBuf = Buffer.from(canonicalPinned, "utf8");
        if (
          serverBuf.length !== pinnedBuf.length ||
          !crypto.timingSafeEqual(serverBuf, pinnedBuf)
        ) {
          throw new Error(
            `Server certificate pinning mismatch! Expected ${canonicalPinned}, received ${serverFp}`,
          );
        }
        return undefined as any;
      }

      if (!options.allowUnpaired) {
        throw new Error(
          `Unpinned hub certificate rejected (${serverFp}). Initial pairing requires explicit trust confirmation.`,
        );
      }

      return undefined as any;
    },
  };

  if (options.caCertPem) {
    (opts as any).ca = [options.caCertPem];
  }

  return opts;
}

export function extractPeerCertificate(socket: any): PeerCertificateInfo | null {
  if (!socket) return null;
  if (socket._peerCertInfo) return socket._peerCertInfo;
  const tlsSocket: TLSSocket = socket;

  if (typeof tlsSocket.getPeerX509Certificate === "function") {
    try {
      const x509 = tlsSocket.getPeerX509Certificate();
      if (x509) {
        const certDer = x509.raw;
        const certPem = x509.toString();
        const spkiDer = x509.publicKey.export({ format: "der", type: "spki" }) as Buffer;
        const fingerprint = fingerprintPublicKey(spkiDer);
        const keyType = x509.publicKey.asymmetricKeyType || "unknown";
        const principalId = `${keyType}-sha256:${fingerprint}`;
        return {
          certDer,
          certPem,
          fingerprint,
          spkiDer,
          principalId,
          keyType,
        };
      }
    } catch {}
  }

  if (typeof tlsSocket.getPeerCertificate === "function") {
    try {
      const cert = tlsSocket.getPeerCertificate(true);
      if (cert && cert.raw) {
        const certDer = Buffer.isBuffer(cert.raw) ? cert.raw : Buffer.from(cert.raw);
        const x509 = new crypto.X509Certificate(certDer);
        const certPem = x509.toString();
        const spkiDer = x509.publicKey.export({ format: "der", type: "spki" }) as Buffer;
        const fingerprint = fingerprintPublicKey(spkiDer);
        const keyType = x509.publicKey.asymmetricKeyType || "unknown";
        const principalId = `${keyType}-sha256:${fingerprint}`;
        return {
          certDer,
          certPem,
          fingerprint,
          spkiDer,
          principalId,
          keyType,
        };
      }
    } catch {}
  }

  return null;
}

export function verifyPeerSpki(socket: any, expected: string): PeerCertificateInfo {
  const peer = extractPeerCertificate(socket);
  if (!peer) {
    throw new Error("Peer did not present a certificate");
  }

  const actual = fingerprintPublicKey(peer.spkiDer);
  const actualBytes = Buffer.from(normalizeFingerprint(actual));
  const expectedBytes = Buffer.from(normalizeFingerprint(expected));

  if (
    actualBytes.length !== expectedBytes.length ||
    !crypto.timingSafeEqual(actualBytes, expectedBytes)
  ) {
    throw new Error(`SPKI mismatch: expected ${expected}, received ${actual}`);
  }

  return { ...peer, fingerprint: actual };
}
