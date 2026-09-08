import * as crypto from "node:crypto";
import type { TLSSocket } from "node:tls";
import type { ServerOptions as HttpsServerOptions } from "node:https";
import type { ClientOptions as WsClientOptions } from "ws";
import {
  type DeviceIdentity,
  fingerprintDer,
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
    allowUnpaired?: boolean;
  } = {},
): WsClientOptions {
  return {
    key: identity.keyPem,
    cert: identity.certPem,
    minVersion: "TLSv1.3",
    rejectUnauthorized: false,
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

      const serverFp = fingerprintDer(rawDer);

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
        return true;
      }

      if (!options.allowUnpaired) {
        throw new Error(
          `Unpinned hub certificate rejected (${serverFp}). Initial pairing requires explicit trust confirmation.`,
        );
      }

      return true;
    },
  };
}

export function extractPeerCertificate(socket: any): PeerCertificateInfo | null {
  if (!socket) return null;
  const tlsSocket: TLSSocket = socket;

  if (typeof tlsSocket.getPeerX509Certificate === "function") {
    try {
      const x509 = tlsSocket.getPeerX509Certificate();
      if (x509) {
        const certDer = x509.raw;
        const certPem = x509.toString();
        const fingerprint = fingerprintDer(certDer);
        const spkiDer = x509.publicKey.export({ format: "der", type: "spki" }) as Buffer;
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
        const fingerprint = fingerprintDer(certDer);
        const spkiDer = x509.publicKey.export({ format: "der", type: "spki" }) as Buffer;
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
