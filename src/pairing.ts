import * as crypto from "node:crypto";
import {
  type DevicePermissions,
  type PairedDevice,
  DEFAULT_PERMISSIONS,
  savePairedDevice,
  derivePairingSas,
  deriveLocalSas,
  normalizeFingerprint,
} from "./identity.js";
import { type PeerCertificateInfo } from "./tls.js";

export const MAX_GLOBAL_PENDING_REQUESTS = 16;
export const PAIRING_EXPIRY_MS = 60_000;

export interface PendingPairRequest {
  id: number;
  socket: any; // WebSocket
  fingerprint: string;
  principalId: string;
  certPem: string;
  displayName: string;
  clientNonce: string;
  hubNonce: string;
  sasCode: string;
  host: string;
  createdAt: number;
  expiresAt: number;
  timer: NodeJS.Timeout;
}

export class PairingManager {
  private pendingRequests = new Map<number, PendingPairRequest>();
  private nextRequestId = 1;
  private customOmpDir?: string;

  constructor(customOmpDir?: string) {
    this.customOmpDir = customOmpDir;
  }

  public createRequest(params: {
    socket: any;
    peerCert: PeerCertificateInfo;
    hubSpkiDer: Buffer;
    displayName: string;
    clientNonce: string;
    host?: string;
    onExpire?: (req: PendingPairRequest) => void;
  }): { ok: true; request: PendingPairRequest } | { ok: false; error: string } {
    if (this.pendingRequests.size >= MAX_GLOBAL_PENDING_REQUESTS) {
      return { ok: false, error: "Pairing queue full: maximum 16 pending requests reached" };
    }

    const canonicalFp = normalizeFingerprint(params.peerCert.fingerprint);

    // Limit 1 per socket
    for (const [_, req] of this.pendingRequests) {
      if (req.socket === params.socket) {
        return { ok: false, error: "A pairing request is already pending on this connection" };
      }
      if (req.fingerprint === canonicalFp) {
        return { ok: false, error: "A pairing request is already pending for this certificate" };
      }
    }

    const hubNonce = crypto.randomBytes(32).toString("hex");
    const sasCode = deriveLocalSas(
      params.socket,
      params.hubSpkiDer,
      params.peerCert.spkiDer,
      Buffer.from(hubNonce, "hex"),
      Buffer.from(params.clientNonce, "hex"),
    );

    const id = this.nextRequestId++;
    const expiresAt = Date.now() + PAIRING_EXPIRY_MS;

    const req: PendingPairRequest = {
      id,
      socket: params.socket,
      fingerprint: canonicalFp,
      principalId: params.peerCert.principalId,
      certPem: params.peerCert.certPem,
      displayName: params.displayName,
      clientNonce: params.clientNonce,
      hubNonce,
      sasCode,
      host: params.host || "unknown",
      createdAt: Date.now(),
      expiresAt,
      timer: setTimeout(() => {
        this.pendingRequests.delete(id);
        if (params.onExpire) params.onExpire(req);
      }, PAIRING_EXPIRY_MS),
    };

    this.pendingRequests.set(id, req);
    return { ok: true, request: req };
  }

  public getRequest(id: number): PendingPairRequest | undefined {
    return this.pendingRequests.get(id);
  }

  public getAllRequests(): PendingPairRequest[] {
    return Array.from(this.pendingRequests.values());
  }

  public approveRequest(
    id: number,
    permissions: DevicePermissions = DEFAULT_PERMISSIONS,
    code?: string,
  ): PairedDevice | null {
    const req = this.pendingRequests.get(id);
    if (!req) return null;

    if (code) {
      const cleanExpected = req.sasCode.replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
      const cleanGiven = code.replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
      const expBuf = Buffer.from(cleanExpected, "utf8");
      const givBuf = Buffer.from(cleanGiven, "utf8");
      if (expBuf.length !== givBuf.length || !crypto.timingSafeEqual(expBuf, givBuf)) {
        return null;
      }
    }

    clearTimeout(req.timer);
    this.pendingRequests.delete(id);

    const pairedDevice: PairedDevice = {
      principalId: req.principalId,
      fingerprint: req.fingerprint,
      certPem: req.certPem,
      deviceName: req.displayName,
      permissions,
      pairedAt: Date.now(),
      lastSeen: Date.now(),
      lastAddress: req.host,
    };

    savePairedDevice(pairedDevice, this.customOmpDir);
    return pairedDevice;
  }

  public denyRequest(id: number): boolean {
    const req = this.pendingRequests.get(id);
    if (!req) return false;

    clearTimeout(req.timer);
    this.pendingRequests.delete(id);
    return true;
  }

  public cleanupSocket(socket: any): void {
    for (const [id, req] of this.pendingRequests) {
      if (req.socket === socket) {
        clearTimeout(req.timer);
        this.pendingRequests.delete(id);
      }
    }
  }

  public clearAll(): void {
    for (const [_, req] of this.pendingRequests) {
      clearTimeout(req.timer);
    }
    this.pendingRequests.clear();
  }
}
