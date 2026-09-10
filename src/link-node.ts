import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { WebSocketServer, WebSocket } from "ws";
import { exec } from "node:child_process";

import {
  type DeviceIdentity,
  type PairedDevice,
  type DevicePermissions,
  DEFAULT_PERMISSIONS,
  NO_PERMISSIONS,
  FULL_PERMISSIONS,
  getOrCreateDeviceIdentity,
  loadPairedDevices,
  savePairedDevice,
  removePairedDevice,
  getPairedDevice,
  normalizeFingerprint,
  verifyAndConsumeInvite,
  derivePairingSas,
  deriveLocalSas,
  getOmpDir,
} from "./identity.js";

import {
  PROTOCOL_VERSION,
  type WireMessage,
  type ApplicationMessage,
  type ClientHelloMsg,
  type ServerHelloMsg,
  type PairRequestMsg,
  type PairResponseMsg,
  type PairVerifyMsg,
  type ChatMsg,
  type DirectMsg,
  type StatusUpdateMsg,
  type CompactRequestMsg,
  type CompactResponseMsg,
  type FileOfferMsg,
  type FileChunkMsg,
  type FileAckMsg,
  type RpcRequestMsg,
  type RpcResponseMsg,
  parseWireMessage,
  HANDSHAKE_MESSAGE_TYPES,
  APPLICATION_MESSAGE_TYPES,
} from "./protocol-schema.js";

import {
  getServerTlsOptions,
  getClientTlsOptions,
  extractPeerCertificate,
  verifyPeerSpki,
  type PeerCertificateInfo,
} from "./tls.js";

import {
  type ConnectionContext,
  createConnectionContext,
  validateMessagePhase,
  checkMessageDeduplication,
  setConnectionPhase,
  cleanupConnectionContext,
} from "./connection-state.js";

import {
  isActionPermitted,
  bindMessageOrigin,
  createExecGrant,
  checkAndConsumeExecGrant,
  revokeGrantsForPrincipal,
  revokeAllGrants,
  getActiveGrants,
  updateDevicePermissions,
  MUTATION_GUARD_ADVISORY,
} from "./authorization.js";

import {
  safeGitStatus,
  safeGitDiff,
  safeGitLog,
  safeGitGrep,
  safeReadFile,
  safeListDir,
  getRegisteredWorkspace,
  registerWorkspace,
  validateOutboundFile,
} from "./inspection.js";

import { TransferReceiver } from "./transfer-receiver.js";
import { computeFileHashStreaming, streamFileChunks } from "./transfer-sender.js";
import { appendAuditLog } from "./audit.js";
import { startUdpDiscoveryResponder, getNetworkInfo, DEFAULT_PORT } from "./discovery.js";

export interface LinkNodeOptions {
  customOmpDir?: string;
  port?: number;
  bindHost?: string;
  networkMode?: "lan" | "tailscale" | "loopback";
  terminalName?: string;
  sessionId?: string;
  allowRemoteExec?: boolean;
  workspaceRoot?: string;
}

export type NodeRole = "hub" | "client" | "disconnected";

export class LinkNode {
  public identity: DeviceIdentity;
  public role: NodeRole = "disconnected";

  public get isAuthenticated(): boolean {
    if (this.role === "hub") return true;
    return this.clientContext?.phase === "authenticated";
  }

  public async waitForAuthenticated(timeoutMs = 10_000): Promise<boolean> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (this.isAuthenticated) return true;
      await new Promise((r) => setTimeout(r, 50));
    }
    return this.isAuthenticated;
  }
  public currentSessionId: string;
  public terminalName: string;
  public port: number;
  public bindHost: string;
  public networkMode: "lan" | "tailscale" | "loopback";
  public customOmpDir?: string;
  public allowRemoteExec: boolean;
  public workspaceRoot: string;

  // Rate limiting maps: IP -> timestamp[]
  private connectionRateMap = new Map<string, number[]>();
  private pairingRateMap = new Map<string, number[]>();

  // Hub components
  private httpsServer: HttpsServer | null = null;
  private wss: WebSocketServer | null = null;
  private udpSocket: any = null;
  private hubConnections = new Map<any, ConnectionContext>(); // socket -> context
  private terminalContexts = new Map<string, any>(); // terminalName -> context snapshot
  private terminalStatuses = new Map<string, any>(); // terminalName -> status
  private nextPairingReqId = 1;
  private pendingPairRequests = new Map<number, {
    id: number;
    socket: any;
    peerCert: PeerCertificateInfo;
    displayName: string;
    clientNonce: string;
    hubNonce: string;
    sasCode: string;
    host: string;
    createdAt: number;
    timer: NodeJS.Timeout;
  }>();

  // Concurrency tracking for RPCs
  private activeRpcsByPeer = new Map<string, number>();
  public static readonly MAX_CONCURRENT_RPCS = 3;

  // Client components
  private clientWs: WebSocket | null = null;
  private clientContext: ConnectionContext | null = null;
  private pinnedHubFingerprint: string | null = null;
  private capturedServerCert: PeerCertificateInfo | null = null;
  public lastClientNonce: string | null = null;
  public currentLocalSas: string | null = null;

  // File transfers
  public transferReceiver: TransferReceiver;
  private pendingRpcRequests = new Map<string, {
    expectedPrincipalId?: string;
    expectedAction?: string;
    resolve: (res: RpcResponseMsg) => void;
    reject: (err: Error) => void;
    timeout: NodeJS.Timeout;
  }>();
  private pendingCompactRequests = new Map<string, {
    expectedPrincipalId?: string;
    resolve: (res: CompactResponseMsg) => void;
    reject: (err: Error) => void;
    timeout: NodeJS.Timeout;
  }>();
  private pendingFileAcks = new Map<string, {
    expectedPrincipalId?: string;
    resolve: (ack: FileAckMsg) => void;
    reject: (err: Error) => void;
    timeout: NodeJS.Timeout;
  }>();

  // Event handlers
  public onMessage?: (msg: ApplicationMessage) => void;
  public onPeerStatusUpdate?: (peer: string, status: any, context?: any) => void;
  public onPairingRequested?: (req: { id: number; displayName: string; fingerprint: string; sasCode: string; host: string }) => void;
  public onPairingApproved?: (device: PairedDevice) => void;
  public onPairingDenied?: (id: number) => void;
  public onTerminalsChanged?: (terminals: string[]) => void;
  public onNotification?: (msg: string, level: "info" | "warning" | "error") => void;
  public onCompactRequest?: (msg: CompactRequestMsg) => Promise<{ ok: boolean; reason?: string }>;

  constructor(options: LinkNodeOptions = {}) {
    this.customOmpDir = options.customOmpDir;
    this.identity = getOrCreateDeviceIdentity(this.customOmpDir);
    this.port = options.port || DEFAULT_PORT;
    this.bindHost = options.bindHost || "0.0.0.0";
    this.networkMode = options.networkMode || "lan";
    this.terminalName = options.terminalName || this.identity.deviceName;
    this.currentSessionId = options.sessionId || "team-link";
    this.allowRemoteExec = options.allowRemoteExec ?? false;
    this.workspaceRoot = options.workspaceRoot || process.cwd();
    this.transferReceiver = new TransferReceiver(this.customOmpDir);

    // Register canonical workspace root
    try {
      registerWorkspace({ id: "default", rootDir: this.workspaceRoot });
    } catch {}
  }

  // ── Hub Lifecycle ─────────────────────────────────────────────────────────

  private checkRateLimit(map: Map<string, number[]>, key: string | undefined, maxPerWindow: number, windowMs = 60_000): boolean {
    const safeKey = key || "unknown";
    const now = Date.now();
    const timestamps = (map.get(safeKey) || []).filter((t) => now - t < windowMs);
    if (timestamps.length >= maxPerWindow) {
      return false;
    }
    timestamps.push(now);
    map.set(safeKey, timestamps);
    return true;
  }

  public async startHub(): Promise<void> {
    if (this.role !== "disconnected") {
      await this.stop();
    }

    if (this.networkMode === "tailscale") {
      const net = getNetworkInfo();
      if (!net.tailscaleIp) {
        throw new Error("Tailscale IPv4 address not found. Ensure Tailscale is running or switch to LAN mode.");
      }
      this.bindHost = net.tailscaleIp;
    } else if (this.networkMode === "loopback") {
      this.bindHost = "127.0.0.1";
    }

    const tlsOptions = getServerTlsOptions(this.identity);

    return new Promise((resolve, reject) => {
      this.httpsServer = createHttpsServer(tlsOptions, (req, res) => {
        // Minimal, public status endpoint with strict security headers (no sensitive session name exposed)
        if (req.method === "GET" && (req.url === "/status" || req.url?.startsWith("/status?"))) {
          res.writeHead(200, {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'",
            "X-Content-Type-Options": "nosniff",
          });
          res.end(
            JSON.stringify({
              service: "omp-link",
              protocolVersion: PROTOCOL_VERSION,
              sessionId: this.currentSessionId,
              spkiFingerprint: this.identity.fingerprint,
              certificateFingerprint: this.identity.fingerprint,
              principalId: this.identity.principalId,
              pairingAvailable: true,
              transport: "wss",
            }),
          );
          return;
        }

        // All other HTTP routes rejected
        res.writeHead(404, {
          "Content-Type": "text/plain",
          "Cache-Control": "no-store",
        });
        res.end("Not Found");
      });

      this.wss = new WebSocketServer({
        server: this.httpsServer,
        maxPayload: 2 * 1024 * 1024,
        perMessageDeflate: false,
      });

      this.wss.on("connection", (socket, req) => {
        this.handleHubInboundConnection(socket, req);
      });

      this.httpsServer.on("error", (err: any) => {
        reject(err);
      });

      try {
        this.httpsServer.listen(this.port, this.bindHost, () => {
          this.role = "hub";
          if (this.networkMode === "lan") {
            this.udpSocket = startUdpDiscoveryResponder(this.port, {
              bindHost: this.bindHost,
              enabled: true,
            });
          } else {
            this.udpSocket = null;
          }
          appendAuditLog({
            type: "hub_started",
            timestamp: Date.now(),
            sessionId: this.currentSessionId,
            port: this.port,
            principalId: this.identity.principalId,
            bindHost: this.bindHost,
            networkMode: this.networkMode,
          });
          resolve();
        });
      } catch (err: any) {
        reject(err);
      }
    });
  }

  private handleHubInboundConnection(socket: any, req: any): void {
    const remoteAddress = req.socket?.remoteAddress || "unknown";

    // Rate limit connections per IP (max 60/min)
    if (!this.checkRateLimit(this.connectionRateMap, remoteAddress, 60)) {
      socket.close(4429, "Connection rate limit exceeded");
      return;
    }

    const peerCert = extractPeerCertificate(req.socket);
    if (!peerCert) {
      // Mutual TLS required
      socket.close(4403, "Mutual TLS client certificate required");
      return;
    }

    const ctx = createConnectionContext({
      socket,
      remoteAddress,
      peerCert,
      isLocal: remoteAddress === "127.0.0.1" || remoteAddress === "::1",
      onHandshakeTimeout: () => {
        socket.close(4408, "Handshake timeout (10s)");
      },
    });

    this.hubConnections.set(socket, ctx);

    // Check paired status
    const canonicalFp = normalizeFingerprint(peerCert.fingerprint);
    const pairedDevices = loadPairedDevices(this.customOmpDir);
    const paired = pairedDevices.get(canonicalFp);

    if (paired) {
      ctx.principalId = paired.principalId;
      ctx.displayName = paired.deviceName;
      ctx.permissions = paired.permissions;
      paired.lastSeen = Date.now();
      paired.lastAddress = remoteAddress;
      savePairedDevice(paired, this.customOmpDir);
    }

    socket.on("message", (data: any) => {
      this.handleHubSocketMessage(socket, ctx, data, req);
    });

    socket.on("close", () => {
      this.handleHubSocketClose(socket, ctx);
    });

    socket.on("error", () => {
      this.handleHubSocketClose(socket, ctx);
    });
  }

  private handleHubSocketMessage(socket: any, ctx: ConnectionContext, rawData: any, req?: any): void {
    const parsed = parseWireMessage(rawData);
    if (!parsed.ok) {
      socket.close(parsed.closeCode, parsed.error);
      return;
    }

    const msg = parsed.message;

    // Phase validation
    const phaseCheck = validateMessagePhase(ctx, msg.type);
    if (!phaseCheck.allowed) {
      socket.close(phaseCheck.closeCode || 4403, phaseCheck.reason);
      return;
    }

    // Handshake handling
    if (msg.type === "client_hello") {
      this.handleHubClientHello(socket, ctx, msg as ClientHelloMsg, req);
      return;
    }

    if (msg.type === "pair_request") {
      this.handleHubPairRequest(socket, ctx, msg as PairRequestMsg, req);
      return;
    }

    if (msg.type === "pair_verify") {
      this.handleHubPairVerify(socket, ctx, msg as PairVerifyMsg);
      return;
    }

    // Application message handling
    const appMsg = msg as ApplicationMessage;

    // Deduplication check
    if (!checkMessageDeduplication(ctx, appMsg.id)) {
      return; // Duplicate frame, ignore
    }

    // Capability check
    const permCheck = isActionPermitted(ctx.permissions, appMsg);
    if (!permCheck.permitted) {
      this.sendApplicationFrame(socket, ctx, {
        type: appMsg.type === "rpc_request" ? "rpc_response" : "chat",
        version: 5,
        id: crypto.randomUUID(),
        from: this.terminalName,
        originPrincipalId: this.identity.principalId,
        to: ctx.displayName,
        toPrincipalId: ctx.principalId,
        ok: false,
        text: `[Access Denied] ${permCheck.reason}`,
        error: permCheck.reason,
        ts: Date.now(),
      } as WireMessage);
      return;
    }

    // Overwrite authoritative origin from authenticated socket
    const boundMsg = bindMessageOrigin(appMsg, ctx);

    // Route application message
    this.routeApplicationMessage(socket, ctx, boundMsg);
  }

  private handleHubClientHello(socket: any, ctx: ConnectionContext, msg: ClientHelloMsg, req?: any): void {
    ctx.helloReceived = true;
    const peerCert = ctx.peerCert!;
    const canonicalFp = normalizeFingerprint(peerCert.fingerprint);

    // Disambiguate duplicate display names across peers
    let finalDisplayName = msg.displayName;
    for (const [s, c] of this.hubConnections) {
      if (
        s !== socket &&
        c.phase === "authenticated" &&
        c.displayName === finalDisplayName &&
        c.principalId !== peerCert.principalId
      ) {
        finalDisplayName = `${msg.displayName}@${canonicalFp.replace(/:/g, "").slice(0, 6)}`;
        break;
      }
    }
    ctx.displayName = finalDisplayName;

    // Check one-time invite secret if provided
    if (msg.inviteSecret) {
      const inviteRes = verifyAndConsumeInvite(msg.inviteSecret);
      if (inviteRes.valid) {
        // Automatically pair and approve
        const paired: PairedDevice = {
          principalId: peerCert.principalId,
          fingerprint: canonicalFp,
          certPem: peerCert.certPem,
          deviceName: finalDisplayName,
          permissions: DEFAULT_PERMISSIONS,
          pairedAt: Date.now(),
          lastSeen: Date.now(),
          lastAddress: ctx.remoteAddress,
        };
        savePairedDevice(paired, this.customOmpDir);
        ctx.principalId = paired.principalId;
        ctx.permissions = paired.permissions;

        this.sendHandshakeFrame(socket, ctx, {
          type: "server_hello",
          version: 5,
          sessionId: this.currentSessionId,
          hubPrincipalId: this.identity.principalId,
          hubFingerprint: this.identity.fingerprint,
          hubNonce: crypto.randomBytes(32).toString("hex"),
          requiresPairing: false,
          host: os.hostname(),
          terminals: this.getConnectedTerminalsList(),
        } as ServerHelloMsg);

        setConnectionPhase(ctx, "authenticated");

        this.broadcastTerminalList();
        if (this.onPairingApproved) this.onPairingApproved(paired);
        return;
      }
    }

    // Already paired device
    const pairedDevices = loadPairedDevices(this.customOmpDir);
    const paired = pairedDevices.get(canonicalFp);

    if (paired) {
      ctx.principalId = paired.principalId;
      ctx.permissions = paired.permissions;

      this.sendHandshakeFrame(socket, ctx, {
        type: "server_hello",
        version: 5,
        sessionId: this.currentSessionId,
        hubPrincipalId: this.identity.principalId,
        hubFingerprint: this.identity.fingerprint,
        hubNonce: crypto.randomBytes(32).toString("hex"),
        requiresPairing: false,
        host: os.hostname(),
        terminals: this.getConnectedTerminalsList(),
      } as ServerHelloMsg);

      setConnectionPhase(ctx, "authenticated");

      this.broadcastTerminalList();
      return;
    }

    // Unpaired device -> enter pairing queue
    this.initiatePairingForSocket(socket, ctx, msg.clientNonce, finalDisplayName, undefined, req);
  }

  private handleHubPairRequest(socket: any, ctx: ConnectionContext, msg: PairRequestMsg, req?: any): void {
    if (ctx.pairingRequested) {
      socket.close(4400, "Pairing request already active on this connection");
      return;
    }
    this.initiatePairingForSocket(socket, ctx, msg.clientNonce, msg.displayName, msg.inviteSecret, req);
  }

  private initiatePairingForSocket(
    socket: any,
    ctx: ConnectionContext,
    clientNonce: string,
    displayName: string,
    inviteSecret?: string,
    req?: any,
  ): void {
    // Rate limit pairing attempts per IP (max 10/min)
    if (!this.checkRateLimit(this.pairingRateMap, ctx.remoteAddress, 10)) {
      socket.close(4429, "Pairing rate limit exceeded");
      return;
    }

    const peerCert = ctx.peerCert!;
    const canonicalFp = normalizeFingerprint(peerCert.fingerprint);

    if (inviteSecret) {
      const inviteRes = verifyAndConsumeInvite(inviteSecret);
      if (inviteRes.valid) {
        const paired: PairedDevice = {
          principalId: peerCert.principalId,
          fingerprint: canonicalFp,
          certPem: peerCert.certPem,
          deviceName: displayName,
          permissions: DEFAULT_PERMISSIONS,
          pairedAt: Date.now(),
          lastSeen: Date.now(),
          lastAddress: ctx.remoteAddress,
        };
        savePairedDevice(paired, this.customOmpDir);
        ctx.principalId = paired.principalId;
        ctx.displayName = displayName;
        ctx.permissions = paired.permissions;

        this.sendHandshakeFrame(socket, ctx, {
          type: "server_hello",
          version: 5,
          sessionId: this.currentSessionId,
          hubPrincipalId: this.identity.principalId,
          hubFingerprint: this.identity.fingerprint,
          hubNonce: crypto.randomBytes(32).toString("hex"),
          requiresPairing: false,
          terminals: this.getConnectedTerminalsList(),
        } as ServerHelloMsg);

        setConnectionPhase(ctx, "authenticated");

        this.broadcastTerminalList();
        return;
      }
    }

    if (this.pendingPairRequests.size >= 16) {
      socket.close(4429, "Pairing queue full (maximum 16 requests)");
      return;
    }

    const reqId = this.nextPairingReqId++;
    const hubNonce = crypto.randomBytes(32).toString("hex");

    // Independently derive local SAS bound to TLS socket channel
    const tlsSocket = req?.socket || (socket as any)?._socket;
    const sasCode = deriveLocalSas(
      tlsSocket,
      this.identity.spkiDer,
      peerCert.spkiDer,
      Buffer.from(hubNonce, "hex"),
      Buffer.from(clientNonce, "hex"),
    );

    ctx.pairingRequested = true;
    ctx.phase = "awaiting-pairing";
    ctx.sasCode = sasCode;
    ctx.displayName = displayName;

    const timer = setTimeout(() => {
      this.pendingPairRequests.delete(reqId);
      socket.close(4408, "Pairing request timed out after 60s");
    }, 60_000);

    this.pendingPairRequests.set(reqId, {
      id: reqId,
      socket,
      peerCert,
      displayName,
      clientNonce,
      hubNonce,
      sasCode,
      host: ctx.remoteAddress || "unknown",
      createdAt: Date.now(),
      timer,
    });

    // Send server_hello WITHOUT transmitting the SAS code over the wire
    this.sendHandshakeFrame(socket, ctx, {
      type: "server_hello",
      version: 5,
      sessionId: this.currentSessionId,
      hubPrincipalId: this.identity.principalId,
      hubFingerprint: this.identity.fingerprint,
      hubNonce,
      requiresPairing: true,
    } as ServerHelloMsg);

    if (this.onPairingRequested) {
      this.onPairingRequested({
        id: reqId,
        displayName,
        fingerprint: canonicalFp,
        sasCode,
        host: ctx.remoteAddress || "unknown",
      });
    }
  }

  private handleHubPairVerify(socket: any, ctx: ConnectionContext, msg: PairVerifyMsg): void {
    if (!ctx.sasCode || msg.sasCode !== ctx.sasCode) {
      socket.close(4403, "SAS verification mismatch");
      return;
    }
  }

  public approvePairing(
    id: number,
    permissions: DevicePermissions = DEFAULT_PERMISSIONS,
    code?: string,
  ): PairedDevice | null {
    const req = this.pendingPairRequests.get(id);
    if (!req) return null;

    // Verify Short Authentication String (SAS) if supplied
    if (code) {
      const cleanExpected = req.sasCode.replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
      const cleanGiven = code.replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
      const expBuf = Buffer.from(cleanExpected, "utf8");
      const givBuf = Buffer.from(cleanGiven, "utf8");
      if (expBuf.length !== givBuf.length || !crypto.timingSafeEqual(expBuf, givBuf)) {
        appendAuditLog({
          type: "pairing_rejected_invalid_sas",
          timestamp: Date.now(),
          reqId: id,
          principalId: req.peerCert.principalId,
        });
        return null;
      }
    }

    clearTimeout(req.timer);
    this.pendingPairRequests.delete(id);

    const paired: PairedDevice = {
      principalId: req.peerCert.principalId,
      fingerprint: normalizeFingerprint(req.peerCert.fingerprint),
      certPem: req.peerCert.certPem,
      deviceName: req.displayName,
      permissions,
      pairedAt: Date.now(),
      lastSeen: Date.now(),
      lastAddress: req.host,
    };

    savePairedDevice(paired, this.customOmpDir);

    const ctx = this.hubConnections.get(req.socket);
    if (ctx) {
      ctx.principalId = paired.principalId;
      ctx.displayName = paired.deviceName;
      ctx.permissions = paired.permissions;

      this.sendHandshakeFrame(req.socket, ctx, {
        type: "pair_response",
        version: 5,
        approved: true,
        permissions: paired.permissions,
      } as PairResponseMsg);

      setConnectionPhase(ctx, "authenticated");

      this.broadcastTerminalList();
    }

    appendAuditLog({
      type: "pairing_approved",
      timestamp: Date.now(),
      principalId: paired.principalId,
      deviceName: paired.deviceName,
      permissions,
    });

    if (this.onPairingApproved) this.onPairingApproved(paired);
    return paired;
  }

  public denyPairing(id: number): boolean {
    const req = this.pendingPairRequests.get(id);
    if (!req) return false;

    clearTimeout(req.timer);
    this.pendingPairRequests.delete(id);

    const ctx = this.hubConnections.get(req.socket);
    try {
      if (ctx) {
        this.sendHandshakeFrame(req.socket, ctx, {
          type: "pair_response",
          version: 5,
          approved: false,
          reason: "Pairing request was denied by the host",
        } as PairResponseMsg);
      }
      req.socket.close(4403, "Pairing denied");
    } catch {}

    appendAuditLog({
      type: "pairing_denied",
      timestamp: Date.now(),
      principalId: req.peerCert.principalId,
      deviceName: req.displayName,
    });

    if (this.onPairingDenied) this.onPairingDenied(id);
    return true;
  }

  public revokeDevice(fingerprintOrPrincipal: string): boolean {
    const removed = removePairedDevice(fingerprintOrPrincipal, this.customOmpDir);
    revokeGrantsForPrincipal(fingerprintOrPrincipal, "Device pairing revoked");

    for (const [socket, ctx] of this.hubConnections) {
      const matchesFp = ctx.peerCert && (
        ctx.peerCert.principalId === fingerprintOrPrincipal ||
        normalizeFingerprint(ctx.peerCert.fingerprint) === normalizeFingerprint(fingerprintOrPrincipal)
      );
      const matchesName = ctx.displayName === fingerprintOrPrincipal;
      if (matchesFp || matchesName) {
        if (ctx.principalId) revokeGrantsForPrincipal(ctx.principalId, "Device pairing revoked");
        try {
          socket.close(4403, "Device pairing revoked");
        } catch {}
        this.handleHubSocketClose(socket, ctx);
      }
    }

    appendAuditLog({
      type: "device_revoked",
      timestamp: Date.now(),
      target: fingerprintOrPrincipal,
    });

    this.broadcastTerminalList();
    return removed;
  }

  public updatePeerPermissions(
    fingerprintOrPrincipal: string,
    updates: Partial<DevicePermissions>,
  ): boolean {
    const updated = updateDevicePermissions(fingerprintOrPrincipal, updates, this.customOmpDir);
    if (!updated) return false;

    // Update active connection context immediately
    for (const [_, ctx] of this.hubConnections) {
      const matchesFp = ctx.peerCert && (
        ctx.peerCert.principalId === fingerprintOrPrincipal ||
        normalizeFingerprint(ctx.peerCert.fingerprint) === normalizeFingerprint(fingerprintOrPrincipal)
      );
      const matchesName = ctx.displayName === fingerprintOrPrincipal;
      if (matchesFp || matchesName) {
        ctx.permissions = {
          ...(ctx.permissions || DEFAULT_PERMISSIONS),
          ...updates,
        };
      }
    }

    appendAuditLog({
      type: "permissions_updated",
      timestamp: Date.now(),
      target: fingerprintOrPrincipal,
      updates,
    });

    return true;
  }

  private routeApplicationMessage(
    senderSocket: any,
    senderCtx: ConnectionContext,
    msg: ApplicationMessage,
  ): void {
    // 1. Status update
    if (msg.type === "status_update") {
      this.terminalStatuses.set(senderCtx.displayName, msg.status);
      if (msg.context) this.terminalContexts.set(senderCtx.displayName, msg.context);
      if (this.onPeerStatusUpdate) {
        this.onPeerStatusUpdate(senderCtx.displayName, msg.status, msg.context);
      }
      // Broadcast to other authenticated connections
      this.broadcastToOthers(senderSocket, msg);
      return;
    }

    // 2. Addressed to the hub itself
    const isForHub =
      (msg.toPrincipalId && msg.toPrincipalId === this.identity.principalId) ||
      (!msg.toPrincipalId && (msg.to === this.terminalName || !msg.to));

    if (isForHub) {
      this.handleLocalApplicationMessage(msg, senderSocket, senderCtx);
      return;
    }

    // 3. Routed to another peer
    let targetSocket: any = null;
    let targetCtx: ConnectionContext | null = null;
    for (const [s, c] of this.hubConnections) {
      if (c.phase === "authenticated") {
        if (msg.toPrincipalId && c.principalId === msg.toPrincipalId) {
          targetSocket = s;
          targetCtx = c;
          break;
        } else if (!msg.toPrincipalId && c.displayName === msg.to) {
          targetSocket = s;
          targetCtx = c;
          break;
        }
      }
    }

    if (targetSocket && targetCtx) {
      this.sendApplicationFrame(targetSocket, targetCtx, msg);
    } else {
      // Recipient not found
      if (msg.type === "rpc_request") {
        this.sendApplicationFrame(senderSocket, senderCtx, {
          type: "rpc_response",
          version: 5,
          id: msg.id,
          from: this.terminalName,
          to: senderCtx.displayName,
          ok: false,
          error: `Target peer "${msg.toPrincipalId || msg.to}" is not online`,
          ts: Date.now(),
        } as RpcResponseMsg);
      }
    }
  }

  private async handleLocalApplicationMessage(
    msg: ApplicationMessage,
    senderSocket: any,
    senderCtx: ConnectionContext,
  ): Promise<void> {
    if (msg.type === "chat" || msg.type === "direct_message") {
      if (this.onMessage) this.onMessage(msg);
      return;
    }

    if (msg.type === "rpc_request") {
      await this.handleLocalRpcRequest(msg as RpcRequestMsg, senderSocket, senderCtx);
      return;
    }

    if (msg.type === "rpc_response") {
      const resp = msg as RpcResponseMsg;
      const pending = this.pendingRpcRequests.get(resp.id);
      if (pending) {
        if (pending.expectedPrincipalId && senderCtx.principalId && senderCtx.principalId !== pending.expectedPrincipalId) {
          appendAuditLog({
            type: "rpc_response_origin_mismatch",
            timestamp: Date.now(),
            expectedPrincipalId: pending.expectedPrincipalId,
            actualPrincipalId: senderCtx.principalId,
          });
          return;
        }
        clearTimeout(pending.timeout);
        this.pendingRpcRequests.delete(resp.id);
        pending.resolve(resp);
      }
      return;
    }

    if (msg.type === "file_ack") {
      const ack = msg as FileAckMsg;
      const pending = this.pendingFileAcks.get(ack.transferId);
      if (pending) {
        if (pending.expectedPrincipalId && senderCtx.principalId && senderCtx.principalId !== pending.expectedPrincipalId) {
          appendAuditLog({
            type: "file_ack_origin_mismatch",
            timestamp: Date.now(),
            expectedPrincipalId: pending.expectedPrincipalId,
            actualPrincipalId: senderCtx.principalId,
          });
          return;
        }
        clearTimeout(pending.timeout);
        this.pendingFileAcks.delete(ack.transferId);
        pending.resolve(ack);
      }
      return;
    }

    if (msg.type === "compact_response") {
      const cResp = msg as CompactResponseMsg;
      const pending = this.pendingCompactRequests.get(cResp.id);
      if (pending) {
        if (pending.expectedPrincipalId && senderCtx.principalId && senderCtx.principalId !== pending.expectedPrincipalId) {
          appendAuditLog({
            type: "compact_response_origin_mismatch",
            timestamp: Date.now(),
            expectedPrincipalId: pending.expectedPrincipalId,
            actualPrincipalId: senderCtx.principalId,
          });
          return;
        }
        clearTimeout(pending.timeout);
        this.pendingCompactRequests.delete(cResp.id);
        pending.resolve(cResp);
      }
      return;
    }

    if (msg.type === "file_offer") {
      const offer = msg as FileOfferMsg;
      const res = this.transferReceiver.handleOffer(offer, this.currentSessionId);
      if (!res.ok) {
        this.sendApplicationFrame(senderSocket, senderCtx, {
          type: "file_ack",
          version: 5,
          id: `ack-${offer.transferId}`,
          transferId: offer.transferId,
          from: this.terminalName,
          to: senderCtx.displayName,
          ok: false,
          error: res.error,
          ts: Date.now(),
        } as FileAckMsg);
      }
      return;
    }

    if (msg.type === "file_chunk") {
      const chunk = msg as FileChunkMsg;
      const res = this.transferReceiver.handleChunk(chunk);
      if (res.complete || !res.ok) {
        this.sendApplicationFrame(senderSocket, senderCtx, {
          type: "file_ack",
          version: 5,
          id: `ack-${chunk.transferId}`,
          transferId: chunk.transferId,
          from: this.terminalName,
          to: senderCtx.displayName,
          ok: res.ok,
          error: res.error,
          ts: Date.now(),
        } as FileAckMsg);

        if (res.ok) {
          appendAuditLog({
            type: "file_transfer_received",
            timestamp: Date.now(),
            transferId: chunk.transferId,
            from: senderCtx.displayName,
            finalPath: res.finalPath,
          });
        }
      }
      return;
    }

    if (msg.type === "compact_request") {
      let ok = true;
      let reason: string | undefined;
      if (this.onCompactRequest) {
        try {
          const cRes = await this.onCompactRequest(msg as CompactRequestMsg);
          ok = cRes.ok;
          reason = cRes.reason;
        } catch (err: any) {
          ok = false;
          reason = err.message;
        }
      }
      this.sendApplicationFrame(senderSocket, senderCtx, {
        type: "compact_response",
        version: 5,
        id: msg.id,
        from: this.terminalName,
        to: senderCtx.displayName,
        ok,
        reason,
        ts: Date.now(),
      } as CompactResponseMsg);
      return;
    }
  }

  private async handleLocalRpcRequest(
    req: RpcRequestMsg,
    senderSocket: any,
    senderCtx: ConnectionContext | null,
  ): Promise<void> {
    const callerPrincipalId = senderCtx?.principalId || req.originPrincipalId;
    const callerDisplayName = senderCtx?.displayName || req.from;
    const callerDevice = callerPrincipalId
      ? getPairedDevice(callerPrincipalId, this.customOmpDir)
      : undefined;
    const isLocalHubCaller = this.role === "client" && (
      (senderCtx && senderCtx.phase === "authenticated") ||
      (this.clientContext && this.clientContext.phase === "authenticated")
    );
    const callerPermissions =
      (isLocalHubCaller ? FULL_PERMISSIONS : null) ||
      senderCtx?.permissions ||
      callerDevice?.permissions ||
      NO_PERMISSIONS;

    const sendRes = (ok: boolean, result?: any, error?: string) => {
      const resp: RpcResponseMsg = {
        type: "rpc_response",
        version: 5,
        id: req.id,
        from: this.terminalName,
        originPrincipalId: this.identity.principalId,
        to: req.from || callerDisplayName || "unknown",
        toPrincipalId: req.originPrincipalId,
        ok,
        result,
        error,
        ts: Date.now(),
      };
      if (this.role === "hub" && senderSocket && senderCtx) {
        this.sendApplicationFrame(senderSocket, senderCtx, resp);
      } else if (this.role === "client" && this.clientWs && this.clientContext) {
        this.sendApplicationFrame(this.clientWs, this.clientContext, resp);
      }
    };

    // Concurrency limiting per peer
    const peerKey = callerPrincipalId || callerDisplayName || "unknown";
    const currentActive = this.activeRpcsByPeer.get(peerKey) || 0;
    if (currentActive >= LinkNode.MAX_CONCURRENT_RPCS) {
      sendRes(false, undefined, `Inspection concurrency limit exceeded (max ${LinkNode.MAX_CONCURRENT_RPCS} in flight)`);
      return;
    }
    this.activeRpcsByPeer.set(peerKey, currentActive + 1);

    const finishRpc = () => {
      const active = this.activeRpcsByPeer.get(peerKey) || 1;
      if (active <= 1) {
        this.activeRpcsByPeer.delete(peerKey);
      } else {
        this.activeRpcsByPeer.set(peerKey, active - 1);
      }
    };

    try {
      if (req.action === "system_status") {
        const statusData = {
          service: "omp-link",
          protocolVersion: PROTOCOL_VERSION,
          hubPrincipalId: this.identity.principalId,
          hubFingerprint: this.identity.fingerprint,
          sessionId: this.currentSessionId,
          role: this.role,
          terminalName: this.terminalName,
          connectedPeers: this.getConnectedTerminalsList(),
          caller: {
            principalId: callerPrincipalId,
            displayName: callerDisplayName,
            permissions: callerPermissions,
            workspaces: callerDevice?.workspaces || [],
          },
          activeGrants: getActiveGrants().map((g) => ({
            grantId: g.grantId,
            principalId: g.principalId,
            displayName: g.displayName,
            workspaceId: g.workspaceId,
            remainingUses: g.remainingUses,
            expiresAt: g.expiresAt,
          })),
        };
        sendRes(true, statusData);
        return;
      }

      // Check granular capability permissions
      const permCheck = isActionPermitted(callerPermissions, req);
      if (!permCheck.permitted) {
        sendRes(false, undefined, permCheck.reason);
        return;
      }

      if (req.action === "exec") {
        if (!this.allowRemoteExec) {
          sendRes(false, undefined, "Remote execution is disabled on this node (requires --unsafe-remote-exec)");
          return;
        }

        // Require base capability first
        if (!callerPermissions?.execRequest) {
          sendRes(false, undefined, 'Permission denied: device does not have base "execRequest" capability');
          return;
        }

        // Check execution grant with workspace confinement & command digest
        const grantCheck = checkAndConsumeExecGrant(
          callerPrincipalId || "",
          req.params?.workspace,
          req.params?.command,
        );
        if (!grantCheck.allowed) {
          appendAuditLog({
            type: "exec_blocked",
            timestamp: Date.now(),
            principalId: callerPrincipalId,
            peer: callerDisplayName,
            command: req.params?.command,
            reason: grantCheck.reason,
          });
          sendRes(false, undefined, grantCheck.reason);
          return;
        }

        appendAuditLog({
          type: "exec_executed",
          timestamp: Date.now(),
          principalId: callerPrincipalId,
          peer: callerDisplayName,
          command: req.params?.command,
        });

        exec(
          req.params?.command || "",
          { cwd: this.workspaceRoot, timeout: 15_000 },
          (err, stdout, stderr) => {
            if (err) {
              sendRes(false, undefined, stderr || err.message);
            } else {
              sendRes(true, stdout || "[Command succeeded with no output]");
            }
          },
        );
        return;
      }

      const wsId = req.params?.workspace || "default";
      const wsPolicy = getRegisteredWorkspace(wsId);
      const cwd = wsPolicy ? wsPolicy.canonicalRoot : this.workspaceRoot;

      switch (req.action) {
        case "git_status": {
          const res = await safeGitStatus(cwd);
          sendRes(res.ok, res.output, res.error);
          break;
        }
        case "git_diff": {
          const res = await safeGitDiff(cwd);
          sendRes(res.ok, res.output, res.error);
          break;
        }
        case "git_log": {
          const res = await safeGitLog(cwd, req.params?.count || 10);
          sendRes(res.ok, res.output, res.error);
          break;
        }
        case "search_text": {
          const res = await safeGitGrep(cwd, req.params?.pattern || "");
          sendRes(res.ok, res.output, res.error);
          break;
        }
        case "read_file": {
          const res = await safeReadFile(cwd, req.params?.filePath || "");
          sendRes(res.ok, res.content, res.error);
          break;
        }
        case "list_dir": {
          const res = await safeListDir(cwd, req.params?.filePath || "");
          sendRes(res.ok, res.entries?.join("\n"), res.error);
          break;
        }
        default:
          sendRes(false, undefined, `Unsupported RPC action: "${req.action}"`);
          break;
      }
    } finally {
      finishRpc();
    }
  }

  private handleHubSocketClose(socket: any, ctx: ConnectionContext): void {
    cleanupConnectionContext(ctx);
    this.hubConnections.delete(socket);

    const peerKey = ctx.principalId || ctx.displayName;
    this.activeRpcsByPeer.delete(peerKey);

    if (ctx.principalId) {
      revokeGrantsForPrincipal(ctx.principalId, "Peer disconnected");
      this.transferReceiver.cleanupPeerTransfers(ctx.principalId);
      this.transferReceiver.cleanupPeerTransfers(ctx.displayName);
      appendAuditLog({
        type: "peer_disconnected",
        timestamp: Date.now(),
        principalId: ctx.principalId,
        peer: ctx.displayName,
      });
    }

    this.terminalStatuses.delete(ctx.displayName);
    this.terminalContexts.delete(ctx.displayName);

    // Clean any pending pairing request on this socket
    for (const [id, req] of this.pendingPairRequests) {
      if (req.socket === socket) {
        clearTimeout(req.timer);
        this.pendingPairRequests.delete(id);
      }
    }

    this.broadcastTerminalList();
  }

  // ── Client Lifecycle ──────────────────────────────────────────────────────

  public async connectToHub(
    hubUrl: string,
    pinnedFingerprint?: string,
    inviteSecret?: string,
  ): Promise<void> {
    if (this.role !== "disconnected") {
      await this.stop();
    }

    let effectiveFingerprint = pinnedFingerprint;
    let caCertPem: string | undefined;

    // Look up known hub in paired devices if not explicitly provided
    const paired = loadPairedDevices(this.customOmpDir);
    if (!effectiveFingerprint) {
      for (const [_, dev] of paired) {
        if (dev.lastAddress === hubUrl || hubUrl.includes(dev.deviceName)) {
          effectiveFingerprint = dev.fingerprint;
          caCertPem = dev.certPem;
          break;
        }
      }
      if (!effectiveFingerprint && paired.size === 1) {
        const single = paired.values().next().value;
        if (single) {
          effectiveFingerprint = single.fingerprint;
          caCertPem = single.certPem;
        }
      }
    } else {
      const match = paired.get(normalizeFingerprint(effectiveFingerprint));
      if (match) {
        caCertPem = match.certPem;
      }
    }

    this.pinnedHubFingerprint = effectiveFingerprint || null;
    let capturedServerCert: PeerCertificateInfo | null = null;
    const tlsOptions = getClientTlsOptions(this.identity, {
      pinnedFingerprint: effectiveFingerprint,
      caCertPem,
      allowUnpaired: !effectiveFingerprint,
      onServerCertificate: (certInfo) => {
        capturedServerCert = certInfo;
      },
    });

    return new Promise((resolve, reject) => {
      const ws = new WebSocket(hubUrl, {
        ...tlsOptions,
        maxPayload: 2 * 1024 * 1024,
        perMessageDeflate: false,
      });
      this.clientWs = ws;

      ws.on("open", () => {
        if (this.clientWs !== ws) return;

        const tlsSocket = (ws as any)._socket;
        let peerCert: PeerCertificateInfo | null = capturedServerCert;
        if (!peerCert && tlsSocket) {
          try {
            peerCert = extractPeerCertificate(tlsSocket);
          } catch {}
        }
        if (tlsSocket && peerCert) {
          tlsSocket._peerCertInfo = peerCert;
        }
        if (peerCert) {
          this.capturedServerCert = peerCert;
          this.pinnedHubFingerprint = peerCert.fingerprint;
        }

        if (effectiveFingerprint && (peerCert || tlsSocket)) {
          const verified = peerCert
            ? normalizeFingerprint(peerCert.fingerprint) === normalizeFingerprint(effectiveFingerprint)
            : verifyPeerSpki(tlsSocket, effectiveFingerprint);
          if (!verified) {
            ws.terminate();
            reject(new Error(`SPKI fingerprint mismatch: expected ${effectiveFingerprint}`));
            return;
          }
        }

        this.role = "client";
        this.clientContext = createConnectionContext({
          socket: ws,
          peerCert: this.capturedServerCert,
          isLocal: hubUrl.includes("127.0.0.1") || hubUrl.includes("localhost"),
        });

        if (this.capturedServerCert) {
          this.clientContext.peerCert = this.capturedServerCert;
          this.clientContext.principalId = this.capturedServerCert.principalId;
          this.clientContext.permissions = FULL_PERMISSIONS;
        }

        const clientNonce = crypto.randomBytes(32).toString("hex");
        this.lastClientNonce = clientNonce;

        // Send client_hello (Handshake frame)
        const hello: ClientHelloMsg = {
          type: "client_hello",
          version: 5,
          clientNonce,
          displayName: this.terminalName,
          inviteSecret,
          host: os.hostname(),
          cwd: process.cwd(),
        };

        this.sendHandshakeFrame(ws, this.clientContext, hello);
        resolve();
      });

      ws.on("message", (data: any) => {
        if (this.clientWs !== ws) return;
        this.handleClientSocketMessage(data);
      });

      ws.on("close", () => {
        if (this.clientWs === ws) {
          this.role = "disconnected";
          this.clientContext = null;
          this.clientWs = null;
        }
      });

      ws.on("error", (err) => {
        if (this.clientWs === ws) {
          this.role = "disconnected";
          this.clientContext = null;
          this.clientWs = null;
        }
        reject(err);
      });
    });
  }

  private async handleClientSocketMessage(rawData: any): Promise<void> {
    const parsed = parseWireMessage(rawData);
    if (!parsed.ok) return;

    const msg = parsed.message;

    if (msg.type === "server_hello") {
      const sHello = msg as ServerHelloMsg;
      if (sHello.requiresPairing) {
        let sasWords = "(unavailable)";
        const tlsSocket = (this.clientWs as any)?._socket;
        if (tlsSocket && sHello.hubFingerprint && this.lastClientNonce && sHello.hubNonce) {
          try {
            const peerCert = extractPeerCertificate(tlsSocket);
            if (peerCert) {
              sasWords = deriveLocalSas(
                tlsSocket,
                peerCert.spkiDer,
                this.identity.spkiDer,
                Buffer.from(sHello.hubNonce, "hex"),
                Buffer.from(this.lastClientNonce, "hex"),
              );
              this.currentLocalSas = sasWords;
            }
          } catch {}
        }
        if (this.onNotification) {
          this.onNotification(
            `🔒 Pairing required by hub.\n   Verification code: ${sasWords}\n   Tell the host to approve your device with this verification code.`,
            "warning",
          );
        }
      } else {
        if (this.clientContext) setConnectionPhase(this.clientContext, "authenticated");
        // Save paired hub certificate for future pinned connections
        this.persistPairedHubIdentity(sHello.hubPrincipalId);
        if (this.onNotification) {
          this.onNotification(`Connected to session "${sHello.sessionId}"`, "info");
        }
      }
      return;
    }

    if (msg.type === "pair_response") {
      const pResp = msg as PairResponseMsg;
      if (pResp.approved) {
        if (this.clientContext) setConnectionPhase(this.clientContext, "authenticated");
        // Save paired hub certificate for future pinned connections
        this.persistPairedHubIdentity();
        if (this.onNotification) this.onNotification("Device pairing approved by host!", "info");
      } else {
        if (this.onNotification) this.onNotification(`Pairing rejected: ${pResp.reason}`, "error");
      }
      return;
    }

    if (msg.type === "rpc_response") {
      const resp = msg as RpcResponseMsg;
      const pending = this.pendingRpcRequests.get(resp.id);
      if (pending) {
        if (pending.expectedPrincipalId && resp.originPrincipalId && resp.originPrincipalId !== pending.expectedPrincipalId) {
          appendAuditLog({
            type: "rpc_response_origin_mismatch",
            timestamp: Date.now(),
            expectedPrincipalId: pending.expectedPrincipalId,
            actualPrincipalId: resp.originPrincipalId,
          });
          return;
        }
        clearTimeout(pending.timeout);
        this.pendingRpcRequests.delete(resp.id);
        pending.resolve(resp);
      }
      return;
    }

    if (msg.type === "file_ack") {
      const ack = msg as FileAckMsg;
      const pending = this.pendingFileAcks.get(ack.transferId);
      if (pending) {
        if (pending.expectedPrincipalId && ack.originPrincipalId && ack.originPrincipalId !== pending.expectedPrincipalId) {
          appendAuditLog({
            type: "file_ack_origin_mismatch",
            timestamp: Date.now(),
            expectedPrincipalId: pending.expectedPrincipalId,
            actualPrincipalId: ack.originPrincipalId,
          });
          return;
        }
        clearTimeout(pending.timeout);
        this.pendingFileAcks.delete(ack.transferId);
        pending.resolve(ack);
      }
      return;
    }

    if (msg.type === "compact_response") {
      const cResp = msg as CompactResponseMsg;
      const pending = this.pendingCompactRequests.get(cResp.id);
      if (pending) {
        if (pending.expectedPrincipalId && cResp.originPrincipalId && cResp.originPrincipalId !== pending.expectedPrincipalId) {
          appendAuditLog({
            type: "compact_response_origin_mismatch",
            timestamp: Date.now(),
            expectedPrincipalId: pending.expectedPrincipalId,
            actualPrincipalId: cResp.originPrincipalId,
          });
          return;
        }
        clearTimeout(pending.timeout);
        this.pendingCompactRequests.delete(cResp.id);
        pending.resolve(cResp);
      }
      return;
    }

    if (msg.type === "file_offer") {
      const offer = msg as FileOfferMsg;
      const res = this.transferReceiver.handleOffer(offer, this.currentSessionId);
      if (!res.ok) {
        this.sendToHub({
          type: "file_ack",
          version: 5,
          id: `ack-${offer.transferId}`,
          transferId: offer.transferId,
          from: this.terminalName,
          to: offer.from || "hub",
          ok: false,
          error: res.error,
          ts: Date.now(),
        } as FileAckMsg);
      }
      return;
    }

    if (msg.type === "file_chunk") {
      const chunk = msg as FileChunkMsg;
      const res = this.transferReceiver.handleChunk(chunk);
      if (res.complete || !res.ok) {
        this.sendToHub({
          type: "file_ack",
          version: 5,
          id: `ack-${chunk.transferId}`,
          transferId: chunk.transferId,
          from: this.terminalName,
          to: chunk.from || "hub",
          ok: res.ok,
          error: res.error,
          ts: Date.now(),
        } as FileAckMsg);
      }
      return;
    }

    if (msg.type === "rpc_request") {
      await this.handleLocalRpcRequest(msg as RpcRequestMsg, this.clientWs, this.clientContext);
      return;
    }

    if (msg.type === "compact_request") {
      let ok = true;
      let reason: string | undefined;
      if (this.onCompactRequest) {
        try {
          const cRes = await this.onCompactRequest(msg as CompactRequestMsg);
          ok = cRes.ok;
          reason = cRes.reason;
        } catch (err: any) {
          ok = false;
          reason = err.message;
        }
      }
      this.sendToHub({
        type: "compact_response",
        version: 5,
        id: msg.id,
        from: this.terminalName,
        to: msg.from,
        ok,
        reason,
        ts: Date.now(),
      } as CompactResponseMsg);
      return;
    }

    if (msg.type === "chat" || msg.type === "direct_message") {
      if (this.onMessage) this.onMessage(msg as ApplicationMessage);
      return;
    }
  }

  private persistPairedHubIdentity(hubPrincipalId?: string): void {
    try {
      const peerCert = this.capturedServerCert || extractPeerCertificate((this.clientWs as any)?._socket);
      if (peerCert) {
        const canonicalFp = normalizeFingerprint(peerCert.fingerprint);
        const pairedHub: PairedDevice = {
          principalId: hubPrincipalId || peerCert.principalId,
          fingerprint: canonicalFp,
          certPem: peerCert.certPem,
          deviceName: hubPrincipalId || "hub",
          permissions: FULL_PERMISSIONS,
          pairedAt: Date.now(),
          lastSeen: Date.now(),
          lastAddress: this.clientWs?.url,
        };
        savePairedDevice(pairedHub, this.customOmpDir);
        if (this.clientContext) {
          this.clientContext.principalId = pairedHub.principalId;
          this.clientContext.permissions = pairedHub.permissions;
        }
      }
    } catch {}
  }

  // ── Operations & Helper Methods ───────────────────────────────────────────

  public sendMessage(to: string, text: string): boolean {
    const isBroadcast = to === "*";
    const msg: ApplicationMessage = {
      type: isBroadcast ? "chat" : "direct_message",
      version: 5,
      id: crypto.randomUUID(),
      from: this.terminalName,
      originPrincipalId: this.identity.principalId,
      to,
      toPrincipalId: to.startsWith("ed25519-") ? to : undefined,
      text,
      ts: Date.now(),
    };

    if (this.role === "hub") {
      if (isBroadcast) {
        this.broadcastToOthers(null, msg);
        return true;
      }
      for (const [s, c] of this.hubConnections) {
        if (c.phase === "authenticated" && (c.displayName === to || c.principalId === to)) {
          msg.toPrincipalId = c.principalId;
          this.sendApplicationFrame(s, c, msg);
          return true;
        }
      }
      return false;
    } else if (this.role === "client" && this.clientWs && this.clientContext) {
      this.sendApplicationFrame(this.clientWs, this.clientContext, msg);
      return true;
    }
    return false;
  }

  public async executeRemoteRpc(
    to: string,
    action: string,
    params: any = {},
  ): Promise<RpcResponseMsg> {
    const id = crypto.randomUUID();
    let expectedPrincipalId: string | undefined;

    if (this.role === "hub") {
      for (const [_, c] of this.hubConnections) {
        if (c.phase === "authenticated" && (c.displayName === to || c.principalId === to)) {
          expectedPrincipalId = c.principalId;
          break;
        }
      }
    } else if (to.startsWith("ed25519-")) {
      expectedPrincipalId = to;
    }

    const msg: RpcRequestMsg = {
      type: "rpc_request",
      version: 5,
      id,
      from: this.terminalName,
      originPrincipalId: this.identity.principalId,
      to,
      toPrincipalId: expectedPrincipalId,
      action,
      params,
      ts: Date.now(),
    };

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRpcRequests.delete(id);
        reject(new Error(`RPC request to "${to}" timed out after 30s`));
      }, 30_000);

      this.pendingRpcRequests.set(id, { expectedPrincipalId, resolve, reject, timeout });

      if (this.role === "hub") {
        let sent = false;
        for (const [s, c] of this.hubConnections) {
          if (c.phase === "authenticated" && (c.displayName === to || c.principalId === to)) {
            this.sendApplicationFrame(s, c, msg);
            sent = true;
            break;
          }
        }
        if (!sent) {
          clearTimeout(timeout);
          this.pendingRpcRequests.delete(id);
          reject(new Error(`Peer "${to}" not found`));
        }
      } else if (this.role === "client" && this.clientWs && this.clientContext) {
        this.sendApplicationFrame(this.clientWs, this.clientContext, msg);
      } else {
        clearTimeout(timeout);
        this.pendingRpcRequests.delete(id);
        reject(new Error("Node not connected"));
      }
    });
  }

  public async requestCompact(
    to: string,
    instructions?: string,
  ): Promise<CompactResponseMsg> {
    const id = crypto.randomUUID();
    let expectedPrincipalId: string | undefined;

    if (this.role === "hub") {
      for (const [_, c] of this.hubConnections) {
        if (c.phase === "authenticated" && (c.displayName === to || c.principalId === to)) {
          expectedPrincipalId = c.principalId;
          break;
        }
      }
    } else if (to.startsWith("ed25519-")) {
      expectedPrincipalId = to;
    }

    const msg: CompactRequestMsg = {
      type: "compact_request",
      version: 5,
      id,
      from: this.terminalName,
      originPrincipalId: this.identity.principalId,
      to,
      toPrincipalId: expectedPrincipalId,
      instructions,
      ts: Date.now(),
    };

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingCompactRequests.delete(id);
        reject(new Error(`Compact request to "${to}" timed out after 180s`));
      }, 180_000);

      this.pendingCompactRequests.set(id, { expectedPrincipalId, resolve, reject, timeout });

      if (this.role === "hub") {
        let sent = false;
        for (const [s, c] of this.hubConnections) {
          if (c.phase === "authenticated" && (c.displayName === to || c.principalId === to)) {
            this.sendApplicationFrame(s, c, msg);
            sent = true;
            break;
          }
        }
        if (!sent) {
          clearTimeout(timeout);
          this.pendingCompactRequests.delete(id);
          reject(new Error(`Peer "${to}" not online`));
        }
      } else if (this.role === "client" && this.clientWs && this.clientContext) {
        this.sendApplicationFrame(this.clientWs, this.clientContext, msg);
      } else {
        clearTimeout(timeout);
        this.pendingCompactRequests.delete(id);
        reject(new Error("Node not connected"));
      }
    });
  }

  public async sendFile(to: string, filePath: string): Promise<{ ok: boolean; error?: string }> {
    const outboundCheck = validateOutboundFile(
      this.workspaceRoot,
      filePath,
      this.customOmpDir ? [this.customOmpDir] : [],
    );
    if (!outboundCheck.allowed) {
      return { ok: false, error: outboundCheck.reason };
    }
    const realFilePath = outboundCheck.canonicalPath || filePath;

    const hashInfo = await computeFileHashStreaming(realFilePath);
    const transferId = crypto.randomUUID();
    const filename = path.basename(realFilePath);

    let targetPrincipalId: string | undefined;
    let targetSocket: any = null;
    let targetCtx: ConnectionContext | null = null;

    if (this.role === "hub") {
      for (const [s, c] of this.hubConnections) {
        if (c.phase === "authenticated" && (c.displayName === to || c.principalId === to)) {
          targetSocket = s;
          targetCtx = c;
          targetPrincipalId = c.principalId;
          break;
        }
      }
      if (!targetSocket || !targetCtx) return { ok: false, error: `Peer "${to}" not online` };
    } else if (this.role === "client" && this.clientWs && this.clientContext) {
      targetSocket = this.clientWs;
      targetCtx = this.clientContext;
    } else {
      return { ok: false, error: "Not connected" };
    }

    const offer: FileOfferMsg = {
      type: "file_offer",
      version: 5,
      id: crypto.randomUUID(),
      transferId,
      from: this.terminalName,
      originPrincipalId: this.identity.principalId,
      to,
      toPrincipalId: targetPrincipalId,
      filename,
      sizeBytes: hashInfo.sizeBytes,
      totalChunks: hashInfo.totalChunks,
      sha256: hashInfo.sha256,
      ts: Date.now(),
    };

    const ackPromise = new Promise<FileAckMsg>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingFileAcks.delete(transferId);
        reject(new Error(`Transfer ack timeout for "${transferId}"`));
      }, 60_000);
      this.pendingFileAcks.set(transferId, { expectedPrincipalId: targetPrincipalId, resolve, reject, timeout });
    });

    this.sendApplicationFrame(targetSocket, targetCtx, offer);

    const sendChunkFn = (chunk: FileChunkMsg) => {
      chunk.originPrincipalId = this.identity.principalId;
      chunk.toPrincipalId = targetPrincipalId;
      if (this.role === "hub") {
        if (targetSocket && targetCtx && targetCtx.phase === "authenticated") {
          this.sendApplicationFrame(targetSocket, targetCtx, chunk);
          return true;
        }
        return false;
      } else if (this.role === "client" && this.clientWs && this.clientContext) {
        this.sendApplicationFrame(this.clientWs, this.clientContext, chunk);
        return true;
      }
      return false;
    };

    await streamFileChunks(
      realFilePath,
      transferId,
      this.terminalName,
      to,
      hashInfo.totalChunks,
      sendChunkFn,
      () => (targetSocket as any)?.bufferedAmount || 0,
    );

    const finalAck = await ackPromise;
    return { ok: finalAck.ok, error: finalAck.error };
  }

  public async sendBounded(
    socket: any,
    msg: WireMessage,
    highWaterMark = 512 * 1024,
  ): Promise<void> {
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      throw new Error("Socket is not open");
    }
    while ((socket.bufferedAmount || 0) > highWaterMark) {
      await new Promise((resolve) => setTimeout(resolve, 20));
      if (socket.readyState !== WebSocket.OPEN) {
        throw new Error("Socket closed during sendBounded");
      }
    }
    const data = JSON.stringify(msg);
    return new Promise<void>((resolve, reject) => {
      socket.send(data, (err: any) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  public sendHandshakeFrame(socket: any, ctx: ConnectionContext, msg: WireMessage): void {
    if (ctx.phase === "authenticated") {
      throw new Error(`Handshake frame "${msg.type}" strictly forbidden after connection is authenticated`);
    }
    this.sendToSocket(socket, msg);
  }

  public sendApplicationFrame(socket: any, ctx: ConnectionContext, msg: WireMessage): void {
    if (ctx.phase !== "authenticated") {
      throw new Error(`Application frame "${msg.type}" strictly forbidden before connection is authenticated`);
    }
    this.sendToSocket(socket, msg);
  }

  private sendToSocket(socket: any, msg: WireMessage): void {
    try {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify(msg));
      }
    } catch {}
  }

  private sendToHub(msg: WireMessage): void {
    if (this.clientWs && this.clientContext) {
      if (this.clientContext.phase === "authenticated") {
        this.sendApplicationFrame(this.clientWs, this.clientContext, msg);
      } else {
        this.sendHandshakeFrame(this.clientWs, this.clientContext, msg);
      }
    }
  }

  private broadcastToOthers(excludeSocket: any, msg: WireMessage): void {
    for (const [socket, ctx] of this.hubConnections) {
      if (socket !== excludeSocket && ctx.phase === "authenticated") {
        this.sendApplicationFrame(socket, ctx, msg);
      }
    }
  }

  private broadcastTerminalList(): void {
    const list = this.getConnectedTerminalsList();
    const updateMsg: WireMessage = {
      type: "status_update",
      version: 5,
      id: `terms-${Date.now()}`,
      from: this.terminalName,
      status: { terminals: list.map((t) => t.name) },
      ts: Date.now(),
    };
    this.broadcastToOthers(null, updateMsg);

    if (this.onTerminalsChanged) {
      this.onTerminalsChanged(list.map((t) => t.name));
    }
  }

  public getConnectedTerminalsList(): Array<{ name: string; host?: string; cwd?: string; status?: string }> {
    const res: Array<{ name: string; host?: string; cwd?: string; status?: string }> = [
      { name: this.terminalName, host: os.hostname(), cwd: process.cwd(), status: "idle" },
    ];
    for (const [_, ctx] of this.hubConnections) {
      if (ctx.phase === "authenticated") {
        res.push({
          name: ctx.displayName,
          host: ctx.remoteAddress,
          status: this.terminalStatuses.get(ctx.displayName)?.status || "idle",
        });
      }
    }
    return res;
  }

  public async stop(): Promise<void> {
    revokeAllGrants("Link stopping");
    this.transferReceiver.abortAllTransfers();
    this.activeRpcsByPeer.clear();

    for (const [_, p] of this.pendingRpcRequests) {
      clearTimeout(p.timeout);
      p.reject(new Error("Link stopped"));
    }
    this.pendingRpcRequests.clear();

    for (const [_, p] of this.pendingCompactRequests) {
      clearTimeout(p.timeout);
      p.reject(new Error("Link stopped"));
    }
    this.pendingCompactRequests.clear();

    for (const [_, p] of this.pendingFileAcks) {
      clearTimeout(p.timeout);
      p.reject(new Error("Link stopped"));
    }
    this.pendingFileAcks.clear();

    for (const [_, req] of this.pendingPairRequests) {
      clearTimeout(req.timer);
    }
    this.pendingPairRequests.clear();

    if (this.udpSocket) {
      try { this.udpSocket.close(); } catch {}
      this.udpSocket = null;
    }

    if (this.wss) {
      for (const socket of this.wss.clients) {
        try { socket.close(1000, "Link shutting down"); } catch {}
      }
      this.wss.close();
      this.wss = null;
    }

    if (this.httpsServer) {
      await new Promise<void>((resolve) => {
        this.httpsServer!.close(() => resolve());
      });
      this.httpsServer = null;
    }

    if (this.clientWs) {
      const ws = this.clientWs;
      this.clientWs = null;
      this.clientContext = null;
      try {
        ws.removeAllListeners();
        ws.close(1000, "Disconnected");
      } catch {}
    }

    this.hubConnections.clear();
    this.role = "disconnected";
  }
}
