import * as crypto from "node:crypto";
import * as os from "node:os";
import * as path from "node:path";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { type TLSSocket } from "node:tls";
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
  deriveLocalSas,
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
  markConnectionAlive,
  setConnectionPhase,
  cleanupConnectionContext,
} from "./connection-state.js";

import {
  isActionPermitted,
  isCorrelatedResponse,
  bindMessageOrigin,
  checkAndConsumeExecGrant,
  revokeGrantsForPrincipal,
  revokeAllGrants,
  getActiveGrants,
  updateDevicePermissions,
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
import { type LinkTimings, getTimings } from "./config.js";

export interface LinkNodeOptions {
  customOmpDir?: string;
  port?: number;
  bindHost?: string;
  networkMode?: "lan" | "tailscale" | "loopback";
  terminalName?: string;
  sessionId?: string;
  /** Opaque room identity. Generated when hosting a new room; supplied when rejoining a known one. */
  roomId?: string;
  allowRemoteExec?: boolean;
  workspaceRoot?: string;
}

export type NodeRole = "hub" | "client" | "disconnected";

/** One running terminal in a room. Identity is the pair; `name` is a mutable label. */
export interface TerminalDescriptor {
  principalId: string;
  agentInstanceId: string;
  name: string;
  workspaceLabel?: string;
  isSelf?: boolean;
}

/**
 * What a connection attempt actually achieved. "Connected" is not a synonym for "socket open":
 * a caller must be able to tell an admitted agent from one still waiting to be verified.
 */
export type ConnectOutcome =
  | { state: "authenticated" }
  | { state: "pairing-required"; sasCode: string };

/**
 * How long stop() waits for peers to answer their close frame before dropping their sockets.
 * `ws` would otherwise hold each unanswered close for its own 30 s timeout, and the HTTPS
 * server's close callback waits on those sockets — so quitting a terminal would stall 30 s.
 */
const CLOSE_HANDSHAKE_GRACE_MS = 250;

/** Upper bound on a hub-published roster. Membership feeds routing, so it is never unbounded. */
const MAX_ROSTER_ENTRIES = 64;

/** Ceiling on distinct rate-limit keys before stale buckets are swept. */
const MAX_RATE_LIMIT_KEYS = 1024;

// ── Liveness ──────────────────────────────────────────────────────────────────
// Timings come from `getTimings(customOmpDir)` in src/config.ts — keys `heartbeatIntervalMs`
// (15 s), `heartbeatMissesBeforeDrop` (2) and `clientHubSilenceTimeoutMs` (45 s). Nothing in
// this file hardcodes a liveness number; an operator retunes them in link.json.
//
// Semantics: every interval a side sends a WebSocket ping. Any inbound traffic — a pong OR any
// frame — marks the peer alive. A hub drops a peer once `heartbeatMissesBeforeDrop` whole
// intervals pass with nothing inbound at all (30 s by default). The client's own deadline is
// deliberately longer: a client that declares its hub dead too eagerly triggers local hub
// succession, and a spurious takeover is worse than 15 s of stale roster.

/** Close code for a peer that stopped answering. 4408 is this protocol's "timed out". */
const CLOSE_CODE_LIVENESS_TIMEOUT = 4408;

/** Close code for a connection replaced by a newer one from the same agent instance. */
const CLOSE_CODE_SUPERSEDED = 4409;

/**
 * A WebSocket close reason must fit in 123 bytes; `ws` throws a RangeError otherwise — inside
 * the same synchronous socket callback that is trying to report the problem, which kills the
 * process. Some reasons quote peer-supplied text (an unrecognised message type), so every close
 * in this file goes through `closeSocket`.
 */
function truncateCloseReason(reason: string): string {
  if (Buffer.byteLength(reason, "utf8") <= 123) return reason;
  const head = Buffer.from(reason, "utf8").subarray(0, 120).toString("utf8").replace(/\uFFFD+$/, "");
  return `${head}...`;
}

function closeSocket(socket: WebSocket | null | undefined, code: number, reason?: string): void {
  if (!socket) return;
  try {
    socket.close(code, reason === undefined ? undefined : truncateCloseReason(reason));
  } catch {}
}

function extractTlsSocket(ws: WebSocket | null | undefined): TLSSocket | null {
  if (!ws) return null;
  // `ws` exposes the live TLS socket only through an internal field: there is no public
  // accessor, and no runtime check could establish more than its presence.
  const internals = ws as unknown as { _socket?: TLSSocket };
  return internals._socket ?? null;
}

export class LinkNode {
  public identity: DeviceIdentity;
  public role: NodeRole = "disconnected";

  /**
   * Identifies this running terminal. The device principal is shared by every terminal on a
   * machine, so authorization and routing key on the pair (principalId, agentInstanceId).
   */
  public readonly agentInstanceId: string = crypto.randomUUID();

  /** Opaque room identity. A room is (roomId, hub principalId) — never a display label. */
  public roomId: string;

  /** Roster as reported by the hub. Clients have no inbound connections of their own. */
  private hubRoster: TerminalDescriptor[] = [];

  /** Settles the in-flight connectToHub() promise once the handshake reaches a real verdict. */
  private clientConnectSettle?: (outcome?: ConnectOutcome, err?: Error) => void;

  public get isAuthenticated(): boolean {
    if (this.role === "hub") return true;
    return this.clientContext?.phase === "authenticated";
  }

  /** The verified certificate of the hub this agent is connected to, or null. */
  public getHubIdentity(): PeerCertificateInfo | null {
    return this.role === "client" ? this.capturedServerCert : null;
  }

  /**
   * The TLS version actually negotiated on the live socket. Diagnostics must report what was
   * measured, not what the implementation intends.
   */
  public getNegotiatedProtocol(): string | null {
    const socket = extractTlsSocket(this.clientWs);
    return socket?.getProtocol?.() ?? null;
  }
  public currentSessionId: string;
  public terminalName: string;
  public port: number;
  public bindHost: string;
  public networkMode: "lan" | "tailscale" | "loopback";
  public customOmpDir?: string;
  public allowRemoteExec: boolean;
  public workspaceRoot: string;

  /**
   * Operational timings, read once from `link.json` at construction. Every value is already
   * validated and floored by `getTimings`, so nothing here re-clamps; editing link.json takes
   * effect on the next terminal start.
   */
  private readonly timings: LinkTimings;

  // Rate limiting maps: IP -> timestamp[]
  private connectionRateMap = new Map<string, number[]>();
  private pairingRateMap = new Map<string, number[]>();

  /**
   * Liveness sweepers. Deliberately not `unref()`d: a leaked interval must keep the process
   * alive so a lifecycle test can see it, rather than hiding a teardown bug behind the event
   * loop. `stop()` clears both.
   */
  private hubHeartbeatTimer: NodeJS.Timeout | null = null;
  private clientHeartbeatTimer: NodeJS.Timeout | null = null;

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
  /**
   * Fired when the hub connection of a client node goes away, after local state is cleared.
   * The host decides whether that loss is worth acting on (local hub succession) or expected
   * (a deliberate `/link off`) — this node only reports it.
   */
  public onHubDisconnected?: () => void;
  public onNotification?: (msg: string, level: "info" | "warning" | "error") => void;
  public onCompactRequest?: (msg: CompactRequestMsg) => Promise<{ ok: boolean; reason?: string }>;

  constructor(options: LinkNodeOptions = {}) {
    this.customOmpDir = options.customOmpDir;
    this.identity = getOrCreateDeviceIdentity(this.customOmpDir);
    this.timings = getTimings(this.customOmpDir);
    // `?? `, not `||`: port 0 means "bind an ephemeral port", and startHub() writes the real
    // port back to this.port once listening.
    this.port = options.port ?? DEFAULT_PORT;
    this.bindHost = options.bindHost || "0.0.0.0";
    this.networkMode = options.networkMode || "lan";
    this.terminalName = options.terminalName || this.identity.deviceName;
    this.currentSessionId = options.sessionId || "team-link";
    this.roomId = options.roomId || crypto.randomUUID();
    this.allowRemoteExec = options.allowRemoteExec ?? false;
    this.workspaceRoot = options.workspaceRoot || process.cwd();
    this.transferReceiver = new TransferReceiver(this.customOmpDir);

    // Register canonical workspace root
    try {
      registerWorkspace({ id: "default", rootDir: this.workspaceRoot });
    } catch {}
  }

  // ── Hub Lifecycle ─────────────────────────────────────────────────────────

  /**
   * Sliding-window limiter. Empty buckets are dropped and the map is capped: a long-lived hub on
   * a Tailnet otherwise accumulates one entry per source address it has ever seen.
   */
  private checkRateLimit(map: Map<string, number[]>, key: string | undefined, maxPerWindow: number, windowMs = 60_000): boolean {
    const safeKey = key || "unknown";
    const now = Date.now();
    const timestamps = (map.get(safeKey) || []).filter((t) => now - t < windowMs);
    if (timestamps.length >= maxPerWindow) {
      map.set(safeKey, timestamps);
      return false;
    }
    timestamps.push(now);
    map.set(safeKey, timestamps);

    if (map.size > MAX_RATE_LIMIT_KEYS) {
      for (const [k, stamps] of map) {
        if (stamps.length === 0 || now - stamps[stamps.length - 1] >= windowMs) map.delete(k);
      }
    }
    return true;
  }

  // ── Liveness ──────────────────────────────────────────────────────────────
  //
  // A TCP connection outlives its peer. A SIGKILLed agent on the same host resets promptly, but
  // a suspended process, a closed laptop lid or a dropped Wi-Fi link leaves an established
  // socket that neither end will notice for minutes, and a hub with no keepalive keeps naming
  // that agent in `link_list` the whole time. Worse, a SIGSTOPped process still ACKs at the TCP
  // layer, so nothing below the application can tell it apart from an idle peer — only an
  // unanswered WebSocket ping can.

  /** Arms the hub-side sweeper. Idempotent: restarting a hub never stacks two intervals. */
  private startHubHeartbeat(): void {
    this.stopHubHeartbeat();
    this.hubHeartbeatTimer = setInterval(() => {
      try {
        this.sweepHubLiveness();
      } catch {
        // A sweep is best-effort maintenance. It runs on a bare timer callback, where a throw
        // has no caller and would take the host process down.
      }
    }, this.timings.heartbeatIntervalMs);
  }

  private stopHubHeartbeat(): void {
    if (this.hubHeartbeatTimer) {
      clearInterval(this.hubHeartbeatTimer);
      this.hubHeartbeatTimer = null;
    }
  }

  /**
   * Pings every authenticated peer and drops the ones that have gone quiet. Connections that
   * have not authenticated yet are the handshake deadline's business, not this sweep's.
   */
  private sweepHubLiveness(): void {
    const deadlineMs = this.timings.heartbeatIntervalMs * this.timings.heartbeatMissesBeforeDrop;
    const now = Date.now();
    // Snapshot: dropping a peer mutates hubConnections while we are walking it.
    for (const [socket, ctx] of [...this.hubConnections]) {
      if (ctx.phase !== "authenticated") continue;

      const silentMs = now - ctx.lastInboundAt;
      if (silentMs > deadlineMs) {
        appendAuditLog({
          type: "peer_liveness_timeout",
          timestamp: now,
          roomId: this.roomId,
          principalId: ctx.principalId,
          agentInstanceId: ctx.agentInstanceId,
          peer: ctx.displayName,
          silentMs,
        });
        this.onNotification?.(
          `"${ctx.displayName}" stopped responding (${Math.round(silentMs / 1000)}s) and was removed from the room.`,
          "warning",
        );
        this.dropHubConnection(
          socket,
          ctx,
          CLOSE_CODE_LIVENESS_TIMEOUT,
          `No response for ${Math.round(deadlineMs / 1000)}s`,
        );
        continue;
      }

      try {
        if (socket.readyState === WebSocket.OPEN) socket.ping();
      } catch {}
    }
  }

  /**
   * Removes a hub-side connection now, without waiting for a close handshake the peer may never
   * answer. The close frame is written first so a peer that is merely frozen learns why when it
   * thaws, then teardown runs immediately and the socket is dropped: `ws` would otherwise hold
   * an unanswered close for its own 30 s timeout, and the roster must be honest before that.
   */
  private dropHubConnection(socket: WebSocket, ctx: ConnectionContext, code: number, reason: string): void {
    closeSocket(socket, code, reason);
    this.handleHubSocketClose(socket, ctx);
    try { socket.terminate(); } catch {}
  }

  /**
   * A terminal that reconnects — after a crash, a sleep, or a network flap — presents the same
   * `agentInstanceId`. Its previous connection may still look alive to this hub, and leaving it
   * in place double-counts the agent in the roster, splits routing between two sockets by
   * display name, and keeps the dead connection's exec grants. The newcomer proved possession of
   * the same device key on a fresh TLS session, so the older context is evicted.
   */
  private evictSupersededInstance(socket: WebSocket, principalId: string, agentInstanceId: string | undefined): void {
    if (!agentInstanceId) return;
    for (const [otherSocket, otherCtx] of [...this.hubConnections]) {
      if (otherSocket === socket) continue;
      if (otherCtx.principalId !== principalId) continue;
      if (otherCtx.agentInstanceId !== agentInstanceId) continue;
      appendAuditLog({
        type: "peer_connection_superseded",
        timestamp: Date.now(),
        roomId: this.roomId,
        principalId,
        agentInstanceId,
        peer: otherCtx.displayName,
      });
      this.dropHubConnection(
        otherSocket,
        otherCtx,
        CLOSE_CODE_SUPERSEDED,
        "Superseded by a newer connection from the same agent",
      );
    }
  }

  /** Arms the client-side sweeper against the hub. Idempotent. */
  private startClientHeartbeat(): void {
    this.stopClientHeartbeat();
    this.clientHeartbeatTimer = setInterval(() => {
      try {
        this.sweepClientLiveness();
      } catch {}
    }, this.timings.heartbeatIntervalMs);
  }

  private stopClientHeartbeat(): void {
    if (this.clientHeartbeatTimer) {
      clearInterval(this.clientHeartbeatTimer);
      this.clientHeartbeatTimer = null;
    }
  }

  /**
   * The client half of the same check. A hub that has gone silent must move this node to
   * `disconnected` rather than leave it reporting a room it can no longer reach — that
   * transition is what fires `onHubDisconnected`, and local hub succession hangs off it.
   */
  private sweepClientLiveness(): void {
    const ws = this.clientWs;
    const ctx = this.clientContext;
    if (!ws || !ctx) {
      this.stopClientHeartbeat();
      return;
    }

    const silentMs = Date.now() - ctx.lastInboundAt;
    if (silentMs > this.timings.clientHubSilenceTimeoutMs) {
      appendAuditLog({
        type: "hub_liveness_timeout",
        timestamp: Date.now(),
        roomId: this.roomId,
        principalId: ctx.principalId,
        silentMs,
      });
      this.onNotification?.(
        `Lost contact with the link hub (silent for ${Math.round(silentMs / 1000)}s). Disconnected.`,
        "warning",
      );
      // Tear down with the real reason before dropping the socket: an in-flight caller told
      // only "connection closed" would go looking for a close nobody sent. The subsequent
      // "close" event is then a no-op, and terminate() rather than close() because a hub that
      // is not answering will not answer a close handshake either.
      this.finalizeClientDisconnect(
        ws,
        `Hub stopped responding (silent for ${Math.round(silentMs / 1000)}s)`,
      );
      try { ws.terminate(); } catch {}
      return;
    }

    try {
      if (ws.readyState === WebSocket.OPEN) ws.ping();
    } catch {}
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
              roomId: this.roomId,
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

      // One idempotent handler on BOTH emitters. `ws` forwards the underlying server's "error"
      // to the WebSocketServer (ws/lib/websocket-server.js), so an unhandled wss "error" kills
      // the host process on EADDRINUSE. Neither the promise executor nor a try/catch around
      // listen() can catch it: it is emitted on a later tick.
      let listening = false;
      let startupError: NodeJS.ErrnoException | null = null;

      const handleServerError = (err: NodeJS.ErrnoException): void => {
        if (listening) {
          // Runtime failure after a successful start. Rejecting a settled promise does nothing;
          // transition state and tear down instead.
          appendAuditLog({
            type: "hub_server_error",
            timestamp: Date.now(),
            roomId: this.roomId,
            port: this.port,
            code: err.code,
            message: err.message,
          });
          this.onNotification?.(`Link hub transport error: ${err.code || err.message}`, "error");
          void this.stop();
          return;
        }
        // Startup failure. Both emitters report the same error; only the first one counts.
        if (startupError) return;
        startupError = err;
        appendAuditLog({
          type: "hub_start_failed",
          timestamp: Date.now(),
          roomId: this.roomId,
          port: this.port,
          bindHost: this.bindHost,
          code: err.code,
          message: err.message,
        });
        const failedWss = this.wss;
        const failedHttps = this.httpsServer;
        this.wss = null;
        this.httpsServer = null;
        this.role = "disconnected";
        try { failedWss?.close(); } catch {}
        try { failedHttps?.close(); } catch {}
        reject(err);
      };

      this.httpsServer.on("error", handleServerError);

      this.wss = new WebSocketServer({
        server: this.httpsServer,
        maxPayload: 2 * 1024 * 1024,
        perMessageDeflate: false,
      });
      this.wss.on("error", handleServerError);

      this.wss.on("connection", (socket, req) => {
        this.handleHubInboundConnection(socket, req);
      });

      // listen() reports failure through the "error" event, never synchronously.
      this.httpsServer.listen(this.port, this.bindHost, () => {
        listening = true;
        this.role = "hub";
        const bound = this.httpsServer?.address();
        if (bound && typeof bound === "object") this.port = bound.port;
        if (this.networkMode === "lan") {
          this.udpSocket = startUdpDiscoveryResponder(this.port, {
            bindHost: this.bindHost,
            enabled: true,
          });
        } else {
          this.udpSocket = null;
        }
        this.startHubHeartbeat();
        appendAuditLog({
          type: "hub_started",
          timestamp: Date.now(),
          roomId: this.roomId,
          port: this.port,
          principalId: this.identity.principalId,
          agentInstanceId: this.agentInstanceId,
          bindHost: this.bindHost,
          networkMode: this.networkMode,
        });
        resolve();
      });
    });
  }

  private handleHubInboundConnection(socket: any, req: any): void {
    const remoteAddress = req.socket?.remoteAddress || "unknown";

    // Rate limit connections per IP (max 60/min)
    if (!this.checkRateLimit(this.connectionRateMap, remoteAddress, 60)) {
      closeSocket(socket, 4429, "Connection rate limit exceeded");
      return;
    }

    const peerCert = extractPeerCertificate(req.socket);
    if (!peerCert) {
      // Mutual TLS required
      closeSocket(socket, 4403, "Mutual TLS client certificate required");
      return;
    }

    const ctx = createConnectionContext({
      socket,
      remoteAddress,
      peerCert,
      isLocal: remoteAddress === "127.0.0.1" || remoteAddress === "::1",
      handshakeTimeoutMs: this.timings.handshakeTimeoutMs,
      onHandshakeTimeout: () => {
        closeSocket(socket, 4408, `Handshake timeout (${Math.round(this.timings.handshakeTimeoutMs / 1000)}s)`);
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

    // `ws` answers an inbound ping itself, so a peer only stops ponging when its process is
    // gone or wedged — which is exactly the case a TCP-level check cannot see.
    socket.on("pong", () => {
      markConnectionAlive(ctx);
    });

    socket.on("close", () => {
      this.handleHubSocketClose(socket, ctx);
    });

    socket.on("error", () => {
      this.handleHubSocketClose(socket, ctx);
    });
  }

  /**
   * The single inbound authorization pipeline. Both roles MUST run it: a relay's permission to
   * carry a message never grants the sender access to the receiver's files, so a client applies
   * exactly the same gates to traffic arriving from its hub as the hub applies to its peers.
   *
   * Order is the security model: dedupe -> capability -> authoritative origin.
   * Returns the origin-bound message, or null when the frame was rejected.
   */
  private gateInboundApplicationMessage(
    socket: WebSocket,
    ctx: ConnectionContext,
    appMsg: ApplicationMessage,
  ): ApplicationMessage | null {
    if (!checkMessageDeduplication(ctx, appMsg.id)) return null;

    // Correlated responses are authorized by their pending request, not by a standing
    // capability. Gating them here would drop a denied peer's error reply and hang the caller
    // until its timeout instead of failing fast.
    if (isCorrelatedResponse(appMsg)) {
      return this.attributeOrigin(ctx, appMsg);
    }

    const permCheck = isActionPermitted(ctx.permissions, appMsg);
    if (!permCheck.permitted) {
      appendAuditLog({
        type: "authorization_denied",
        timestamp: Date.now(),
        roomId: this.roomId,
        principalId: ctx.principalId,
        agentInstanceId: this.agentInstanceId,
        action: appMsg.type,
        required: permCheck.required,
        reason: permCheck.reason,
      });
      this.sendDenial(socket, ctx, appMsg, permCheck.reason || "Access denied");
      return null;
    }

    return this.attributeOrigin(ctx, appMsg);
  }

  /**
   * A hub authenticates its peers directly, so it overwrites any claimed origin from the TLS
   * context. A client's only peer IS the hub: the hub's attribution of relayed traffic is the
   * attestation the star topology rests on, and rewriting it here would relabel every relayed
   * message as coming from the hub itself. The client instead verifies that attestation
   * against the roster when it matches a pending request.
   */
  private attributeOrigin(ctx: ConnectionContext, appMsg: ApplicationMessage): ApplicationMessage {
    return this.role === "hub" ? bindMessageOrigin(appMsg, ctx) : appMsg;
  }

  /**
   * Answer a refused request in its own protocol shape. A denial delivered as a chat frame
   * never matches the caller's pending map, so the caller waits out its full timeout instead
   * of learning it was refused.
   */
  private sendDenial(
    socket: WebSocket,
    ctx: ConnectionContext,
    appMsg: ApplicationMessage,
    reason: string,
  ): void {
    const envelope = {
      version: PROTOCOL_VERSION,
      from: this.terminalName,
      originPrincipalId: this.identity.principalId,
      to: ctx.displayName,
      toPrincipalId: ctx.principalId,
      ok: false,
      ts: Date.now(),
    };

    // A denial must never throw: it is emitted from the inbound gate, which runs in a socket
    // callback, and the phase can already forbid application frames.
    if (appMsg.type === "rpc_request") {
      this.trySendApplicationFrame(socket, ctx, { ...envelope, type: "rpc_response", id: appMsg.id, error: reason } as WireMessage);
      return;
    }
    if (appMsg.type === "compact_request") {
      this.trySendApplicationFrame(socket, ctx, { ...envelope, type: "compact_response", id: appMsg.id, reason } as WireMessage);
      return;
    }
    if (appMsg.type === "file_offer" || appMsg.type === "file_chunk") {
      this.trySendApplicationFrame(socket, ctx, {
        ...envelope,
        type: "file_ack",
        id: `ack-${appMsg.transferId}`,
        transferId: appMsg.transferId,
        error: reason,
      } as WireMessage);
      return;
    }
    this.trySendApplicationFrame(socket, ctx, {
      ...envelope,
      type: "chat",
      id: crypto.randomUUID(),
      text: `[Access Denied] ${reason}`,
    } as WireMessage);
  }

  private handleHubSocketMessage(socket: any, ctx: ConnectionContext, rawData: any, req?: any): void {
    // A peer that is talking is a peer that is alive, whatever the frame turns out to be.
    markConnectionAlive(ctx);
    const parsed = parseWireMessage(rawData);
    if (!parsed.ok) {
      closeSocket(socket, parsed.closeCode, parsed.error);
      return;
    }

    const msg = parsed.message;

    // Phase validation
    const phaseCheck = validateMessagePhase(ctx, msg.type);
    if (!phaseCheck.allowed) {
      closeSocket(socket, phaseCheck.closeCode || 4403, phaseCheck.reason);
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
    // A handshake frame reaching this point has no branch above. Handing it to the application
    // gate answers the denial with an application frame in a pre-authenticated phase, and
    // `sendApplicationFrame` throws there — synchronously inside a socket callback, so an
    // unpaired peer could kill this process with one frame. Refuse the frame instead.
    if (HANDSHAKE_MESSAGE_TYPES.has(msg.type)) {
      appendAuditLog({
        type: "unexpected_handshake_frame",
        timestamp: Date.now(),
        roomId: this.roomId,
        principalId: ctx.principalId,
        remoteAddress: ctx.remoteAddress,
        messageType: msg.type,
        phase: ctx.phase,
      });
      closeSocket(socket, 4400, `Unexpected handshake frame "${msg.type}"`);
      return;
    }

    const appMsg = msg as ApplicationMessage;

    const boundMsg = this.gateInboundApplicationMessage(socket, ctx, appMsg);
    if (!boundMsg) return;

    this.routeApplicationMessage(socket, ctx, boundMsg);
  }

  /**
   * Names route messages, so no two devices may answer to one. Every entry point that sets
   * `ctx.displayName` goes through here: the handshake, and the moment an operator approves a
   * pairing. A collision suffixes the newcomer with a fingerprint stub and is audited, because
   * a silently renamed peer is a peer the operator will address by the wrong name.
   *
   * Two things the live-connection scan alone gets wrong:
   *
   * - **An offline device still owns its name.** `approvePairing` persists `deviceName`, and
   *   `handleHubClientHello` prefers the stored name for a known device. Checking only live
   *   sockets lets a newcomer be stored under an absent device's exact name; when that device
   *   returns, both are served the same routing key and the legitimate one is the one that
   *   gets suffixed. So the persisted store is part of the taken set.
   * - **`alice` and `alice\u200b` are the same name to a human.** `sanitizeDisplayName` strips
   *   control and CSI sequences but not format characters, so comparison is on an NFKC,
   *   format-stripped, case-folded key. The name the operator sees is still the one requested;
   *   only the collision test is normalised.
   */
  private uniqueDisplayName(
    preferred: string,
    socket: WebSocket,
    peerCert: PeerCertificateInfo,
    agentInstanceId: string | undefined,
  ): string {
    const canonicalFp = normalizeFingerprint(peerCert.fingerprint);
    const key = (name: string): string =>
      name.normalize("NFKC").replace(/\p{Cf}/gu, "").trim().toLowerCase();
    const wanted = key(preferred);

    let taken = false;
    for (const [s, c] of this.hubConnections) {
      if (s !== socket && c.phase === "authenticated" && c.agentInstanceId !== agentInstanceId && key(c.displayName) === wanted) {
        taken = true;
        break;
      }
    }
    if (!taken) {
      for (const [fp, device] of loadPairedDevices(this.customOmpDir)) {
        if (fp !== canonicalFp && key(device.deviceName) === wanted) {
          taken = true;
          break;
        }
      }
    }
    if (!taken) return preferred;

    const assigned = `${preferred}@${canonicalFp.replace(/:/g, "").slice(0, 6)}`;
    appendAuditLog({
      type: "display_name_collision",
      timestamp: Date.now(),
      roomId: this.roomId,
      principalId: peerCert.principalId,
      agentInstanceId,
      requested: preferred,
      assigned,
    });
    return assigned;
  }

  private handleHubClientHello(socket: any, ctx: ConnectionContext, msg: ClientHelloMsg, req?: any): void {
    ctx.helloReceived = true;
    const peerCert = ctx.peerCert!;
    const canonicalFp = normalizeFingerprint(peerCert.fingerprint);
    // Two terminals on one machine share a device certificate. They are distinct agents, and
    // the hub must be able to tell them apart for routing, grants and the roster.
    ctx.agentInstanceId = msg.agentInstanceId;
    ctx.workspaceLabel = msg.cwd ? path.basename(msg.cwd) : undefined;

    // Before anything is admitted or renamed: if this exact agent already holds a connection
    // here, that one is stale by definition — this hello arrived on a new TLS session from the
    // same terminal. Dropping it first keeps the roster and the display-name check honest.
    this.evictSupersededInstance(socket, peerCert.principalId, msg.agentInstanceId);

    // A display name is a routing key, so it must not be peer-asserted for a device we already
    // know. For a paired device the authoritative name is the one stored locally when the
    // operator approved it; the wire name is honoured only for a device with no local record,
    // i.e. during pairing, which is the one case where it is the operator's own input.
    const knownDevice = loadPairedDevices(this.customOmpDir).get(canonicalFp);
    ctx.displayName = this.uniqueDisplayName(
      knownDevice?.deviceName || msg.displayName,
      socket,
      peerCert,
      msg.agentInstanceId,
    );

    // Check one-time invite secret if provided
    if (msg.inviteSecret) {
      const inviteRes = verifyAndConsumeInvite(msg.inviteSecret);
      if (inviteRes.valid) {
        // Automatically pair and approve
        const paired: PairedDevice = {
          principalId: peerCert.principalId,
          fingerprint: canonicalFp,
          certPem: peerCert.certPem,
          deviceName: ctx.displayName,
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
          version: PROTOCOL_VERSION,
          roomId: this.roomId,
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

    // A peer presenting THIS device's own certificate is another terminal of the same user on
    // the same machine: it proved possession of this device's private key. Asking the user to
    // verify a code against themselves is theatre, and local compromise of the state directory
    // already defeats device identity (SECURITY.md, explicit non-goal). Distinct terminals stay
    // distinguishable by agentInstanceId, which is what grants and routing key on.
    if (peerCert.principalId === this.identity.principalId) {
      ctx.principalId = peerCert.principalId;
      ctx.permissions = { ...FULL_PERMISSIONS };
      appendAuditLog({
        type: "local_sibling_admitted",
        timestamp: Date.now(),
        roomId: this.roomId,
        principalId: peerCert.principalId,
        agentInstanceId: msg.agentInstanceId,
        remoteAddress: ctx.remoteAddress,
      });
      this.sendHandshakeFrame(socket, ctx, {
        type: "server_hello",
        version: PROTOCOL_VERSION,
        roomId: this.roomId,
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

    // Already paired device
    const pairedDevices = loadPairedDevices(this.customOmpDir);
    const paired = pairedDevices.get(canonicalFp);

    if (paired) {
      ctx.principalId = paired.principalId;
      ctx.permissions = paired.permissions;

      this.sendHandshakeFrame(socket, ctx, {
        type: "server_hello",
        version: PROTOCOL_VERSION,
        roomId: this.roomId,
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
    this.initiatePairingForSocket(socket, ctx, msg.clientNonce, ctx.displayName, undefined, req);
  }

  private handleHubPairRequest(socket: any, ctx: ConnectionContext, msg: PairRequestMsg, req?: any): void {
    if (ctx.pairingRequested) {
      closeSocket(socket, 4400, "Pairing request already active on this connection");
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
      closeSocket(socket, 4429, "Pairing rate limit exceeded");
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
          version: PROTOCOL_VERSION,
          roomId: this.roomId,
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
      closeSocket(socket, 4429, "Pairing queue full (maximum 16 requests)");
      return;
    }

    const reqId = this.nextPairingReqId++;
    const hubNonce = crypto.randomBytes(32).toString("hex");

    // Independently derived and bound to this TLS channel. If the runtime cannot export keying
    // material there is no safe code to show, so pairing fails closed rather than degrading.
    const tlsSocket = req?.socket || extractTlsSocket(socket);
    let sasCode: string;
    try {
      sasCode = deriveLocalSas(
        tlsSocket,
        this.identity.spkiDer,
        peerCert.spkiDer,
        Buffer.from(hubNonce, "hex"),
        Buffer.from(clientNonce, "hex"),
      );
    } catch (err: unknown) {
      const reason = err instanceof Error ? err.message : String(err);
      appendAuditLog({
        type: "pairing_aborted_no_channel_binding",
        timestamp: Date.now(),
        principalId: peerCert.principalId,
        reason,
      });
      this.onNotification?.(
        `Pairing refused: no channel-bound verification code could be derived (${reason})`,
        "error",
      );
      closeSocket(socket, 4409, "Pairing unsupported on this runtime");
      return;
    }

    ctx.pairingRequested = true;
    // Not a raw assignment: entering this phase must disarm the 10s handshake deadline, or the
    // socket is closed 4408 long before the operator has compared the code.
    setConnectionPhase(ctx, "awaiting-pairing");
    ctx.sasCode = sasCode;
    ctx.displayName = displayName;

    const pairingWindowMs = this.timings.pairingWindowMs;
    const timer = setTimeout(() => {
      this.pendingPairRequests.delete(reqId);
      closeSocket(socket, 4408, `Pairing request timed out after ${Math.round(pairingWindowMs / 1000)}s`);
    }, pairingWindowMs);

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
      version: PROTOCOL_VERSION,
      roomId: this.roomId,
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
    const expected = ctx.sasCode ? Buffer.from(ctx.sasCode, "utf8") : null;
    const given = typeof msg.sasCode === "string" ? Buffer.from(msg.sasCode, "utf8") : null;
    const matches = !!expected && !!given
      && expected.length === given.length
      && crypto.timingSafeEqual(expected, given);
    if (!matches) {
      closeSocket(socket, 4403, "SAS verification mismatch");
    }
  }

  /**
   * Refuse a pending pairing request and tell the peer, so its connect attempt fails now
   * instead of hanging until the 60s pairing timer fires.
   */
  private rejectPendingPairing(id: number, reason: string): null {
    const req = this.pendingPairRequests.get(id);
    if (!req) return null;
    clearTimeout(req.timer);
    this.pendingPairRequests.delete(id);
    const ctx = this.hubConnections.get(req.socket);
    try {
      if (ctx) {
        this.sendHandshakeFrame(req.socket, ctx, {
          type: "pair_response",
          version: PROTOCOL_VERSION,
          approved: false,
          reason,
        } as PairResponseMsg);
      }
      closeSocket(req.socket, 4403, reason);
    } catch {}
    return null;
  }

  /**
   * Approve a pending pairing request. The verification code is REQUIRED: an approval without
   * a compared code is a keystroke, not a decision, and would let anyone who can reach this hub
   * be admitted by an operator who never looked at the other screen.
   */
  public approvePairing(
    id: number,
    permissions: DevicePermissions = DEFAULT_PERMISSIONS,
    code?: string,
  ): PairedDevice | null {
    const req = this.pendingPairRequests.get(id);
    if (!req) return null;

    if (!code || !code.trim()) {
      appendAuditLog({
        type: "pairing_rejected_missing_sas",
        timestamp: Date.now(),
        reqId: id,
        principalId: req.peerCert.principalId,
      });
      return this.rejectPendingPairing(id, "Verification code required");
    }

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
      return this.rejectPendingPairing(id, "Verification code did not match");
    }

    clearTimeout(req.timer);
    this.pendingPairRequests.delete(id);

    // Persist the name the operator will actually see and address. Two devices approved under
    // one name would otherwise both answer to it forever, not just for this connection.
    const deviceName = this.uniqueDisplayName(
      req.displayName,
      req.socket,
      req.peerCert,
      this.hubConnections.get(req.socket)?.agentInstanceId,
    );

    const paired: PairedDevice = {
      principalId: req.peerCert.principalId,
      fingerprint: normalizeFingerprint(req.peerCert.fingerprint),
      certPem: req.peerCert.certPem,
      deviceName,
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
        version: PROTOCOL_VERSION,
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
          version: PROTOCOL_VERSION,
          approved: false,
          reason: "Pairing request was denied by the host",
        } as PairResponseMsg);
      }
      closeSocket(req.socket, 4403, "Pairing denied");
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
    revokeGrantsForPrincipal(fingerprintOrPrincipal, undefined, "Device pairing revoked");

    for (const [socket, ctx] of this.hubConnections) {
      const matchesFp = ctx.peerCert && (
        ctx.peerCert.principalId === fingerprintOrPrincipal ||
        normalizeFingerprint(ctx.peerCert.fingerprint) === normalizeFingerprint(fingerprintOrPrincipal)
      );
      const matchesName = ctx.displayName === fingerprintOrPrincipal;
      if (matchesFp || matchesName) {
        if (ctx.principalId) revokeGrantsForPrincipal(ctx.principalId, undefined, "Device pairing revoked");
        try {
          closeSocket(socket, 4403, "Device pairing revoked");
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

    // A client's own hub connection is a peer connection too: granting the hub a capability
    // must take effect now, not at the next reconnect.
    if (this.clientContext?.principalId) {
      const stored = getPairedDevice(this.clientContext.principalId, this.customOmpDir);
      const matchesClientHub = stored && (
        stored.principalId === fingerprintOrPrincipal ||
        normalizeFingerprint(stored.fingerprint) === normalizeFingerprint(fingerprintOrPrincipal) ||
        stored.deviceName === fingerprintOrPrincipal
      );
      if (matchesClientHub) this.applyStoredHubPermissions();
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
      // Fire-and-forget from a socket callback: an unhandled rejection here kills the host.
      this.handleLocalApplicationMessage(msg, senderSocket, senderCtx).catch((err: unknown) => {
        appendAuditLog({
          type: "message_dispatch_failed",
          timestamp: Date.now(),
          roomId: this.roomId,
          principalId: senderCtx.principalId,
          messageType: msg.type,
          error: err instanceof Error ? err.message : String(err),
        });
      });
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
          version: PROTOCOL_VERSION,
          id: msg.id,
          from: this.terminalName,
          to: senderCtx.displayName,
          originPrincipalId: this.identity.principalId,
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
          version: PROTOCOL_VERSION,
          id: `ack-${offer.transferId}`,
          transferId: offer.transferId,
          from: this.terminalName,
          to: senderCtx.displayName,
          originPrincipalId: this.identity.principalId,
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
          version: PROTOCOL_VERSION,
          id: `ack-${chunk.transferId}`,
          transferId: chunk.transferId,
          from: this.terminalName,
          to: senderCtx.displayName,
          originPrincipalId: this.identity.principalId,
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
      // The peer may have disconnected during an interactive confirm; a late answer is dropped.
      this.trySendApplicationFrame(senderSocket, senderCtx, {
        type: "compact_response",
        version: PROTOCOL_VERSION,
        id: msg.id,
        from: this.terminalName,
        to: senderCtx.displayName,
        originPrincipalId: this.identity.principalId,
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
    const callerPermissions =
      senderCtx?.permissions ||
      callerDevice?.permissions ||
      NO_PERMISSIONS;

    const sendRes = (ok: boolean, result?: any, error?: string) => {
      const resp: RpcResponseMsg = {
        type: "rpc_response",
        version: PROTOCOL_VERSION,
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
      // A response computed across an await can outlive its requester: git, exec and file reads
      // all resolve on a later tick, by which time the peer may be gone.
      if (this.role === "hub") {
        this.trySendApplicationFrame(senderSocket, senderCtx, resp);
      } else if (this.role === "client") {
        this.trySendApplicationFrame(this.clientWs, this.clientContext, resp);
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
      // Every action, including status, is checked before it runs. Status is not free: it
      // discloses the principal, roster and live grants.
      const permCheck = isActionPermitted(callerPermissions, req);
      if (!permCheck.permitted) {
        sendRes(false, undefined, permCheck.reason);
        return;
      }

      if (req.action === "system_status") {
        const statusData = {
          service: "omp-link",
          protocolVersion: PROTOCOL_VERSION,
          hubPrincipalId: this.identity.principalId,
          hubFingerprint: this.identity.fingerprint,
          roomId: this.roomId,
          role: this.role,
          terminalName: this.terminalName,
          agentInstanceId: this.agentInstanceId,
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
            agentInstanceId: g.agentInstanceId,
            displayName: g.displayName,
            workspaceId: g.workspaceId,
            remainingUses: g.remainingUses,
            expiresAt: g.expiresAt,
          })),
        };
        sendRes(true, statusData);
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
          senderCtx?.agentInstanceId || "",
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
    // A liveness drop and an eviction both tear down and then terminate the socket, so `ws`
    // delivers a "close" (and often an "error") for a context that is already gone. Running
    // teardown twice re-audits a disconnect, revokes grants a second time and rebroadcasts a
    // roster that did not change.
    if (ctx.teardownComplete) return;
    ctx.teardownComplete = true;

    cleanupConnectionContext(ctx);
    this.hubConnections.delete(socket);

    const peerKey = ctx.principalId || ctx.displayName;
    this.activeRpcsByPeer.delete(peerKey);

    if (ctx.principalId) {
      revokeGrantsForPrincipal(ctx.principalId, ctx.agentInstanceId, "Peer disconnected");
      this.transferReceiver.cleanupPeerTransfers(ctx.principalId);
      this.transferReceiver.cleanupPeerTransfers(ctx.displayName);
      // Anything this hub was waiting on from that peer can never arrive. Without this a
      // file transfer to a peer that vanished mid-stream blocks its caller for the full 60s
      // ack timeout (30s for an RPC, 180s for a compact) after the loss is already known.
      this.rejectPendingRequests(`Peer "${ctx.displayName}" disconnected`, ctx.principalId);
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
  ): Promise<ConnectOutcome> {
    // `role` is only set once the socket opens, so an attempt still inside its TLS handshake
    // reads as disconnected. Supersede it explicitly: two live sockets otherwise race, and the
    // loser's close/error event settles the winner's promise.
    if (this.role !== "disconnected" || this.clientWs || this.clientConnectSettle) {
      await this.stop();
    }

    // Discovery is not trust. A pin comes from an explicit argument or from a stored record for
    // this exact endpoint — never from "there is only one paired device" or a substring match
    // of the URL against a device name.
    let effectiveFingerprint = pinnedFingerprint;
    let caCertPem: string | undefined;

    const paired = loadPairedDevices(this.customOmpDir);
    if (!effectiveFingerprint) {
      for (const [, dev] of paired) {
        if (dev.lastAddress && dev.lastAddress === hubUrl) {
          effectiveFingerprint = dev.fingerprint;
          caCertPem = dev.certPem;
          break;
        }
      }
    } else {
      const match = paired.get(normalizeFingerprint(effectiveFingerprint));
      if (match) {
        caCertPem = match.certPem;
      }
    }

    let capturedServerCert: PeerCertificateInfo | null = null;
    const tlsOptions = getClientTlsOptions(this.identity, {
      pinnedFingerprint: effectiveFingerprint,
      caCertPem,
      allowUnpaired: !effectiveFingerprint,
      onServerCertificate: (certInfo) => {
        capturedServerCert = certInfo;
      },
    });

    return new Promise<ConnectOutcome>((resolve, reject) => {
      const ws = new WebSocket(hubUrl, {
        ...tlsOptions,
        maxPayload: 2 * 1024 * 1024,
        perMessageDeflate: false,
      });
      this.clientWs = ws;

      // "Connected" means authenticated and admitted, or a definite answer that pairing is
      // needed. Resolving at socket open reports transport-open as a usable connection.
      let settled = false;
      const handshakeDeadline = setTimeout(() => {
        if (settled) return;
        settled = true;
        this.clientConnectSettle = undefined;
        try { ws.terminate(); } catch {}
        reject(new Error("Handshake timed out before the hub admitted this agent"));
      }, this.timings.handshakeTimeoutMs);

      this.clientConnectSettle = (outcome, err) => {
        if (settled) return;
        settled = true;
        clearTimeout(handshakeDeadline);
        this.clientConnectSettle = undefined;
        if (err) reject(err);
        else if (outcome) resolve(outcome);
      };

      ws.on("open", () => {
        if (this.clientWs !== ws) return;

        const tlsSocket = extractTlsSocket(ws);
        let peerCert: PeerCertificateInfo | null = capturedServerCert;
        if (!peerCert && tlsSocket) {
          try {
            peerCert = extractPeerCertificate(tlsSocket);
          } catch {}
        }
        if (peerCert) {
          this.capturedServerCert = peerCert;
        }

        if (effectiveFingerprint && (peerCert || tlsSocket)) {
          const verified = peerCert
            ? normalizeFingerprint(peerCert.fingerprint) === normalizeFingerprint(effectiveFingerprint)
            : verifyPeerSpki(tlsSocket, effectiveFingerprint);
          if (!verified) {
            appendAuditLog({
              type: "hub_pin_mismatch",
              timestamp: Date.now(),
              expectedFingerprint: effectiveFingerprint,
              actualFingerprint: peerCert?.fingerprint,
              endpoint: hubUrl,
            });
            ws.terminate();
            this.clientConnectSettle?.(undefined, new Error(`SPKI fingerprint mismatch: expected ${effectiveFingerprint}`));
            return;
          }
        }

        this.role = "client";
        this.clientContext = createConnectionContext({
          socket: ws,
          peerCert: this.capturedServerCert,
          isLocal: hubUrl.includes("127.0.0.1") || hubUrl.includes("localhost"),
          handshakeTimeoutMs: this.timings.handshakeTimeoutMs,
        });

        if (this.capturedServerCert) {
          this.clientContext.peerCert = this.capturedServerCert;
          this.clientContext.principalId = this.capturedServerCert.principalId;
        }
        // A hub starts with nothing. Its capabilities come from this machine's own stored
        // record once the handshake completes, never from its role or from the wire.
        this.clientContext.permissions = { ...NO_PERMISSIONS };

        const clientNonce = crypto.randomBytes(32).toString("hex");
        this.lastClientNonce = clientNonce;

        const hello: ClientHelloMsg = {
          type: "client_hello",
          version: PROTOCOL_VERSION,
          clientNonce,
          displayName: this.terminalName,
          agentInstanceId: this.agentInstanceId,
          inviteSecret,
          host: os.hostname(),
          cwd: process.cwd(),
        };

        this.sendHandshakeFrame(ws, this.clientContext, hello);
      });

      ws.on("message", (data: unknown) => {
        if (this.clientWs !== ws) return;
        if (this.clientContext) markConnectionAlive(this.clientContext);
        // Dispatch is fire-and-forget from a socket callback: a rejection here has no caller
        // and would surface as an unhandled rejection, which kills the host process.
        this.handleClientSocketMessage(data).catch((err: unknown) => {
          appendAuditLog({
            type: "client_message_dispatch_failed",
            timestamp: Date.now(),
            roomId: this.roomId,
            error: err instanceof Error ? err.message : String(err),
          });
        });
      });

      ws.on("pong", () => {
        if (this.clientWs !== ws) return;
        if (this.clientContext) markConnectionAlive(this.clientContext);
      });

      // Only the socket this node currently owns may settle the connect promise or reset node
      // state. A superseded attempt failing later must not report failure for the live one.
      ws.on("close", () => {
        this.finalizeClientDisconnect(
          ws,
          "Hub connection closed",
          new Error("Hub closed the connection before admitting this agent"),
        );
      });

      // A link that drops mid-session can reach this side as a transport or protocol error
      // followed by a close that the error handler used to swallow — it nulled `clientWs`, so
      // the close handler's ownership guard rejected its own socket and `onHubDisconnected`
      // never fired. That callback is what drives local hub succession, so the room silently
      // failed to recover from exactly the failure succession exists for. One path now, and
      // `finalizeClientDisconnect` is idempotent so the trailing close is a no-op.
      ws.on("error", (err) => {
        this.finalizeClientDisconnect(ws, `Hub connection failed: ${err.message}`, err);
      });
    });
  }

  /**
   * The one place a client link ends. Every route into it — a clean close, a transport error, a
   * liveness timeout, a terminate() — must leave the node in the same state and must report the
   * loss exactly once, because `onHubDisconnected` is what triggers local hub succession.
   *
   * `reason` is what an in-flight caller is told and must describe what actually happened;
   * `settleError` answers a connect promise that never got a verdict, which is a different
   * statement ("you were never admitted") and is only ever true while one is pending.
   *
   * Ownership guard first: a superseded connect attempt failing later must not tear down the
   * live one. Nulling `clientWs` makes this idempotent for the error-then-close pair.
   */
  private finalizeClientDisconnect(ws: WebSocket, reason: string, settleError?: Error): void {
    if (this.clientWs !== ws) return;
    // An attempt that never opened (a refused connection, a failed TLS handshake, a dead
    // endpoint) is a failed join, not a lost hub. Reporting it as a disconnect makes the host
    // run local hub succession for a room this agent was never in — `/link on` against a dead
    // endpoint would quietly start hosting, which `join never creates` forbids.
    const wasEstablished = this.role === "client" && this.clientContext !== null;
    this.stopClientHeartbeat();
    this.role = "disconnected";
    this.clientContext = null;
    this.clientWs = null;
    this.hubRoster = [];
    this.rejectPendingRequests(reason);
    this.onTerminalsChanged?.(this.getConnectedTerminalsList().map((t) => t.name));
    this.clientConnectSettle?.(undefined, settleError ?? new Error(reason));
    if (wasEstablished) {
      try { this.onHubDisconnected?.(); } catch {}
    }
  }

  private async handleClientSocketMessage(rawData: unknown): Promise<void> {
    const parsed = parseWireMessage(rawData);
    if (!parsed.ok) {
      // A silently dropped frame turns a schema drift into a mystery disconnect.
      appendAuditLog({
        type: "client_frame_rejected",
        timestamp: Date.now(),
        roomId: this.roomId,
        error: parsed.error,
        closeCode: parsed.closeCode,
      });
      return;
    }

    const msg = parsed.message;
    const ctx = this.clientContext;
    if (!ctx) return;

    // Same phase machine as the hub. A hub cannot skip the handshake by sending application
    // traffic early any more than a client can.
    const phaseCheck = validateMessagePhase(ctx, msg.type);
    if (!phaseCheck.allowed) {
      appendAuditLog({
        type: "client_phase_violation",
        timestamp: Date.now(),
        principalId: ctx.principalId,
        messageType: msg.type,
        phase: ctx.phase,
        reason: phaseCheck.reason,
      });
      closeSocket(this.clientWs, phaseCheck.closeCode || 4403, phaseCheck.reason);
      return;
    }

    if (msg.type === "server_hello") {
      const sHello = msg as ServerHelloMsg;
      if (sHello.requiresPairing) {
        const tlsSocket = extractTlsSocket(this.clientWs);
        let sasWords: string | null = null;
        let sasError: string | null = null;
        if (tlsSocket && sHello.hubFingerprint && this.lastClientNonce && sHello.hubNonce) {
          try {
            // Use the certificate captured during checkServerIdentity: re-reading it from the
            // socket returns an empty object under app-level pinning, so it must not be the
            // source of the pairing code.
            const peerCert = this.capturedServerCert || extractPeerCertificate(tlsSocket);
            if (peerCert) {
              // Derived locally from this side's view of the channel. The code is never
              // transmitted, so a matching pair of words proves both ends share one TLS session.
              sasWords = deriveLocalSas(
                tlsSocket,
                peerCert.spkiDer,
                this.identity.spkiDer,
                Buffer.from(sHello.hubNonce, "hex"),
                Buffer.from(this.lastClientNonce, "hex"),
              );
              this.currentLocalSas = sasWords;
            }
          } catch (err: unknown) {
            sasError = err instanceof Error ? err.message : String(err);
          }
        }

        if (!sasWords) {
          const reason = sasError === "PAIRING_UNSUPPORTED_RUNTIME"
            ? "This runtime cannot derive a channel-bound verification code (TLS keying material export unavailable). Pairing is not possible here."
            : `Could not derive a verification code for this connection${sasError ? `: ${sasError}` : ""}`;
          this.onNotification?.(reason, "error");
          closeSocket(this.clientWs, 4409, "Pairing unsupported");
          this.clientConnectSettle?.(undefined, new Error(reason));
          return;
        }

        // Mirror the hub's phase. Until this connection is approved it may exchange pairing
        // frames and nothing else; leaving it in `tls-connected` makes the client reject the
        // very approval it is waiting for.
        setConnectionPhase(ctx, "awaiting-pairing");
        this.roomId = sHello.roomId || this.roomId;

        this.onNotification?.(
          `Pairing required. Compare this code on BOTH devices: ${sasWords}\n`
          + `The host approves with: /link accept <id> ${sasWords}`,
          "warning",
        );
        this.clientConnectSettle?.({ state: "pairing-required", sasCode: sasWords });
      } else {
        // The hub says this device is already known. Trust that only as far as our own pinned
        // record: the authoritative principal is the one in the certificate we verified.
        this.persistPairedHubIdentity();
        setConnectionPhase(ctx, "authenticated");
        this.applyStoredHubPermissions();
        this.absorbRoster(sHello.terminals);
        this.roomId = sHello.roomId || this.roomId;
        // Admitted: from here on this node watches its hub as closely as the hub watches it.
        this.startClientHeartbeat();
        this.clientConnectSettle?.({ state: "authenticated" });
      }
      return;
    }

    if (msg.type === "pair_response") {
      const pResp = msg as PairResponseMsg;
      if (pResp.approved) {
        this.persistPairedHubIdentity();
        setConnectionPhase(ctx, "authenticated");
        this.applyStoredHubPermissions();
        this.startClientHeartbeat();
        this.onNotification?.("Device pairing approved by host", "info");
        this.clientConnectSettle?.({ state: "authenticated" });
      } else {
        this.onNotification?.(`Pairing rejected: ${pResp.reason}`, "error");
        this.clientConnectSettle?.(undefined, new Error(`Pairing rejected: ${pResp.reason || "no reason given"}`));
      }
      return;
    }

    // A handshake frame reaching this point has no branch above. Handing it to the application
    // gate answers the denial with an application frame in a pre-authenticated phase, and
    // `sendApplicationFrame` throws there — from inside a socket callback, taking the process
    // down. `validateMessagePhase` allows these frames for the side that consumes them, so the
    // side that does not must refuse them here.
    if (HANDSHAKE_MESSAGE_TYPES.has(msg.type)) {
      appendAuditLog({
        type: "client_unexpected_handshake_frame",
        timestamp: Date.now(),
        principalId: ctx.principalId,
        messageType: msg.type,
        phase: ctx.phase,
      });
      closeSocket(this.clientWs, 4400, `Unexpected handshake frame "${msg.type}"`);
      return;
    }

    // Everything below is application traffic and runs the same gate as the hub side.
    const appMsg = msg as ApplicationMessage;
    const bound = this.clientWs
      ? this.gateInboundApplicationMessage(this.clientWs, ctx, appMsg)
      : null;
    if (!bound) return;

    if (bound.type === "rpc_response") {
      const resp = bound as RpcResponseMsg;
      const pending = this.pendingRpcRequests.get(resp.id);
      if (!pending) return;
      if (!this.originMatchesPending(pending.expectedPrincipalId, resp.originPrincipalId, "rpc_response")) return;
      clearTimeout(pending.timeout);
      this.pendingRpcRequests.delete(resp.id);
      pending.resolve(resp);
      return;
    }

    if (bound.type === "file_ack") {
      const ack = bound as FileAckMsg;
      const pending = this.pendingFileAcks.get(ack.transferId);
      if (!pending) return;
      if (!this.originMatchesPending(pending.expectedPrincipalId, ack.originPrincipalId, "file_ack")) return;
      clearTimeout(pending.timeout);
      this.pendingFileAcks.delete(ack.transferId);
      pending.resolve(ack);
      return;
    }

    if (bound.type === "compact_response") {
      const cResp = bound as CompactResponseMsg;
      const pending = this.pendingCompactRequests.get(cResp.id);
      if (!pending) return;
      if (!this.originMatchesPending(pending.expectedPrincipalId, cResp.originPrincipalId, "compact_response")) return;
      clearTimeout(pending.timeout);
      this.pendingCompactRequests.delete(cResp.id);
      pending.resolve(cResp);
      return;
    }

    if (bound.type === "status_update") {
      const update = bound as StatusUpdateMsg;
      // Membership is the hub's attestation, and only the hub's. A relayed status_update
      // carries its author's principal (the hub stamps it in bindMessageOrigin), so a peer with
      // nothing but `observe` could otherwise rewrite this agent's roster — and the roster is
      // what resolveExpectedResponder trusts to decide who may answer an RPC.
      const hubPrincipalId = this.clientContext?.principalId;
      if (hubPrincipalId && update.originPrincipalId === hubPrincipalId) {
        this.absorbRoster(update.status?.terminals);
      } else if (update.status?.terminals) {
        appendAuditLog({
          type: "roster_update_rejected",
          timestamp: Date.now(),
          roomId: this.roomId,
          expectedPrincipalId: hubPrincipalId ?? null,
          actualPrincipalId: update.originPrincipalId ?? null,
        });
      }
      // A peer's own status is still peer status: it is reported, never treated as membership.
      if (update.from) {
        this.terminalStatuses.set(update.from, update.status);
        this.onPeerStatusUpdate?.(update.from, update.status, update.context);
      }
      return;
    }

    if (bound.type === "file_offer") {
      const offer = bound as FileOfferMsg;
      const res = this.transferReceiver.handleOffer(offer, this.currentSessionId);
      if (!res.ok) {
        this.sendToHub({
          type: "file_ack",
          version: PROTOCOL_VERSION,
          id: `ack-${offer.transferId}`,
          transferId: offer.transferId,
          from: this.terminalName,
          to: offer.from || "hub",
          originPrincipalId: this.identity.principalId,
          ok: false,
          error: res.error,
          ts: Date.now(),
        } as FileAckMsg);
      }
      return;
    }

    if (bound.type === "file_chunk") {
      const chunk = bound as FileChunkMsg;
      const res = this.transferReceiver.handleChunk(chunk);
      if (res.complete || !res.ok) {
        this.sendToHub({
          type: "file_ack",
          version: PROTOCOL_VERSION,
          id: `ack-${chunk.transferId}`,
          transferId: chunk.transferId,
          from: this.terminalName,
          to: chunk.from || "hub",
          originPrincipalId: this.identity.principalId,
          ok: res.ok,
          error: res.error,
          ts: Date.now(),
        } as FileAckMsg);
      }
      return;
    }

    if (bound.type === "rpc_request") {
      await this.handleLocalRpcRequest(bound as RpcRequestMsg, this.clientWs, ctx);
      return;
    }

    if (bound.type === "compact_request") {
      let ok = true;
      let reason: string | undefined;
      if (this.onCompactRequest) {
        try {
          const cRes = await this.onCompactRequest(bound as CompactRequestMsg);
          ok = cRes.ok;
          reason = cRes.reason;
        } catch (err: unknown) {
          ok = false;
          reason = err instanceof Error ? err.message : String(err);
        }
      }
      this.sendToHub({
        type: "compact_response",
        version: PROTOCOL_VERSION,
        id: bound.id,
        from: this.terminalName,
        to: bound.from,
        originPrincipalId: this.identity.principalId,
        ok,
        reason,
        ts: Date.now(),
      } as CompactResponseMsg);
      return;
    }

    if (bound.type === "chat" || bound.type === "direct_message") {
      this.onMessage?.(bound);
      return;
    }
  }

  /**
   * A correlated response only satisfies a pending request when it comes from the principal we
   * sent that request to. A response that omits its origin is unverifiable, so it is refused
   * rather than trusted by default.
   */
  private originMatchesPending(
    expectedPrincipalId: string | undefined,
    actualPrincipalId: string | undefined,
    kind: string,
  ): boolean {
    if (!expectedPrincipalId) return true;
    if (actualPrincipalId === expectedPrincipalId) return true;
    appendAuditLog({
      type: `${kind}_origin_mismatch`,
      timestamp: Date.now(),
      expectedPrincipalId,
      actualPrincipalId: actualPrincipalId ?? null,
    });
    return false;
  }

  /**
   * Replace the roster with the hub's authoritative membership view. Entries are shape-checked
   * and capped: this list feeds routing and `resolveExpectedResponder`.
   */
  private absorbRoster(terminals: TerminalDescriptor[] | undefined): void {
    if (!Array.isArray(terminals)) return;
    this.hubRoster = terminals
      .filter(
        (t): t is TerminalDescriptor =>
          !!t &&
          typeof t.principalId === "string" &&
          typeof t.agentInstanceId === "string" &&
          typeof t.name === "string" &&
          t.agentInstanceId !== this.agentInstanceId,
      )
      // `isSelf` is meaningful only in the descriptor a node builds for itself. Over the wire
      // it is a claim about the sender, and preserving it makes a client's roster report two
      // "self" entries — a consumer that identifies itself by that flag then sees no reachable
      // peers at all and refuses perfectly good sends. Entries carrying our own
      // agentInstanceId are already filtered out, so this only clears the sender's claim.
      .map((t) => ({ ...t, isSelf: false }))
      .slice(0, MAX_ROSTER_ENTRIES);
    this.onTerminalsChanged?.(this.getConnectedTerminalsList().map((t) => t.name));
  }

  /** Capabilities for the hub come from this machine's own record, never from the wire. */
  private applyStoredHubPermissions(): void {
    const ctx = this.clientContext;
    if (!ctx?.principalId) return;
    if (ctx.principalId === this.identity.principalId) {
      // A hub run by a sibling terminal of this same device. See handleHubClientHello.
      ctx.permissions = { ...FULL_PERMISSIONS };
      return;
    }
    const stored = getPairedDevice(ctx.principalId, this.customOmpDir);
    ctx.permissions = stored?.permissions ? { ...stored.permissions } : { ...NO_PERMISSIONS };
  }

  private persistPairedHubIdentity(): void {
    try {
      const peerCert = this.capturedServerCert || extractPeerCertificate(extractTlsSocket(this.clientWs));
      if (!peerCert) return;
      // Never record this device as a peer of itself: a sibling terminal's hub presents our
      // own certificate, and there is nothing to pin that we do not already hold.
      if (peerCert.principalId === this.identity.principalId) {
        if (this.clientContext) this.clientContext.principalId = peerCert.principalId;
        return;
      }
      const canonicalFp = normalizeFingerprint(peerCert.fingerprint);
      const existing = getPairedDevice(peerCert.principalId, this.customOmpDir);
      const pairedHub: PairedDevice = {
        // Derived from the certificate we verified. A wire-supplied principal id is a claim.
        principalId: peerCert.principalId,
        fingerprint: canonicalFp,
        certPem: peerCert.certPem,
        deviceName: existing?.deviceName || "hub",
        // A hub is a peer like any other: it gets the default capability set, not everything.
        permissions: existing?.permissions || DEFAULT_PERMISSIONS,
        pairedAt: existing?.pairedAt || Date.now(),
        lastSeen: Date.now(),
        lastAddress: this.clientWs?.url,
      };
      savePairedDevice(pairedHub, this.customOmpDir);
      if (this.clientContext) {
        this.clientContext.principalId = pairedHub.principalId;
      }
    } catch {}
  }

  // ── Operations & Helper Methods ───────────────────────────────────────────

  public sendMessage(to: string, text: string): boolean {
    const isBroadcast = to === "*";
    // Resolve the name to a principal here, so the frame carries the identity the caller meant
    // rather than a label another peer could be holding.
    const resolved = isBroadcast ? undefined : this.resolveExpectedResponder(to);
    const msg: ApplicationMessage = {
      type: isBroadcast ? "chat" : "direct_message",
      version: PROTOCOL_VERSION,
      id: crypto.randomUUID(),
      from: this.terminalName,
      originPrincipalId: this.identity.principalId,
      to,
      toPrincipalId: resolved,
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
    const expectedPrincipalId = this.resolveExpectedResponder(to);

    const msg: RpcRequestMsg = {
      type: "rpc_request",
      version: PROTOCOL_VERSION,
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
      const rpcTimeoutMs = this.timings.rpcTimeoutMs;
      const timeout = setTimeout(() => {
        this.pendingRpcRequests.delete(id);
        reject(new Error(`RPC request to "${to}" timed out after ${Math.round(rpcTimeoutMs / 1000)}s`));
      }, rpcTimeoutMs);

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

  /**
   * Which principal is allowed to answer a request addressed to `to`. A hub reads it from the
   * live connection; a client reads it from the hub-published roster. Without this a correlated
   * response carrying no origin at all would satisfy any pending request.
   */
  private resolveExpectedResponder(to: string): string | undefined {
    if (to.startsWith("ed25519-")) return to;
    if (this.role === "hub") {
      for (const [, c] of this.hubConnections) {
        if (c.phase === "authenticated" && (c.displayName === to || c.principalId === to)) {
          return c.principalId;
        }
      }
      return undefined;
    }
    return this.hubRoster.find((t) => t.name === to || t.principalId === to)?.principalId;
  }

  public async requestCompact(
    to: string,
    instructions?: string,
  ): Promise<CompactResponseMsg> {
    const id = crypto.randomUUID();
    const expectedPrincipalId = this.resolveExpectedResponder(to);

    const msg: CompactRequestMsg = {
      type: "compact_request",
      version: PROTOCOL_VERSION,
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
      version: PROTOCOL_VERSION,
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
    // This promise is awaited only after every chunk has been streamed, but it can be rejected
    // long before that — a peer disconnecting mid-stream fails it at once. A rejection with no
    // handler attached yet is reported as unhandled, and Node turns that into a fatal
    // uncaught exception. The real outcome is still awaited below; this only claims it early.
    ackPromise.catch(() => {});

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

    try {
      await streamFileChunks(
        realFilePath,
        transferId,
        this.terminalName,
        to,
        hashInfo.totalChunks,
        hashInfo.sizeBytes,
        sendChunkFn,
        // Report no backpressure once the socket is gone: a dead socket's buffer never drains,
        // and the sender's poll loop has no other exit.
        () => (targetSocket?.readyState === WebSocket.OPEN ? targetSocket.bufferedAmount || 0 : 0),
      );
    } catch (err: unknown) {
      // Nothing will consume the ack once the stream itself failed: drop the pending entry so
      // its 60s timer does not fire into a caller that already has an answer.
      const pending = this.pendingFileAcks.get(transferId);
      if (pending) {
        clearTimeout(pending.timeout);
        this.pendingFileAcks.delete(transferId);
      }
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }

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

  /**
   * Answer a peer that may already be gone. `sendApplicationFrame` throws in the wrong phase on
   * purpose, and that catches programmer errors — but a peer disconnecting while we are still
   * computing its answer is not one. By the time an awaited handler resolves, its context can be
   * closing and its socket dead; throwing from that continuation takes the host process down, so
   * a late answer is dropped instead.
   */
  private trySendApplicationFrame(
    socket: WebSocket | null | undefined,
    ctx: ConnectionContext | null,
    msg: WireMessage,
  ): boolean {
    if (!socket || !ctx || ctx.phase !== "authenticated") return false;
    if (socket.readyState !== WebSocket.OPEN) return false;
    this.sendApplicationFrame(socket, ctx, msg);
    return true;
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
    this.broadcastToOthers(null, {
      type: "status_update",
      version: PROTOCOL_VERSION,
      // Stamped so a client can tell the hub's membership attestation from a peer's own status
      // frame relayed through the hub. Without it the two are indistinguishable on the wire.
      id: `terms-${Date.now()}`,
      from: this.terminalName,
      originPrincipalId: this.identity.principalId,
      status: { terminals: list },
      ts: Date.now(),
    } as WireMessage);

    this.onTerminalsChanged?.(list.map((t) => t.name));
  }

  /**
   * Authoritative membership. On a hub this is built from live connections; on a client it is
   * whatever the hub last published, because a client has no inbound connections of its own.
   */
  public getConnectedTerminalsList(): TerminalDescriptor[] {
    const self: TerminalDescriptor = {
      principalId: this.identity.principalId,
      agentInstanceId: this.agentInstanceId,
      name: this.terminalName,
      workspaceLabel: path.basename(this.workspaceRoot),
      isSelf: true,
    };
    if (this.role === "client") {
      return [self, ...this.hubRoster];
    }

    const res: TerminalDescriptor[] = [self];
    for (const [, ctx] of this.hubConnections) {
      if (ctx.phase !== "authenticated") continue;
      res.push({
        principalId: ctx.principalId || "unknown",
        agentInstanceId: ctx.agentInstanceId || "unknown",
        name: ctx.displayName,
        workspaceLabel: ctx.workspaceLabel,
      });
    }
    return res;
  }

  /**
   * Rejects every in-flight correlated request. A dropped link must fail its callers now: a
   * pending RPC otherwise waits out its full 30 s timeout (180 s for a compact, 60 s for a file
   * ack) after the peer is already known to be gone.
   */
  private rejectPendingRequests(reason: string, onlyPrincipalId?: string): void {
    const drop = <T extends { expectedPrincipalId?: string; timeout: NodeJS.Timeout; reject: (err: Error) => void }>(
      map: Map<string, T>,
    ): void => {
      for (const [key, p] of map) {
        if (onlyPrincipalId !== undefined && p.expectedPrincipalId !== onlyPrincipalId) continue;
        clearTimeout(p.timeout);
        map.delete(key);
        p.reject(new Error(reason));
      }
    };
    drop(this.pendingRpcRequests);
    drop(this.pendingCompactRequests);
    drop(this.pendingFileAcks);
  }

  public async stop(): Promise<void> {
    // First, before anything can re-arm them: an interval that outlives stop() keeps the whole
    // agent process alive, so `/link off` or quitting a terminal would simply hang.
    this.stopHubHeartbeat();
    this.stopClientHeartbeat();
    revokeAllGrants("Link stopping");
    this.transferReceiver.abortAllTransfers();
    this.activeRpcsByPeer.clear();
    this.rejectPendingRequests("Link stopped");

    // A connect attempt still inside its handshake owns an unsettled promise and an armed 10 s
    // deadline. Settling it releases both; leaving it keeps a timer alive past stop() and hands
    // the caller a timeout it never waited for.
    this.clientConnectSettle?.(undefined, new Error("Link stopped before the hub admitted this agent"));

    for (const [_, req] of this.pendingPairRequests) {
      clearTimeout(req.timer);
    }
    this.pendingPairRequests.clear();

    if (this.udpSocket) {
      try { this.udpSocket.close(); } catch {}
      this.udpSocket = null;
    }

    if (this.wss) {
      const peers = [...this.wss.clients];
      for (const socket of peers) {
        closeSocket(socket, 1000, "Link shutting down");
      }
      this.wss.close();
      this.wss = null;
      // A peer that never answers its close frame must not hold the host process for ws's 30 s
      // closeTimeout: quitting the terminal has to be immediate. Bounded grace, then drop.
      const graceDeadline = Date.now() + CLOSE_HANDSHAKE_GRACE_MS;
      while (Date.now() < graceDeadline && peers.some((s) => s.readyState !== WebSocket.CLOSED)) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      for (const socket of peers) {
        try { if (socket.readyState !== WebSocket.CLOSED) socket.terminate(); } catch {}
      }
    }

    if (this.httpsServer) {
      const server = this.httpsServer;
      this.httpsServer = null;
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        // An idle keep-alive or never-upgraded TLS connection keeps close() from ever calling
        // back, and /status is a public endpoint anyone can hold open.
        try { server.closeAllConnections(); } catch {}
      });
    }

    if (this.clientWs) {
      const ws = this.clientWs;
      this.clientWs = null;
      this.clientContext = null;
      try {
        ws.removeAllListeners();
        // Closing a socket that is still in its opening handshake aborts it and emits `error` on
        // a later tick. With every listener removed that error is unhandled, and an unhandled
        // `error` event kills the host process where no try/catch can see it.
        ws.on("error", () => {});
        ws.close(1000, "Disconnected");
      } catch {}
    }

    // A context left in hubConnections still holds an armed handshake deadline. Marking it torn
    // down also keeps the socket's trailing "close" event from re-auditing a disconnect and
    // rebroadcasting a roster for a hub that no longer exists.
    for (const [, ctx] of this.hubConnections) {
      ctx.teardownComplete = true;
      cleanupConnectionContext(ctx);
    }
    this.hubConnections.clear();
    this.hubRoster = [];
    this.terminalStatuses.clear();
    this.terminalContexts.clear();
    this.role = "disconnected";
  }
}
