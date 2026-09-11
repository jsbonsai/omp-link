import { type DevicePermissions } from "./identity.js";
import { type PeerCertificateInfo } from "./tls.js";
import { HANDSHAKE_MESSAGE_TYPES, APPLICATION_MESSAGE_TYPES } from "./protocol-schema.js";

export type ConnectionPhase =
  | "tls-connected"
  | "awaiting-pairing"
  | "authenticated"
  | "closing";

/**
 * Documented default for the handshake deadline, and the fallback for a caller that has no
 * configuration in hand. The live value is `handshakeTimeoutMs` in `link.json`: `LinkNode`
 * resolves its timings once at construction and passes the number to
 * `createConnectionContext`, so nothing here reads config per connection.
 */
export const HANDSHAKE_TIMEOUT_MS = 10_000;
const MAX_SEEN_MESSAGES_PER_CONN = 1_000;

export interface ConnectionContext {
  id: string;
  socket: any; // WebSocket
  phase: ConnectionPhase;
  principalId?: string;
  /** Distinguishes terminals sharing one device certificate. Set from client_hello. */
  agentInstanceId?: string;
  agentId?: string;
  displayName: string;
  workspaceLabel?: string;
  permissions?: DevicePermissions;
  connectedAt: number;
  /**
   * Wall clock of the last thing this peer said: any frame, or a WebSocket pong. Liveness is
   * measured from inbound traffic rather than from pongs alone, so a busy peer is never dropped
   * for a pong lost behind a large transfer.
   */
  lastInboundAt: number;
  handshakeDeadline?: NodeJS.Timeout;
  remoteAddress?: string;
  peerCert?: PeerCertificateInfo | null;
  seenMessageIds: Set<string>;
  helloReceived: boolean;
  pairingRequested: boolean;
  sasCode?: string;
  isLocal: boolean;
  workspaces?: string[];
  /**
   * Set once the owning node has run its disconnect teardown for this context. A liveness drop
   * tears down immediately and then terminates the socket, so the socket's own "close" event
   * arrives afterwards and must not revoke grants, audit, or rebroadcast a second time.
   */
  teardownComplete: boolean;
}

export function createConnectionContext(params: {
  socket: any;
  remoteAddress?: string;
  peerCert?: PeerCertificateInfo | null;
  isLocal?: boolean;
  /**
   * Live handshake deadline in ms, from `handshakeTimeoutMs`. Resolved by the owning node, not
   * read here: this function runs once per inbound connection and must not touch the filesystem.
   */
  handshakeTimeoutMs?: number;
  onHandshakeTimeout?: () => void;
}): ConnectionContext {
  const ctx: ConnectionContext = {
    id: `conn-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    socket: params.socket,
    phase: "tls-connected",
    displayName: "unauthenticated",
    connectedAt: Date.now(),
    lastInboundAt: Date.now(),
    remoteAddress: params.remoteAddress,
    peerCert: params.peerCert,
    seenMessageIds: new Set<string>(),
    helloReceived: false,
    pairingRequested: false,
    isLocal: params.isLocal ?? false,
    teardownComplete: false,
  };

  if (params.onHandshakeTimeout) {
    ctx.handshakeDeadline = setTimeout(() => {
      if (ctx.phase !== "authenticated") {
        params.onHandshakeTimeout!();
      }
    }, params.handshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS);
  }

  return ctx;
}

/**
 * Records that the peer on this connection is still there. Called for every inbound frame and
 * for every WebSocket pong: a peer that is answering pings but sending nothing is alive, and so
 * is a peer streaming a file whose pong is queued behind 64 KiB chunks.
 */
export function markConnectionAlive(ctx: ConnectionContext): void {
  ctx.lastInboundAt = Date.now();
}

export function validateMessagePhase(
  ctx: ConnectionContext,
  msgType: string,
): { allowed: boolean; reason?: string; closeCode?: number } {
  if (ctx.phase === "closing") {
    return { allowed: false, reason: "Connection is closing", closeCode: 4403 };
  }

  if (ctx.phase === "tls-connected") {
    if (msgType === "client_hello" || msgType === "server_hello") {
      if (ctx.helloReceived) {
        return { allowed: false, reason: "Duplicate hello message rejected", closeCode: 4400 };
      }
      return { allowed: true };
    }
    if (msgType === "pair_request") {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason: `Message "${msgType}" forbidden in phase "${ctx.phase}" (expected hello)`,
      closeCode: 4403,
    };
  }

  if (ctx.phase === "awaiting-pairing") {
    if (APPLICATION_MESSAGE_TYPES.has(msgType)) {
      return {
        allowed: false,
        reason: "Application traffic strictly prohibited before device pairing approval",
        closeCode: 4403,
      };
    }
    if (msgType === "pair_verify" || msgType === "pair_response" || msgType === "pair_request") {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason: `Message "${msgType}" forbidden while awaiting pairing`,
      closeCode: 4403,
    };
  }

  if (ctx.phase === "authenticated") {
    if (HANDSHAKE_MESSAGE_TYPES.has(msgType)) {
      return {
        allowed: false,
        reason: `Handshake frame "${msgType}" forbidden after connection is authenticated`,
        closeCode: 4400,
      };
    }
    if (APPLICATION_MESSAGE_TYPES.has(msgType)) {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason: `Unknown application message type: "${msgType}"`,
      closeCode: 4400,
    };
  }

  return { allowed: false, reason: "Invalid connection phase", closeCode: 4403 };
}

export function checkMessageDeduplication(ctx: ConnectionContext, msgId?: string): boolean {
  if (!msgId) return true;
  if (ctx.seenMessageIds.has(msgId)) {
    return false; // Already processed
  }
  if (ctx.seenMessageIds.size >= MAX_SEEN_MESSAGES_PER_CONN) {
    const first = ctx.seenMessageIds.values().next().value;
    if (first !== undefined) {
      ctx.seenMessageIds.delete(first);
    }
  }
  ctx.seenMessageIds.add(msgId);
  return true;
}

export function setConnectionPhase(ctx: ConnectionContext, newPhase: ConnectionPhase): void {
  ctx.phase = newPhase;
  // The 10s handshake deadline covers "peer connected and said nothing". Both of these phases
  // mean the peer said something and is now waiting on a decision: an admitted connection has
  // no deadline at all, and a pairing connection is governed by the 60s pairing timer instead.
  // Leaving the handshake deadline armed closes every pairing socket after 10s, which is less
  // time than a human needs to compare four words on two screens.
  if ((newPhase === "authenticated" || newPhase === "awaiting-pairing") && ctx.handshakeDeadline) {
    clearTimeout(ctx.handshakeDeadline);
    ctx.handshakeDeadline = undefined;
  }
}

export function cleanupConnectionContext(ctx: ConnectionContext): void {
  ctx.phase = "closing";
  if (ctx.handshakeDeadline) {
    clearTimeout(ctx.handshakeDeadline);
    ctx.handshakeDeadline = undefined;
  }
  ctx.seenMessageIds.clear();
}
