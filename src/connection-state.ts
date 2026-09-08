import { type DevicePermissions } from "./identity.js";
import { type PeerCertificateInfo } from "./tls.js";
import { HANDSHAKE_MESSAGE_TYPES, APPLICATION_MESSAGE_TYPES } from "./protocol-schema.js";

export type ConnectionPhase =
  | "tls-connected"
  | "awaiting-pairing"
  | "authenticated"
  | "closing";

export const HANDSHAKE_TIMEOUT_MS = 10_000;
export const PAIRING_EXPIRY_MS = 60_000;
const MAX_SEEN_MESSAGES_PER_CONN = 1_000;

export interface ConnectionContext {
  id: string;
  socket: any; // WebSocket
  phase: ConnectionPhase;
  principalId?: string;
  agentId?: string;
  displayName: string;
  permissions?: DevicePermissions;
  connectedAt: number;
  handshakeDeadline?: NodeJS.Timeout;
  remoteAddress?: string;
  peerCert?: PeerCertificateInfo | null;
  seenMessageIds: Set<string>;
  helloReceived: boolean;
  pairingRequested: boolean;
  sasCode?: string;
  isLocal: boolean;
  workspaces?: string[];
}

export function createConnectionContext(params: {
  socket: any;
  remoteAddress?: string;
  peerCert?: PeerCertificateInfo | null;
  isLocal?: boolean;
  onHandshakeTimeout?: () => void;
}): ConnectionContext {
  const ctx: ConnectionContext = {
    id: `conn-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    socket: params.socket,
    phase: "tls-connected",
    displayName: "unauthenticated",
    connectedAt: Date.now(),
    remoteAddress: params.remoteAddress,
    peerCert: params.peerCert,
    seenMessageIds: new Set<string>(),
    helloReceived: false,
    pairingRequested: false,
    isLocal: params.isLocal ?? false,
  };

  if (params.onHandshakeTimeout) {
    ctx.handshakeDeadline = setTimeout(() => {
      if (ctx.phase !== "authenticated") {
        params.onHandshakeTimeout!();
      }
    }, HANDSHAKE_TIMEOUT_MS);
  }

  return ctx;
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
  if (newPhase === "authenticated" && ctx.handshakeDeadline) {
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
