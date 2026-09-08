import { type DevicePermissions } from "./identity.js";

export const PROTOCOL_VERSION = 5;
export const MAX_MESSAGE_SIZE = 2 * 1024 * 1024; // 2MB frame limit

export interface BaseMessage {
  type: string;
  version: number;
  id?: string;
  from?: string;
  to?: string;
  ts?: number;
  originPrincipalId?: string;
  originAgentId?: string;
  [key: string]: any;
}

export interface ClientHelloMsg extends BaseMessage {
  type: "client_hello";
  version: 5;
  clientNonce: string;
  displayName: string;
  inviteSecret?: string;
  host?: string;
  cwd?: string;
}

export interface ServerHelloMsg extends BaseMessage {
  type: "server_hello";
  version: 5;
  sessionId: string;
  hubPrincipalId: string;
  hubFingerprint: string;
  hubNonce: string;
  requiresPairing: boolean;
  sasCode?: string;
  host?: string;
  terminals?: Array<{ name: string; host?: string; cwd?: string; status?: string }>;
}

export interface PairRequestMsg extends BaseMessage {
  type: "pair_request";
  version: 5;
  clientNonce: string;
  displayName: string;
  host?: string;
  inviteSecret?: string;
}

export interface PairResponseMsg extends BaseMessage {
  type: "pair_response";
  version: 5;
  approved: boolean;
  reason?: string;
  permissions?: DevicePermissions;
}

export interface PairVerifyMsg extends BaseMessage {
  type: "pair_verify";
  version: 5;
  sasCode: string;
}

export interface ChatMsg extends BaseMessage {
  type: "chat";
  version: 5;
  id: string;
  from?: string;
  to?: string;
  text: string;
  ts: number;
}

export interface DirectMsg extends BaseMessage {
  type: "direct_message";
  version: 5;
  id: string;
  from?: string;
  to: string;
  text: string;
  ts: number;
}

export interface StatusUpdateMsg extends BaseMessage {
  type: "status_update";
  version: 5;
  id: string;
  from?: string;
  status: any;
  context?: any;
  ts: number;
}

export interface CompactRequestMsg extends BaseMessage {
  type: "compact_request";
  version: 5;
  id: string;
  from?: string;
  to: string;
  instructions?: string;
  ts: number;
}

export interface CompactResponseMsg extends BaseMessage {
  type: "compact_response";
  version: 5;
  id: string;
  from?: string;
  to: string;
  ok: boolean;
  error?: string;
  ts: number;
}

export interface FileOfferMsg extends BaseMessage {
  type: "file_offer";
  version: 5;
  id: string;
  transferId: string;
  from?: string;
  to: string;
  filename: string;
  sizeBytes: number;
  totalChunks: number;
  sha256: string;
  destRelPath?: string;
  ts: number;
}

export interface FileChunkMsg extends BaseMessage {
  type: "file_chunk";
  version: 5;
  id: string;
  transferId: string;
  from?: string;
  to: string;
  chunkIndex: number;
  totalChunks: number;
  data: string;
  ts: number;
}

export interface FileAckMsg extends BaseMessage {
  type: "file_ack";
  version: 5;
  id: string;
  transferId: string;
  from?: string;
  to: string;
  ok: boolean;
  error?: string;
  ts: number;
}

export interface RpcRequestMsg extends BaseMessage {
  type: "rpc_request";
  version: 5;
  id: string;
  from?: string;
  to: string;
  action: string;
  params?: any;
  ts: number;
}

export interface RpcResponseMsg extends BaseMessage {
  type: "rpc_response";
  version: 5;
  id: string;
  from?: string;
  to: string;
  ok: boolean;
  result?: any;
  error?: string;
  ts: number;
}

export type HandshakeMessage =
  | ClientHelloMsg
  | ServerHelloMsg
  | PairRequestMsg
  | PairResponseMsg
  | PairVerifyMsg;

export type ApplicationMessage =
  | ChatMsg
  | DirectMsg
  | StatusUpdateMsg
  | CompactRequestMsg
  | CompactResponseMsg
  | FileOfferMsg
  | FileChunkMsg
  | FileAckMsg
  | RpcRequestMsg
  | RpcResponseMsg;

export type WireMessage = HandshakeMessage | ApplicationMessage;

export const HANDSHAKE_MESSAGE_TYPES = new Set([
  "client_hello",
  "server_hello",
  "pair_request",
  "pair_response",
  "pair_verify",
]);

export const APPLICATION_MESSAGE_TYPES = new Set([
  "chat",
  "direct_message",
  "status_update",
  "compact_request",
  "compact_response",
  "file_offer",
  "file_chunk",
  "file_ack",
  "rpc_request",
  "rpc_response",
]);

export function sanitizeDisplayName(name: string): string {
  // Strip control characters, ANSI escape sequences, and limit length
  return name
    .replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\x00-\x1F\x7F-\x9F]/g, "")
    .trim()
    .slice(0, 64);
}

export function parseWireMessage(
  raw: string | Buffer,
): { ok: true; message: WireMessage } | { ok: false; error: string; closeCode: number } {
  if (typeof raw !== "string" && !Buffer.isBuffer(raw)) {
    return { ok: false, error: "Message must be a string or Buffer", closeCode: 4400 };
  }

  const str = typeof raw === "string" ? raw : raw.toString("utf8");
  if (str.length > MAX_MESSAGE_SIZE) {
    return { ok: false, error: `Frame exceeds maximum permissible size of ${MAX_MESSAGE_SIZE} bytes`, closeCode: 4409 };
  }

  let obj: any;
  try {
    obj = JSON.parse(str);
  } catch (err: any) {
    return { ok: false, error: `Malformed JSON frame: ${err.message}`, closeCode: 4400 };
  }

  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    return { ok: false, error: "Root frame must be a JSON object", closeCode: 4400 };
  }

  // Check protocol version
  if (obj.version !== PROTOCOL_VERSION) {
    return {
      ok: false,
      error: `Unsupported protocol version; expected ${PROTOCOL_VERSION}, got ${obj.version}`,
      closeCode: 4400,
    };
  }

  const msgType = obj.type;
  if (!msgType || typeof msgType !== "string") {
    return { ok: false, error: "Missing or invalid 'type' attribute", closeCode: 4400 };
  }

  const isHandshake = HANDSHAKE_MESSAGE_TYPES.has(msgType);
  const isApp = APPLICATION_MESSAGE_TYPES.has(msgType);

  if (!isHandshake && !isApp) {
    return { ok: false, error: `Unknown message type: "${msgType}"`, closeCode: 4400 };
  }

  // Type-specific field validations
  if (msgType === "client_hello") {
    if (!obj.clientNonce || typeof obj.clientNonce !== "string") {
      return { ok: false, error: "client_hello missing valid clientNonce", closeCode: 4400 };
    }
    if (!obj.displayName || typeof obj.displayName !== "string") {
      return { ok: false, error: "client_hello missing valid displayName", closeCode: 4400 };
    }
    obj.displayName = sanitizeDisplayName(obj.displayName);
  } else if (msgType === "server_hello") {
    if (!obj.sessionId || typeof obj.sessionId !== "string") {
      return { ok: false, error: "server_hello missing valid sessionId", closeCode: 4400 };
    }
    if (!obj.hubPrincipalId || typeof obj.hubPrincipalId !== "string") {
      return { ok: false, error: "server_hello missing valid hubPrincipalId", closeCode: 4400 };
    }
  } else if (msgType === "pair_request") {
    if (!obj.clientNonce || typeof obj.clientNonce !== "string") {
      return { ok: false, error: "pair_request missing valid clientNonce", closeCode: 4400 };
    }
    if (!obj.displayName || typeof obj.displayName !== "string") {
      return { ok: false, error: "pair_request missing valid displayName", closeCode: 4400 };
    }
    obj.displayName = sanitizeDisplayName(obj.displayName);
  } else if (msgType === "pair_verify") {
    if (!obj.sasCode || typeof obj.sasCode !== "string") {
      return { ok: false, error: "pair_verify missing valid sasCode", closeCode: 4400 };
    }
  } else if (msgType === "file_offer") {
    if (!obj.transferId || typeof obj.transferId !== "string" || !/^[a-zA-Z0-9_-]{4,64}$/.test(obj.transferId)) {
      return { ok: false, error: "Invalid transferId", closeCode: 4400 };
    }
    if (!Number.isSafeInteger(obj.sizeBytes) || obj.sizeBytes < 1 || obj.sizeBytes > 50 * 1024 * 1024) {
      return { ok: false, error: "Invalid sizeBytes (must be integer between 1 and 50MB)", closeCode: 4400 };
    }
    const expectedChunks = Math.ceil(obj.sizeBytes / (64 * 1024));
    if (!Number.isSafeInteger(obj.totalChunks) || obj.totalChunks !== expectedChunks) {
      return { ok: false, error: `Invalid totalChunks (expected ${expectedChunks})`, closeCode: 4400 };
    }
    if (typeof obj.sha256 !== "string" || !/^[a-fA-F0-9]{64}$/.test(obj.sha256)) {
      return { ok: false, error: "Invalid sha256 checksum", closeCode: 4400 };
    }
    if (typeof obj.filename !== "string" || obj.filename.length === 0 || obj.filename.length > 255) {
      return { ok: false, error: "Invalid filename", closeCode: 4400 };
    }
  } else if (msgType === "file_chunk") {
    if (!obj.transferId || typeof obj.transferId !== "string") {
      return { ok: false, error: "Invalid transferId", closeCode: 4400 };
    }
    if (!Number.isSafeInteger(obj.chunkIndex) || obj.chunkIndex < 0) {
      return { ok: false, error: "Invalid chunkIndex", closeCode: 4400 };
    }
    if (typeof obj.data !== "string") {
      return { ok: false, error: "Invalid chunk data", closeCode: 4400 };
    }
  }

  return { ok: true, message: obj as WireMessage };
}
