import * as crypto from "node:crypto";
import { type DevicePermissions, savePairedDevice, getPairedDevice } from "./identity.js";
import { type ApplicationMessage } from "./protocol-schema.js";
import { type ConnectionContext } from "./connection-state.js";
import { appendAuditLog } from "./audit.js";

export interface ExecGrant {
  grantId: string;
  principalId: string;
  displayName: string;
  workspaceId: string;
  commandDigest?: string;
  createdAt: number;
  expiresAt: number;
  remainingUses: number;
  timer?: NodeJS.Timeout;
}

export const MUTATION_GUARD_ADVISORY =
  "Full shell access granted. Mutation Guard is advisory and does not provide containment. Treat this peer as having local-user access.";

// Active in-memory execution grants keyed by principalId
const activeExecGrants = new Map<string, ExecGrant>();

export function requiredPermission(message: ApplicationMessage): keyof DevicePermissions {
  switch (message.type) {
    case "chat":
    case "direct_message":
      return "message";
    case "compact_request":
    case "compact_response":
      return "compact";
    case "file_offer":
    case "file_chunk":
    case "file_ack":
      return "fileInbox";
    case "rpc_request": {
      switch (message.action) {
        case "exec":
          return "execRequest";
        case "system_status":
          return "observe";
        case "git_status":
        case "git_log":
        case "list_dir":
          return "inspectMetadata";
        case "read_file":
        case "search_text":
          return "readContent";
        case "git_diff":
          return "readDiff";
        default:
          return "inspectMetadata";
      }
    }
    case "status_update":
    default:
      return "observe";
  }
}

export function isActionPermitted(
  permissions: DevicePermissions | undefined,
  message: ApplicationMessage,
): { permitted: boolean; required: keyof DevicePermissions; reason?: string } {
  const req = requiredPermission(message);
  if (!permissions) {
    return { permitted: false, required: req, reason: "No device permissions attached to connection" };
  }

  // Check granular capability first
  if (permissions[req]) {
    return { permitted: true, required: req };
  }

  // Legacy fallback: if device has general 'inspect: true', allow readContent/readDiff/inspectMetadata
  if (
    permissions.inspect &&
    (req === "inspectMetadata" || req === "readContent" || req === "readDiff")
  ) {
    return { permitted: true, required: req };
  }

  return {
    permitted: false,
    required: req,
    reason: `Permission denied: action requires "${req}" capability, which is not granted to this device`,
  };
}

export function bindMessageOrigin(
  message: ApplicationMessage,
  ctx: ConnectionContext,
): ApplicationMessage {
  // Enforce authoritative origin from authenticated TLS connection
  return {
    ...message,
    from: ctx.displayName,
    originPrincipalId: ctx.principalId,
    originAgentId: ctx.agentId,
  };
}

export function createExecGrant(
  principalId: string,
  displayName: string,
  options: {
    workspaceId?: string;
    command?: string;
    durationMs?: number;
    maxUses?: number;
    onExpire?: (grant: ExecGrant) => void;
  } = {},
): ExecGrant {
  // Revoke existing grant if any
  revokeGrantsForPrincipal(principalId, "Replaced by new grant");

  const grantId = `grant-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  const durationMs = options.durationMs ?? 10 * 60 * 1000; // 10m default
  const maxUses = options.maxUses ?? 1; // 1 use default
  const commandDigest = options.command
    ? crypto.createHash("sha256").update(options.command.trim()).digest("hex")
    : undefined;

  const grant: ExecGrant = {
    grantId,
    principalId,
    displayName,
    workspaceId: options.workspaceId || "*",
    commandDigest,
    createdAt: Date.now(),
    expiresAt: Date.now() + durationMs,
    remainingUses: maxUses,
  };

  grant.timer = setTimeout(() => {
    activeExecGrants.delete(principalId);
    appendAuditLog({
      type: "grant_expired",
      timestamp: Date.now(),
      grantId,
      principalId,
    });
    if (options.onExpire) options.onExpire(grant);
  }, durationMs);

  activeExecGrants.set(principalId, grant);

  appendAuditLog({
    type: "grant_created",
    timestamp: Date.now(),
    grantId,
    principalId,
    displayName,
    workspaceId: grant.workspaceId,
    commandDigest,
    maxUses,
    expiresAt: grant.expiresAt,
  });

  return grant;
}

export function checkAndConsumeExecGrant(
  principalId: string,
  workspaceId?: string,
  command?: string,
): { allowed: boolean; reason?: string; grant?: ExecGrant } {
  const grant = activeExecGrants.get(principalId);
  if (!grant) {
    return {
      allowed: false,
      reason: "No active execution grant found for this device principal. Use /link grant to authorize execution.",
    };
  }

  if (Date.now() > grant.expiresAt) {
    if (grant.timer) clearTimeout(grant.timer);
    activeExecGrants.delete(principalId);
    appendAuditLog({
      type: "grant_expired",
      timestamp: Date.now(),
      grantId: grant.grantId,
      principalId,
    });
    return { allowed: false, reason: "Execution grant has expired" };
  }

  if (grant.remainingUses <= 0) {
    if (grant.timer) clearTimeout(grant.timer);
    activeExecGrants.delete(principalId);
    return { allowed: false, reason: "Execution grant has no remaining uses" };
  }

  // Strictly enforce workspace confinement if grant is confined to specific workspace
  if (grant.workspaceId !== "*") {
    if (!workspaceId || grant.workspaceId !== workspaceId) {
      return {
        allowed: false,
        reason: `Execution grant is confined to workspace "${grant.workspaceId}", requested "${workspaceId || "unspecified"}"`,
      };
    }
  }

  // Strictly enforce command digest matching if grant was bound to a specific command
  if (grant.commandDigest) {
    if (!command) {
      return { allowed: false, reason: "Execution grant is bound to a specific command, none provided" };
    }
    const digest = crypto.createHash("sha256").update(command.trim()).digest("hex");
    if (digest !== grant.commandDigest) {
      return {
        allowed: false,
        reason: "Command does not match the approved command bound to this execution grant",
      };
    }
  }

  grant.remainingUses--;

  appendAuditLog({
    type: "grant_used",
    timestamp: Date.now(),
    grantId: grant.grantId,
    principalId,
    remainingUses: grant.remainingUses,
    workspaceId,
    command: command ? `${command.slice(0, 32)}...` : undefined,
  });

  if (grant.remainingUses <= 0) {
    if (grant.timer) clearTimeout(grant.timer);
    activeExecGrants.delete(principalId);
  }

  return { allowed: true, grant };
}

export function revokeGrantsForPrincipal(principalId: string, reason = "Manual revocation"): number {
  const grant = activeExecGrants.get(principalId);
  if (grant) {
    if (grant.timer) clearTimeout(grant.timer);
    activeExecGrants.delete(principalId);
    appendAuditLog({
      type: "grant_revoked",
      timestamp: Date.now(),
      grantId: grant.grantId,
      principalId,
      reason,
    });
    return 1;
  }
  return 0;
}

export function revokeAllGrants(reason = "System revocation"): number {
  const count = activeExecGrants.size;
  for (const [principalId, grant] of activeExecGrants) {
    if (grant.timer) clearTimeout(grant.timer);
    appendAuditLog({
      type: "grant_revoked",
      timestamp: Date.now(),
      grantId: grant.grantId,
      principalId,
      reason,
    });
  }
  activeExecGrants.clear();
  return count;
}

export function getActiveGrants(): ExecGrant[] {
  return Array.from(activeExecGrants.values());
}

export function updateDevicePermissions(
  fingerprint: string,
  updates: Partial<DevicePermissions>,
  customOmpDir?: string,
): boolean {
  const device = getPairedDevice(fingerprint, customOmpDir);
  if (!device) return false;
  device.permissions = {
    ...device.permissions,
    ...updates,
  };
  savePairedDevice(device, customOmpDir);
  return true;
}
