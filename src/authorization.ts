import { type DevicePermissions, savePairedDevice, getPairedDevice } from "./identity.js";
import { type ApplicationMessage } from "./protocol-schema.js";
import { type ConnectionContext } from "./connection-state.js";

export interface ExecGrant {
  grantId: string;
  principalId: string;
  displayName: string;
  workspaceId: string;
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
    case "rpc_request":
      return message.action === "exec" ? "execRequest" : "inspect";
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
  if (!permissions[req]) {
    return {
      permitted: false,
      required: req,
      reason: `Permission denied: action requires "${req}" capability, which is not granted to this device`,
    };
  }
  return { permitted: true, required: req };
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

  const grant: ExecGrant = {
    grantId,
    principalId,
    displayName,
    workspaceId: options.workspaceId || "*",
    createdAt: Date.now(),
    expiresAt: Date.now() + durationMs,
    remainingUses: maxUses,
  };

  grant.timer = setTimeout(() => {
    activeExecGrants.delete(principalId);
    if (options.onExpire) options.onExpire(grant);
  }, durationMs);

  activeExecGrants.set(principalId, grant);
  return grant;
}

export function checkAndConsumeExecGrant(
  principalId: string,
  workspaceId?: string,
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
    return { allowed: false, reason: "Execution grant has expired" };
  }

  if (grant.remainingUses <= 0) {
    if (grant.timer) clearTimeout(grant.timer);
    activeExecGrants.delete(principalId);
    return { allowed: false, reason: "Execution grant has no remaining uses" };
  }

  if (grant.workspaceId !== "*" && workspaceId && grant.workspaceId !== workspaceId) {
    return {
      allowed: false,
      reason: `Execution grant is confined to workspace "${grant.workspaceId}", requested "${workspaceId}"`,
    };
  }

  grant.remainingUses--;
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
    return 1;
  }
  return 0;
}

export function revokeAllGrants(reason = "System revocation"): number {
  const count = activeExecGrants.size;
  for (const [_, grant] of activeExecGrants) {
    if (grant.timer) clearTimeout(grant.timer);
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
