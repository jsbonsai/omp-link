import * as crypto from "node:crypto";
import { type DevicePermissions, savePairedDevice, getPairedDevice } from "./identity.js";
import { type ApplicationMessage } from "./protocol-schema.js";
import { type ConnectionContext } from "./connection-state.js";
import { appendAuditLog } from "./audit.js";
import { getTimings } from "./config.js";

export interface ExecGrant {
  grantId: string;
  principalId: string;
  agentInstanceId: string;
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

/**
 * A grant's lifetime is `grantDefaultMs` in `link.json` unless the approver names one. There is
 * deliberately no module constant mirroring it: `DEFAULT_TIMINGS.grantDefaultMs` in
 * `src/config.ts` is the single place the default lives (invariant 27).
 */
const DEFAULT_GRANT_MAX_USES = 1;

// Active in-memory execution grants keyed by `${principalId}::${agentInstanceId}`.
// The device principal is shared by every terminal on a machine; the agent instance
// identifies one running terminal. Keying on the pair keeps one agent's approval from
// being silently consumed by a sibling agent on the same device.
const activeExecGrants = new Map<string, ExecGrant>();

// Capability required to accept an inbound application message, or "correlated" for
// response frames that are authorized by the pending request they answer.
export type RequiredCapability = keyof DevicePermissions | "correlated";

const CORRELATED_RESPONSE_TYPES: Partial<Record<ApplicationMessage["type"], true>> = {
  rpc_response: true,
  file_ack: true,
  compact_response: true,
};

/**
 * Response frames carry no standing capability requirement. A peer allowed to ask a
 * question must be able to receive the answer, and a peer whose capabilities were
 * revoked mid-flight must still be able to fail the caller fast rather than have its
 * response dropped by the capability gate (which hangs the caller until its timeout).
 *
 * INVARIANT: transport-level acceptance is NOT authorization. A true result here only
 * says "do not require a standing capability". The dispatcher MUST verify that the
 * frame matches a locally recorded pending request (by `id` / `transferId`) and that
 * the frame's authenticated origin equals that request's expected principal and agent
 * instance. An unmatched or mis-originated response MUST be dropped and audited.
 */
export function isCorrelatedResponse(message: ApplicationMessage): boolean {
  return CORRELATED_RESPONSE_TYPES[message.type] === true;
}

export function requiredPermission(message: ApplicationMessage): RequiredCapability {
  if (isCorrelatedResponse(message)) return "correlated";

  switch (message.type) {
    case "chat":
    case "direct_message":
      return "message";
    case "compact_request":
      return "compact";
    case "file_offer":
    case "file_chunk":
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
): { permitted: boolean; required: RequiredCapability; reason?: string } {
  const req = requiredPermission(message);

  // Correlated responses are gated by the dispatcher's pending-request table, never by
  // a standing capability. See isCorrelatedResponse for the invariant this relies on.
  if (req === "correlated") {
    return { permitted: true, required: req };
  }

  if (!permissions) {
    return { permitted: false, required: req, reason: "No device permissions attached to connection" };
  }

  const granular = permissions[req];
  if (granular === true) {
    return { permitted: true, required: req };
  }

  // Denial wins over the legacy alias: an explicit `false` on the granular capability is
  // authoritative and can never be overridden by `inspect: true`.
  if (granular === false) {
    return {
      permitted: false,
      required: req,
      reason: `Permission denied: "${req}" is explicitly denied for this device`,
    };
  }

  // Legacy `inspect` alias, positive direction only: honored solely when the granular
  // capability is unset, i.e. a paired-device record predating granular capabilities.
  if (
    permissions.inspect === true &&
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
  agentInstanceId: string,
  displayName: string,
  options: {
    workspaceId?: string;
    command?: string;
    durationMs?: number;
    maxUses?: number;
    onExpire?: (grant: ExecGrant) => void;
    /**
     * State root whose `link.json` supplies `grantDefaultMs` when `durationMs` is omitted.
     * Threaded exactly like `identity.ts`: a caller against a temp directory must not pick up
     * the operator's real `~/.omp`.
     */
    customOmpDir?: string;
  } = {},
): ExecGrant {
  // Replace only this agent instance's grant; sibling terminals on the same device keep theirs.
  revokeGrantsForPrincipal(principalId, agentInstanceId, "Replaced by new grant");

  const key = `${principalId}::${agentInstanceId}`;
  const grantId = `grant-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  // Config, not a constant: `grantDefaultMs` is an operator tunable. Grant creation is a
  // human-paced event and `getTimings` is memoised per directory, so this is not a hot read.
  const durationMs = options.durationMs ?? getTimings(options.customOmpDir).grantDefaultMs;
  const maxUses = options.maxUses ?? DEFAULT_GRANT_MAX_USES;
  const commandDigest = options.command
    ? crypto.createHash("sha256").update(options.command.trim()).digest("hex")
    : undefined;

  const grant: ExecGrant = {
    grantId,
    principalId,
    agentInstanceId,
    displayName,
    workspaceId: options.workspaceId || "*",
    commandDigest,
    createdAt: Date.now(),
    expiresAt: Date.now() + durationMs,
    remainingUses: maxUses,
  };

  grant.timer = setTimeout(() => {
    // Only expire the grant still registered under this key; a replacement grant for the
    // same agent instance must never be torn down by its predecessor's timer.
    if (activeExecGrants.get(key) !== grant) return;
    activeExecGrants.delete(key);
    appendAuditLog({
      type: "grant_expired",
      timestamp: Date.now(),
      grantId,
      principalId,
      agentInstanceId,
    });
    if (options.onExpire) options.onExpire(grant);
  }, durationMs);

  activeExecGrants.set(key, grant);

  appendAuditLog({
    type: "grant_created",
    timestamp: Date.now(),
    grantId,
    principalId,
    agentInstanceId,
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
  agentInstanceId: string,
  workspaceId?: string,
  command?: string,
): { allowed: boolean; reason?: string; grant?: ExecGrant } {
  const key = `${principalId}::${agentInstanceId}`;
  const grant = activeExecGrants.get(key);
  if (!grant) {
    return {
      allowed: false,
      reason: "No active execution grant found for this agent instance. Use /link grant to authorize execution.",
    };
  }

  if (Date.now() > grant.expiresAt) {
    clearTimeout(grant.timer);
    activeExecGrants.delete(key);
    appendAuditLog({
      type: "grant_expired",
      timestamp: Date.now(),
      grantId: grant.grantId,
      principalId,
      agentInstanceId,
    });
    return { allowed: false, reason: "Execution grant has expired" };
  }

  if (grant.remainingUses <= 0) {
    clearTimeout(grant.timer);
    activeExecGrants.delete(key);
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
    agentInstanceId,
    remainingUses: grant.remainingUses,
    workspaceId,
    command: command ? `${command.slice(0, 32)}...` : undefined,
  });

  if (grant.remainingUses <= 0) {
    clearTimeout(grant.timer);
    activeExecGrants.delete(key);
  }

  return { allowed: true, grant };
}

/**
 * Revokes grants for a device principal. Omitting `agentInstanceId` revokes every agent
 * instance of that principal (device-wide revocation, e.g. unpairing); passing one
 * revokes just that terminal and leaves sibling terminals on the same device intact.
 */
export function revokeGrantsForPrincipal(
  principalId: string,
  agentInstanceId?: string,
  reason = "Manual revocation",
): number {
  let revoked = 0;
  for (const [key, grant] of activeExecGrants) {
    if (grant.principalId !== principalId) continue;
    if (agentInstanceId !== undefined && grant.agentInstanceId !== agentInstanceId) continue;
    clearTimeout(grant.timer);
    activeExecGrants.delete(key);
    appendAuditLog({
      type: "grant_revoked",
      timestamp: Date.now(),
      grantId: grant.grantId,
      principalId,
      agentInstanceId: grant.agentInstanceId,
      reason,
    });
    revoked++;
  }
  return revoked;
}

export function revokeAllGrants(reason = "System revocation"): number {
  const count = activeExecGrants.size;
  for (const grant of activeExecGrants.values()) {
    clearTimeout(grant.timer);
    appendAuditLog({
      type: "grant_revoked",
      timestamp: Date.now(),
      grantId: grant.grantId,
      principalId: grant.principalId,
      agentInstanceId: grant.agentInstanceId,
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
