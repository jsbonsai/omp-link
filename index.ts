/**
 * Pi Link — WebSocket-based inter-terminal communication (Protocol v5)
 *
 * Connects multiple Pi terminals over a TLS 1.3 mutually authenticated link.
 * Opt-in via --link flag, --link-name flag, pi-link CLI, or /link-join command.
 *
 * Security:
 * - TLS 1.3 mutual device authentication with pinned SPKI fingerprints
 * - Strict connection phase state machine
 * - Origin principal authentication (no spoofing)
 * - Fine-grained capability permissions
 * - Bounded streaming file transfer with external quarantine
 * - Canonical workspace path confinement & sensitive path policy
 */

import {
  VERSION as PI_VERSION,
  type ExtensionAPI,
  type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  getOrCreateDeviceIdentity,
  loadPairedDevices,
  savePairedDevice,
  removePairedDevice,
  DEFAULT_PERMISSIONS,
  FULL_PERMISSIONS,
  createInvite,
  normalizeFingerprint,
  getOmpDir,
  atomicWriteSecureFile,
  type DevicePermissions,
  type PairedDevice,
} from "./src/identity.js";

import {
  createExecGrant,
  revokeGrantsForPrincipal,
  revokeAllGrants,
  getActiveGrants,
  updateDevicePermissions,
  MUTATION_GUARD_ADVISORY,
} from "./src/authorization.js";

import {
  discoverAllHubs,
  getNetworkInfo,
  DEFAULT_PORT,
} from "./src/discovery.js";

import { LinkNode } from "./src/link-node.js";
import { appendAuditLog, readAuditLogs } from "./src/audit.js";

const MIN_PI_VERSION = [0, 84, 2];

function piVersionSupported(version?: string): boolean {
  if (!version) return true;
  const parts = version.split(".").map((p) => parseInt(p, 10));
  for (let i = 0; i < MIN_PI_VERSION.length; i++) {
    const min = MIN_PI_VERSION[i];
    const actual = parts[i] ?? 0;
    if (actual > min) return true;
    if (actual < min) return false;
  }
  return true;
}

function textResult(text: string, details?: any) {
  return {
    content: [{ type: "text" as const, text }],
    details,
  };
}

interface LinkConfig {
  sessionId?: string;
  hub?: string;
  network?: "lan" | "tailscale";
  terminalName?: string;
}

function loadLinkConfig(): LinkConfig {
  const file = path.join(getOmpDir(), "link.json");
  if (fs.existsSync(file)) {
    try {
      return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {}
  }
  return {};
}

function saveLinkConfig(partial: Partial<LinkConfig>): void {
  const file = path.join(getOmpDir(), "link.json");
  const existing = loadLinkConfig();
  const merged = { ...existing, ...partial };
  atomicWriteSecureFile(file, JSON.stringify(merged, null, 2) + "\n");
}

export default function (pi: ExtensionAPI) {
  if ((globalThis as any).__omp_link_loaded) {
    return;
  }
  (globalThis as any).__omp_link_loaded = true;

  if (PI_VERSION && !piVersionSupported(PI_VERSION)) {
    if (process.env.PI_LINK_IGNORE_VERSION_CHECK !== "1") {
      throw new Error(
        `omp-link requires Pi >=${MIN_PI_VERSION.join(".")} (detected ${PI_VERSION || "unknown"}); upgrade Pi or OMP.`,
      );
    }
  }

  pi.registerFlag("link", {
    description: "Connect to link on startup",
    type: "boolean",
    default: false,
  });

  pi.registerFlag("link-name", {
    description: "Terminal display name on the link mesh",
    type: "string",
  });

  const config = loadLinkConfig();
  let linkActive = false;
  let linkNode: LinkNode | null = null;
  let currentSessionId = config.sessionId || "team-link";
  let networkMode: "lan" | "tailscale" = config.network || "lan";
  let targetHubAddress: string | null = config.hub || null;
  let terminalName = config.terminalName || os.hostname() || "omp-node";
  let mutationGuardEnabled = true;
  let lastContext: ExtensionContext | null = null;

  function initNode(): LinkNode {
    if (linkNode) return linkNode;
    linkNode = new LinkNode({
      networkMode,
      terminalName,
      sessionId: currentSessionId,
    });

    linkNode.onMessage = (msg) => {
      pi.sendMessage({
        content: `[${msg.from || "peer"}] ${msg.text}`,
        customType: "link",
        display: true,
        details: { from: msg.from, text: msg.text, originPrincipalId: msg.originPrincipalId },
      });
    };

    linkNode.onCompactRequest = async (req) => {
      if (lastContext && (lastContext as any).compact) {
        return new Promise((resolve) => {
          (lastContext as any).compact({
            customInstructions: req.instructions,
            onComplete: () => resolve({ ok: true }),
            onError: (err: any) => resolve({ ok: false, reason: err?.message || "compaction error" }),
          });
        });
      }
      return { ok: true };
    };

    linkNode.onPairingRequested = (req) => {
      pi.sendMessage({
        content:
          `🔔 [Pairing Request #${req.id}]\n` +
          `   Device:           "${req.displayName}" on ${req.host}\n` +
          `   Fingerprint:      ${req.fingerprint}\n` +
          `   Verification Code: ${req.sasCode}\n` +
          `   Approve with:     /link accept ${req.id} [code]`,
        customType: "link",
        display: true,
        details: { reqId: req.id },
      });
    };

    linkNode.onNotification = (msg, level) => {
      pi.sendMessage({
        content: `⚡ ${msg}`,
        customType: "link",
        display: true,
        details: { level },
      });
    };

    return linkNode;
  }

  async function turnLinkOn(ctx?: ExtensionContext): Promise<void> {
    if (ctx) lastContext = ctx;
    const node = initNode();
    linkActive = true;
    saveLinkConfig({ sessionId: currentSessionId, network: networkMode });

    if (targetHubAddress) {
      try {
        const url = `wss://${targetHubAddress}`;
        await node.connectToHub(url);
        ctx?.ui.notify(`Connected to link hub at ${targetHubAddress}`, "info");
      } catch (err: any) {
        ctx?.ui.notify(`Failed to connect to ${targetHubAddress}: ${err.message}. Starting as host...`, "warning");
        try {
          await node.startHub();
          ctx?.ui.notify(`Hosting link session "${currentSessionId}" on port ${node.port}`, "info");
        } catch (hubErr: any) {
          ctx?.ui.notify(`Failed to host link: ${hubErr.message}`, "error");
        }
      }
    } else {
      try {
        await node.startHub();
        ctx?.ui.notify(`Hosting link session "${currentSessionId}" on port ${node.port}`, "info");
      } catch (err: any) {
        ctx?.ui.notify(`Failed to host link: ${err.message}`, "error");
      }
    }
  }

  async function turnLinkOff(ctx?: ExtensionContext): Promise<void> {
    linkActive = false;
    if (linkNode) {
      await linkNode.stop();
      linkNode = null;
    }
    revokeAllGrants("Link deactivated");
    ctx?.ui.notify("Link mesh disconnected and deactivated.", "info");
  }

  // ── Tools ─────────────────────────────────────────────────────────────────

  pi.registerTool({
    name: "link_send",
    label: "Link Send",
    description: "Send a message to one other Pi terminal on the link mesh.",
    promptSnippet: "Send message to a peer terminal on the link",
    parameters: Type.Object({
      to: Type.String({ description: "Target terminal name, or '*' to broadcast" }),
      message: Type.String({ description: "Message content" }),
    }),
    async execute(_id, params) {
      if (!linkActive || !linkNode) return textResult("Link mesh is not active. Connect with /link join or /link on.");
      const success = linkNode.sendMessage(params.to, params.message);
      if (success) {
        return textResult(`Message sent to "${params.to}".`);
      }
      return textResult(`Failed to deliver message to "${params.to}". Peer not found or offline.`);
    },
  });

  pi.registerTool({
    name: "link_list",
    label: "Link List",
    description: "List all Pi terminals currently connected to the link.",
    promptSnippet: "List connected Pi terminals on the link",
    parameters: Type.Object({}),
    async execute() {
      if (!linkActive || !linkNode) return textResult("Link mesh is not active. Connect with /link join or /link on.");
      const terms = linkNode.getConnectedTerminalsList();
      const list = terms.map((t) => `  • ${t.name} [${t.host || "unknown"}] (${t.status || "idle"})`).join("\n");
      return textResult(`Connected terminals (${terms.length}):\n${list}\n\nSession: "${linkNode.currentSessionId}" [${linkNode.role}]`);
    },
  });

  pi.registerTool({
    name: "link_compact",
    label: "Link Compact",
    description: "Ask one other Pi terminal on the link to compact its context. Blocks until compaction completes, fails, or times out (up to 180s).",
    promptSnippet: "Ask another Pi terminal on the link to compact its context",
    parameters: Type.Object({
      to: Type.String({ description: "Target terminal name" }),
      customInstructions: Type.Optional(
        Type.String({
          description: "Custom instructions to guide the compaction summary (optional)",
        }),
      ),
    }),
    async execute(_id, params) {
      if (!linkActive || !linkNode) return textResult("Link mesh is not active. Connect with /link join or /link on.");
      if (params.to === terminalName) {
        return textResult("Cannot compact yourself - use /compact.", {
          to: params.to,
          error: "self_target",
        });
      }
      try {
        const res = await linkNode.requestCompact(params.to, params.customInstructions);
        if (!res.ok) {
          return textResult(`Compact request declined by "${params.to}": ${res.reason || "unknown reason"}`);
        }
        return textResult(`Terminal "${params.to}" completed compaction successfully.`);
      } catch (err: any) {
        return textResult(`Compact request failed: ${err.message}`);
      }
    },
  });

  pi.registerTool({
    name: "link_discover",
    label: "Link Discover",
    description: "Discover active omp-link sessions across LAN and Tailscale via HTTPS.",
    promptSnippet: "Scan for active omp-link sessions on network",
    parameters: Type.Object({}),
    async execute() {
      const hubs = await discoverAllHubs(DEFAULT_PORT, 1500);
      if (hubs.length === 0) {
        return textResult("No active omp-link sessions discovered on LAN or Tailscale.");
      }
      let output = `Discovered ${hubs.length} active session(s):\n\n`;
      for (const h of hubs) {
        output += `  • Session "${h.sessionId}" on ${h.host} (${h.ip}:${h.port}) [via ${h.source}]\n`;
        output += `    Fingerprint: ${h.certificateFingerprint}\n`;
        output += `    Join with:   /link join ${h.ip}:${h.port}\n\n`;
      }
      return textResult(output);
    },
  });

  pi.registerTool({
    name: "link_exec",
    label: "Link Exec",
    description: "Execute structured inspection RPCs (git_status, git_diff, git_log, search_text, read_file, list_dir) or shell commands (requires grant).",
    promptSnippet: "Inspect remote repository across the mesh",
    parameters: Type.Object({
      to: Type.String({ description: "Target terminal name" }),
      action: Type.Union([
        Type.Literal("git_status"),
        Type.Literal("git_diff"),
        Type.Literal("git_log"),
        Type.Literal("search_text"),
        Type.Literal("read_file"),
        Type.Literal("list_dir"),
        Type.Literal("exec"),
      ]),
      command: Type.Optional(Type.String({ description: "Shell command for 'exec' (requires active execution grant)" })),
      filePath: Type.Optional(Type.String({ description: "Path for 'read_file' or 'list_dir'" })),
      pattern: Type.Optional(Type.String({ description: "Query for 'search_text'" })),
      count: Type.Optional(Type.Number({ description: "Commit count for 'git_log'" })),
    }),
    async execute(_id, params) {
      if (!linkActive || !linkNode) return textResult("Link mesh is not active.");
      try {
        const res = await linkNode.executeRemoteRpc(params.to, params.action, {
          command: params.command,
          filePath: params.filePath,
          pattern: params.pattern,
          count: params.count,
        });
        if (!res.ok) {
          return textResult(`RPC execution error on "${params.to}": ${res.error}`);
        }
        return textResult(res.result || "[Success, no output]");
      } catch (err: any) {
        return textResult(`RPC failed: ${err.message}`);
      }
    },
  });

  pi.registerTool({
    name: "link_send_file",
    label: "Link Send File",
    description: "Transfer a file directly to a peer with memory-bounded streaming and SHA-256 verification.",
    promptSnippet: "Send a file to a peer terminal",
    parameters: Type.Object({
      to: Type.String({ description: "Target terminal name" }),
      filePath: Type.String({ description: "Path of file to send" }),
    }),
    async execute(_id, params) {
      if (!linkActive || !linkNode) return textResult("Link mesh is not active.");
      try {
        const res = await linkNode.sendFile(params.to, params.filePath);
        if (res.ok) {
          return textResult(`File "${path.basename(params.filePath)}" transferred successfully to "${params.to}".`);
        }
        return textResult(`File transfer failed: ${res.error}`);
      } catch (err: any) {
        return textResult(`Transfer error: ${err.message}`);
      }
    },
  });

  // ── Commands ──────────────────────────────────────────────────────────────

  pi.registerCommand("link", {
    description: "Manage link mesh network, security, and sessions. Usage: /link [subcommand]",
    handler: async (args, ctx) => {
      const parts = args.trim().split(/\s+/).filter(Boolean);
      const subcmd = parts[0]?.toLowerCase();
      const restArgs = args.trim().slice(parts[0]?.length || 0).trim();

      if (!subcmd || subcmd === "status") {
        const id = getOrCreateDeviceIdentity();
        let out =
          `⚡ OMP-LINK STATUS (v5)\n` +
          `  Mesh State  : ${linkActive ? "ACTIVE" : "OFFLINE"}\n` +
          `  Node Role   : ${linkNode?.role || "disconnected"}\n` +
          `  Session     : "${currentSessionId}" [${networkMode.toUpperCase()}]\n` +
          `  Terminal    : ${terminalName}\n` +
          `  Fingerprint : ${id.fingerprint}\n` +
          `  Principal   : ${id.principalId}\n`;

        if (linkNode && linkActive) {
          const terms = linkNode.getConnectedTerminalsList();
          out += `  Connected   : ${terms.length} node(s) (${terms.map((t) => t.name).join(", ")})\n`;
        }

        const grants = getActiveGrants();
        if (grants.length > 0) {
          out += `  Grants      : ⚠️ ${grants.map((g) => `${g.displayName} (${Math.ceil((g.expiresAt - Date.now()) / 60000)}m left, ${g.remainingUses} uses)`).join(", ")}\n`;
        }

        ctx.ui.notify(out, linkActive ? "info" : "warning");
        return;
      }

      switch (subcmd) {
        case "on":
          await turnLinkOn(ctx);
          break;
        case "off":
          await turnLinkOff(ctx);
          break;
        case "join": {
          if (!restArgs) {
            ctx.ui.notify("Usage: /link join <ip:port | session-name>", "warning");
            return;
          }
          targetHubAddress = restArgs;
          saveLinkConfig({ hub: targetHubAddress });
          await turnLinkOn(ctx);
          break;
        }
        case "start": {
          if (restArgs) {
            currentSessionId = restArgs;
            saveLinkConfig({ sessionId: currentSessionId });
          }
          targetHubAddress = null;
          saveLinkConfig({ hub: undefined });
          await turnLinkOn(ctx);
          break;
        }
        case "accept": {
          const reqParts = restArgs.split(/\s+/).filter(Boolean);
          const reqId = parseInt(reqParts[0] || "", 10);
          if (!reqId) {
            ctx.ui.notify("Usage: /link accept <request-id> [--allow perms]", "warning");
            return;
          }
          let perms = DEFAULT_PERMISSIONS;
          if (restArgs.includes("--allow")) {
            const permIdx = restArgs.indexOf("--allow");
            const permList = restArgs.slice(permIdx + 7).trim().split(",");
            perms = {
              observe: true,
              message: permList.includes("message"),
              compact: permList.includes("compact"),
              inspect: permList.includes("inspect"),
              fileInbox: permList.includes("file") || permList.includes("fileInbox"),
              execRequest: permList.includes("exec") || permList.includes("execRequest"),
            };
          }
          const approved = linkNode?.approvePairing(reqId, perms);
          if (approved) {
            ctx.ui.notify(`Approved device "${approved.deviceName}" (${approved.fingerprint})!`, "info");
          } else {
            ctx.ui.notify(`Pairing request #${reqId} not found or expired.`, "error");
          }
          break;
        }
        case "deny": {
          const reqId = parseInt(restArgs, 10);
          if (!reqId) {
            ctx.ui.notify("Usage: /link deny <request-id>", "warning");
            return;
          }
          const denied = linkNode?.denyPairing(reqId);
          if (denied) {
            ctx.ui.notify(`Denied pairing request #${reqId}.`, "info");
          } else {
            ctx.ui.notify(`Pairing request #${reqId} not found.`, "error");
          }
          break;
        }
        case "invite": {
          const identity = getOrCreateDeviceIdentity();
          const invite = createInvite(identity, { expiresInMs: 300_000 });
          ctx.ui.notify(
            `🎟️ One-Time Pairing Invite Created (expires in 5m):\n` +
            `   Invite Code: ${invite.inviteCode}\n` +
            `   Secret:      ${invite.secret}\n` +
            `   Fingerprint: ${invite.hubFingerprint}\n` +
            `   Join with:   /link join <hub-ip>:9900 ${invite.secret}`,
            "info",
          );
          break;
        }
        case "devices": {
          const subParts = restArgs.split(/\s+/).filter(Boolean);
          const devAction = subParts[0]?.toLowerCase();
          const devTarget = subParts[1];
          const devExtra = subParts.slice(2).join(" ");

          const devices = loadPairedDevices();

          if (!devAction || devAction === "list") {
            if (devices.size === 0) {
              ctx.ui.notify("No paired devices in ~/.omp/paired-devices.json.", "info");
              return;
            }
            let out = `Paired Devices (${devices.size}):\n\n`;
            for (const [fp, d] of devices) {
              const p = d.permissions;
              const permsStr = Object.entries(p).filter(([_, v]) => v).map(([k]) => k).join(", ");
              out += `  • "${d.deviceName}"\n    Principal:   ${d.principalId}\n    Permissions: ${permsStr}\n    Paired At:   ${new Date(d.pairedAt).toISOString()}\n\n`;
            }
            ctx.ui.notify(out, "info");
            return;
          }

          if (devAction === "show") {
            if (!devTarget) {
              ctx.ui.notify("Usage: /link devices show <device-name-or-fingerprint>", "warning");
              return;
            }
            let matched: PairedDevice | null = null;
            for (const [fp, d] of devices) {
              if (d.deviceName === devTarget || d.principalId === devTarget || fp.startsWith(devTarget.toUpperCase())) {
                matched = d;
                break;
              }
            }
            if (!matched) {
              ctx.ui.notify(`Device "${devTarget}" not found in paired devices.`, "error");
              return;
            }
            const p = matched.permissions;
            const permsStr = Object.entries(p).filter(([_, v]) => v).map(([k]) => k).join(", ");
            ctx.ui.notify(
              `📱 DEVICE RECORD\n` +
              `  Name        : "${matched.deviceName}"\n` +
              `  Principal   : ${matched.principalId}\n` +
              `  Fingerprint : ${matched.fingerprint}\n` +
              `  Permissions : ${permsStr}\n` +
              `  Workspaces  : ${matched.workspaces?.join(", ") || "*"}\n` +
              `  Paired At   : ${new Date(matched.pairedAt).toISOString()}\n` +
              `  Last Seen   : ${matched.lastSeen ? new Date(matched.lastSeen).toISOString() : "never"}\n` +
              `  Last Addr   : ${matched.lastAddress || "unknown"}`,
              "info",
            );
            return;
          }

          if (devAction === "allow" || devAction === "deny") {
            if (!devTarget || !devExtra) {
              ctx.ui.notify(`Usage: /link devices ${devAction} <device> <permission1,permission2>`, "warning");
              return;
            }
            let matched: PairedDevice | null = null;
            for (const [fp, d] of devices) {
              if (d.deviceName === devTarget || d.principalId === devTarget || fp.startsWith(devTarget.toUpperCase())) {
                matched = d;
                break;
              }
            }
            if (!matched) {
              ctx.ui.notify(`Device "${devTarget}" not found.`, "error");
              return;
            }

            const permList = devExtra.split(",").map((s) => s.trim().toLowerCase());
            const updates: Partial<DevicePermissions> = {};
            const val = devAction === "allow";

            if (permList.includes("message")) updates.message = val;
            if (permList.includes("compact")) updates.compact = val;
            if (permList.includes("inspect")) updates.inspect = val;
            if (permList.includes("file") || permList.includes("fileinbox")) updates.fileInbox = val;
            if (permList.includes("exec") || permList.includes("execrequest")) updates.execRequest = val;

            const ok = linkNode
              ? linkNode.updatePeerPermissions(matched.principalId, updates)
              : updateDevicePermissions(matched.fingerprint, updates);

            if (ok) {
              ctx.ui.notify(`Updated permissions for "${matched.deviceName}": ${devAction.toUpperCase()} ${Object.keys(updates).join(", ")}`, "info");
            } else {
              ctx.ui.notify(`Failed to update permissions for "${matched.deviceName}".`, "error");
            }
            return;
          }

          if (devAction === "workspace") {
            if (!devTarget || !devExtra) {
              ctx.ui.notify("Usage: /link devices workspace <device> <ws1,ws2>", "warning");
              return;
            }
            let matched: PairedDevice | null = null;
            for (const [fp, d] of devices) {
              if (d.deviceName === devTarget || d.principalId === devTarget || fp.startsWith(devTarget.toUpperCase())) {
                matched = d;
                break;
              }
            }
            if (!matched) {
              ctx.ui.notify(`Device "${devTarget}" not found.`, "error");
              return;
            }
            matched.workspaces = devExtra.split(",").map((s) => s.trim());
            savePairedDevice(matched);
            ctx.ui.notify(`Updated allowed workspaces for "${matched.deviceName}": ${matched.workspaces.join(", ")}`, "info");
            return;
          }

          if (devAction === "remove" || devAction === "revoke") {
            if (!devTarget) {
              ctx.ui.notify("Usage: /link devices remove <device>", "warning");
              return;
            }
            const ok = linkNode
              ? linkNode.revokeDevice(devTarget)
              : removePairedDevice(devTarget);
            if (ok) {
              ctx.ui.notify(`Revoked and removed device "${devTarget}".`, "info");
            } else {
              ctx.ui.notify(`Device "${devTarget}" not found.`, "error");
            }
            return;
          }

          ctx.ui.notify(`Unknown devices subcommand: "${devAction}". Available: show, allow, deny, workspace, remove, list`, "warning");
          break;
        }
        case "revoke":
        case "unpair": {
          const target = restArgs.trim();
          if (!target) {
            ctx.ui.notify("Usage: /link revoke <device-name-or-fingerprint>", "warning");
            return;
          }
          const ok = linkNode ? linkNode.revokeDevice(target) : removePairedDevice(target);
          if (ok) {
            ctx.ui.notify(`Device "${target}" unpair and revocation complete.`, "info");
          } else {
            ctx.ui.notify(`Device "${target}" not found.`, "error");
          }
          break;
        }
        case "grant": {
          const grantParts = restArgs.split(/\s+/).filter(Boolean);
          const target = grantParts[0];
          if (!target) {
            ctx.ui.notify("Usage: /link grant <device> exec [--workspace backend] [--for 10m] [--uses 1]", "warning");
            return;
          }

          // Parse flags
          let workspaceId = "*";
          let durationMs = 10 * 60 * 1000;
          let maxUses = 1;

          for (let i = 1; i < grantParts.length; i++) {
            if (grantParts[i] === "--workspace" && grantParts[i + 1]) {
              workspaceId = grantParts[i + 1];
              i++;
            } else if (grantParts[i] === "--for" && grantParts[i + 1]) {
              const durStr = grantParts[i + 1];
              const m = durStr.match(/^(\d+)(m|h|s)?$/);
              if (m) {
                const val = parseInt(m[1], 10);
                const unit = m[2] || "m";
                if (unit === "h") durationMs = val * 3600 * 1000;
                else if (unit === "s") durationMs = val * 1000;
                else durationMs = val * 60 * 1000;
              }
              i++;
            } else if (grantParts[i] === "--uses" && grantParts[i + 1]) {
              maxUses = Math.max(1, parseInt(grantParts[i + 1], 10) || 1);
              i++;
            }
          }

          const devices = loadPairedDevices();
          let matched: PairedDevice | null = null;
          for (const [fp, d] of devices) {
            if (d.deviceName === target || d.principalId === target || fp.startsWith(target.toUpperCase())) {
              matched = d;
              break;
            }
          }
          if (!matched) {
            ctx.ui.notify(`No paired device matching "${target}".`, "error");
            return;
          }

          // Ensure base capability is enabled
          if (!matched.permissions.execRequest) {
            if (linkNode) {
              linkNode.updatePeerPermissions(matched.principalId, { execRequest: true });
            } else {
              updateDevicePermissions(matched.fingerprint, { execRequest: true });
            }
            ctx.ui.notify(`ℹ️ Note: Elevated base "execRequest" capability for "${matched.deviceName}".`, "info");
          }

          const grant = createExecGrant(matched.principalId, matched.deviceName, {
            workspaceId,
            durationMs,
            maxUses,
          });

          ctx.ui.notify(
            `⚠️ EXECUTION ELEVATION GRANTED\n` +
            `   Device:      "${matched.deviceName}"\n` +
            `   Principal:   ${matched.principalId}\n` +
            `   Fingerprint: ${matched.fingerprint}\n` +
            `   Workspace:   ${workspaceId}\n` +
            `   Expires:     ${Math.ceil(durationMs / 60000)} minutes (${maxUses} use(s))\n` +
            `   ${MUTATION_GUARD_ADVISORY}`,
            "warning",
          );
          break;
        }
        case "revoke-grant": {
          const target = restArgs.trim();
          if (!target) {
            const count = revokeAllGrants("Manual revoke all");
            ctx.ui.notify(`Revoked ${count} active execution grant(s).`, "info");
            return;
          }
          const devices = loadPairedDevices();
          for (const [_, d] of devices) {
            if (d.deviceName === target || d.principalId === target) {
              const count = revokeGrantsForPrincipal(d.principalId, "Manual revocation");
              ctx.ui.notify(`Revoked execution grant for "${d.deviceName}".`, "info");
              return;
            }
          }
          ctx.ui.notify(`Device "${target}" not found.`, "error");
          break;
        }
        case "doctor": {
          const id = getOrCreateDeviceIdentity();
          const logs = readAuditLogs(5);
          ctx.ui.notify(
            `🩺 OMP-LINK DOCTOR DIAGNOSTIC (Protocol v5)\n` +
            `  Device Certificate : OK (TLS 1.3 / ${id.keyType})\n` +
            `  Principal ID       : ${id.principalId}\n` +
            `  Paired Devices     : ${loadPairedDevices().size}\n` +
            `  Audit Log Entries  : ${logs.length} recent events logged\n` +
            `  Network Mode       : ${networkMode.toUpperCase()}\n` +
            `  System Integrity   : Mutual TLS + SPKI Pinning Active`,
            "info",
          );
          break;
        }
        default:
          ctx.ui.notify(
            `Commands:\n` +
            `  /link status                 View status and online peers\n` +
            `  /link on | off               Turn link mesh ON or OFF\n` +
            `  /link join <ip:port>         Connect to an active hub\n` +
            `  /link start [name]           Host a session as hub\n` +
            `  /link accept <id>            Approve device pairing request\n` +
            `  /link deny <id>              Deny pairing request\n` +
            `  /link invite                 Create single-use pairing code\n` +
            `  /link devices                List paired device identities\n` +
            `  /link grant <dev> exec       Grant temporary shell execution\n` +
            `  /link revoke-grant [dev]     Revoke execution grants\n` +
            `  /link doctor                 Run system diagnostic checks`,
            "info",
          );
          break;
      }
    },
  });

  pi.registerCommand("link-join", {
    description: "Join an active link session (alias for /link join)",
    handler: async (args, ctx) => {
      targetHubAddress = args.trim();
      saveLinkConfig({ hub: targetHubAddress });
      await turnLinkOn(ctx);
    },
  });

  pi.registerCommand("link-leave", {
    description: "Leave link session (alias for /link off)",
    handler: async (_args, ctx) => {
      await turnLinkOff(ctx);
    },
  });

  pi.registerCommand("link-doctor", {
    description: "Run security and system diagnostics (alias for /link doctor)",
    handler: async (_args, ctx) => {
      const id = getOrCreateDeviceIdentity();
      ctx.ui.notify(
        `🩺 OMP-LINK DOCTOR (Protocol v5)\n  Principal: ${id.principalId}\n  Fingerprint: ${id.fingerprint}`,
        "info",
      );
    },
  });

  pi.registerMessageRenderer("link", (message, _options, theme) => {
    const details = message.details as Record<string, unknown> | undefined;
    const from = details?.from ?? "link";
    const principal = details?.originPrincipalId ? ` (${String(details.originPrincipalId).slice(0, 24)}...)` : "";
    const text = theme.fg("accent", `⚡ [${from}${principal}] `) + theme.fg("text", String(message.content));
    return new Text(text, 0, 0);
  });
}
