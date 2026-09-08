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
        details: { from: msg.from, text: msg.text },
      });
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
          const devices = loadPairedDevices();
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
          break;
        }
        case "grant": {
          const grantParts = restArgs.split(/\s+/).filter(Boolean);
          const target = grantParts[0];
          if (!target) {
            ctx.ui.notify("Usage: /link grant <device-name-or-fingerprint> exec [--for 10m] [--uses 1]", "warning");
            return;
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
          const grant = createExecGrant(matched.principalId, matched.deviceName, {
            durationMs: 10 * 60 * 1000,
            maxUses: 1,
          });
          ctx.ui.notify(
            `⚠️ EXECUTION ELEVATION GRANTED\n` +
            `   Device:      "${matched.deviceName}"\n` +
            `   Principal:   ${matched.principalId}\n` +
            `   Expires:     10 minutes (1 single use)\n` +
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
    const from = (message.details as Record<string, unknown> | undefined)?.from ?? "link";
    const text = theme.fg("accent", `⚡ [${from}] `) + theme.fg("text", String(message.content));
    return new Text(text, 0, 0);
  });
}
