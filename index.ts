/**
 * omp-link — inter-terminal coordination over mutually authenticated TLS 1.3 (Protocol v5).
 *
 * This file is the Pi/OMP adapter: it owns the slash command surface, the agent tools, and the
 * lifecycle of exactly one LinkNode per terminal. All protocol, identity and authorization logic
 * lives in src/.
 *
 * Two rules shape everything here:
 *   1. The UI is a projection of one authoritative state. "Connected" means authenticated and
 *      admitted, never "a socket opened".
 *   2. Discovery produces candidates, never trust. Joining a room requires a pinned host
 *      identity or an explicit, compared verification code.
 */

import {
  VERSION as PI_VERSION,
  type ExtensionAPI,
  type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  getOrCreateDeviceIdentity,
  loadPairedDevices,
  savePairedDevice,
  removePairedDevice,
  getPairedDevice,
  wasPairedStoreReset,
  DEFAULT_PERMISSIONS,
  createInvite,
  getOmpDir,
  type DevicePermissions,
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
  fetchPublicHubStatus,
  getNetworkInfo,
  DEFAULT_PORT,
  type DiscoveredHub,
} from "./src/discovery.js";
import { getAllRegisteredWorkspaces } from "./src/inspection.js";

import { LinkNode, type TerminalDescriptor } from "./src/link-node.js";
import {
  appendAuditLog,
  readAuditLogs,
  getAuditLogStatus,
  setAuditAgentInstanceId,
  type AuditEventType,
} from "./src/audit.js";
import {
  loadConfig,
  saveConfig,
  resolveCurrentRoom,
  getTimings,
  type RoomRecord,
} from "./src/config.js";
import {
  COMMANDS,
  parseInvocation,
  renderHelp,
  getVersion,
} from "./src/command-registry.mjs";

const MIN_PI_VERSION = [0, 84, 2];

/**
 * Slack added to the hub's pairing window so the hub's own timeout message wins the race and the
 * joining agent never reports a timeout the host has not yet declared. The window itself is a
 * tunable, so this must be derived from it and never re-typed as a literal.
 */
const PAIRING_WATCH_SLACK_MS = 5_000;

/** How long a client waits before trying to take over a vanished local hub. */
const SUCCESSION_BASE_DELAY_MS = 400;
const SUCCESSION_JITTER_MS = 1_200;

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

function textResult(text: string, details?: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text }],
    details,
  };
}

/**
 * Corruption found while reading `link.json`. Surfaced on the next `/link` command rather than
 * thrown: a hand-edited or half-written config must never stop the extension from loading.
 * The shape, the validation and the defaults all live in `src/config.ts`.
 */
let configLoadWarning: string | null = null;

/** What the user is currently entitled to believe about this agent's link. */
type LinkState =
  | "off"
  | "starting"
  | "pairing"
  | "hosting"
  | "connected"
  | "reconnecting"
  | "blocked";

/**
 * Audit event types the sharing receipt renders. `satisfies` binds this list to the declared
 * vocabulary in `src/audit.ts`, so a filter naming an event nothing emits — which renders an
 * empty receipt on a busy machine — is a compile error rather than a silent blank screen.
 */
const RECEIPT_EVENT_TYPES: Record<string, true> = {
  pairing_approved: true,
  pairing_denied: true,
  pairing_rejected_invalid_sas: true,
  pairing_rejected_missing_sas: true,
  grant_created: true,
  grant_used: true,
  grant_revoked: true,
  exec_executed: true,
  exec_blocked: true,
  file_transfer_received: true,
  permissions_updated: true,
  device_revoked: true,
  authorization_denied: true,
  local_sibling_admitted: true,
  hub_pin_mismatch: true,
} satisfies Partial<Record<AuditEventType, true>>;

/**
 * Turn what a human types into `host:port`. A missing port is the common case and means the
 * default hub port, not TLS 443 — dialing 443 produces a connection error that names nothing.
 */
function normalizeEndpoint(raw: string): { endpoint: string } | { error: string } {
  const trimmed = raw.trim().replace(/^(wss?|https?):\/\//i, "").replace(/\/+$/, "");
  if (!trimmed || /[\s/?#]/.test(trimmed)) {
    return { error: `"${raw}" is not an address. Use <ip-or-host>:<port>, e.g. /link join 192.168.1.183:9900` };
  }
  const match = /^(\[[0-9A-Fa-f:]+\]|[^:]+)(?::(\d+))?$/.exec(trimmed);
  if (!match) {
    return { error: `"${raw}" is not an address. Use <ip-or-host>:<port>, e.g. /link join 192.168.1.183:9900` };
  }
  const host = match[1];
  if (match[2] === undefined) return { endpoint: `${host}:${DEFAULT_PORT}` };
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { error: `Port ${match[2]} is out of range in "${raw}". Ports are 1-65535; omp-link hubs listen on ${DEFAULT_PORT}.` };
  }
  return { endpoint: `${host}:${port}` };
}

export default function (pi: ExtensionAPI) {
  const globals = globalThis as { __omp_link_loaded?: boolean };
  if (globals.__omp_link_loaded) return;
  globals.__omp_link_loaded = true;

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

  pi.registerFlag("unsafe-remote-exec", {
    description:
      "Allow paired peers to REQUEST shell execution. Still requires the execRequest capability "
      + "and a single-use grant. Equivalent to local-user access for that peer.",
    type: "boolean",
    default: false,
  });

  const loaded = loadConfig();
  const config = loaded.config;
  configLoadWarning = loaded.warning;
  let linkNode: LinkNode | null = null;
  let networkMode: "lan" | "tailscale" = config.network || "lan";
  // `--link-name` wins over the stored name, which wins over the hostname. `getFlag` is read
  // defensively: a throw here happens before any command is registered, i.e. the whole
  // extension silently fails to load.
  const nameFlag = typeof pi.getFlag === "function" ? pi.getFlag("link-name") : undefined;
  let terminalName =
    (typeof nameFlag === "string" && nameFlag.trim() ? nameFlag.trim() : null)
    || config.terminalName
    || os.hostname()
    || "omp-node";
  // Off unless the operator asked for it on this launch. Never persisted to link.json: a
  // dangerous capability should have to be re-stated every time the terminal starts.
  const allowRemoteExec =
    (typeof pi.getFlag === "function" ? pi.getFlag("unsafe-remote-exec") : false) === true;
  let lastContext: ExtensionContext | null = null;

  /** Set while a lifecycle operation is in flight, so the card can say "starting" honestly. */
  let transition: "starting" | "reconnecting" | null = null;
  /** Set when a pin mismatch happened: a blocking security state, never auto-retried. */
  let blockedReason: string | null = null;
  /** Pending pairing this agent is waiting on, as the joining side. */
  let awaitingPairing: { endpoint: string; sasCode: string } | null = null;
  /**
   * True while this terminal is tearing its own link down. A hub vanishing because the user typed
   * `/link off` must never trigger a takeover of the port they just released.
   */
  let intentionalDisconnect = false;
  /** Set while a takeover attempt is running, so two close events cannot both claim the port. */
  let successionInFlight = false;
  let currentRoom: RoomRecord | null = resolveCurrentRoom(config);

  function rememberRoom(room: RoomRecord): void {
    const fresh = loadConfig();
    if (fresh.warning) configLoadWarning = fresh.warning;
    const rooms = (fresh.config.rooms || []).filter((r) => r.roomId !== room.roomId);
    rooms.push(room);
    currentRoom = room;
    saveConfig({ rooms, currentRoomId: room.roomId });
  }

  function linkState(): LinkState {
    if (blockedReason) return "blocked";
    if (awaitingPairing) return "pairing";
    if (transition) return transition;
    if (!linkNode) return "off";
    if (linkNode.role === "hub") return "hosting";
    if (linkNode.role === "client" && linkNode.isAuthenticated) return "connected";
    if (linkNode.role === "disconnected") return "off";
    return "starting";
  }

  /** True only when this agent can actually send and receive right now. */
  function usable(): boolean {
    const state = linkState();
    return state === "hosting" || state === "connected";
  }

  function requireUsable(): string | null {
    if (usable()) return null;
    const state = linkState();
    if (state === "pairing") return "Not connected yet: this agent is waiting to be verified by the host.";
    if (state === "blocked") return `Link is blocked: ${blockedReason}`;
    return "Link is off. Use /link join to enter an existing room, or /link create <name> to host one.";
  }

  function initNode(roomId?: string): LinkNode {
    if (linkNode) return linkNode;
    linkNode = new LinkNode({
      networkMode,
      terminalName,
      sessionId: currentRoom?.label || "link",
      roomId: roomId || currentRoom?.roomId,
      allowRemoteExec,
    });
    // Sibling terminals on one machine append to the same audit.log. Stamping the writer is the
    // only way `/link shared` and the tests can tell two of this device's agents apart.
    setAuditAgentInstanceId(linkNode.agentInstanceId);

    linkNode.onMessage = (msg) => {
      pi.sendMessage({
        // Peer content is data, never instructions.
        content: `[${msg.from || "peer"}] ${msg.text}`,
        customType: "link",
        display: true,
        details: { from: msg.from, text: msg.text, originPrincipalId: msg.originPrincipalId },
      });
    };

    linkNode.onCompactRequest = async (req) => {
      const compactable = lastContext as (ExtensionContext & {
        compact?: (opts: {
          customInstructions?: string;
          onComplete: () => void;
          onError: (err: { message?: string }) => void;
        }) => void;
      }) | null;
      if (compactable?.compact) {
        return new Promise((resolve) => {
          compactable.compact!({
            customInstructions: req.instructions,
            onComplete: () => resolve({ ok: true }),
            onError: (err) => resolve({ ok: false, reason: err?.message || "compaction error" }),
          });
        });
      }
      // No hook means nothing was compacted. Claiming success here makes the caller print
      // "completed compaction successfully" and keep dispatching work to a terminal it believes
      // it just freed. This travels back in the caller's own compact_response{reason} shape.
      return { ok: false, reason: "This terminal's host exposes no compaction hook; nothing was compacted." };
    };

    linkNode.onPairingRequested = (req) => {
      pi.sendMessage({
        content:
          `Pairing request #${req.id}\n`
          + `  Device       "${req.displayName}" from ${req.host}\n`
          + `  Compare this code on BOTH screens:  ${req.sasCode}\n`
          + `  Approve      /link accept ${req.id} ${req.sasCode}\n`
          + `  Refuse       /link deny ${req.id}\n`
          + `  Granting     messages and status only. Add access later with /link devices allow.`,
        customType: "link",
        display: true,
        details: { reqId: req.id, sasCode: req.sasCode, fingerprint: req.fingerprint },
      });
    };

    linkNode.onNotification = (msg, level) => {
      pi.sendMessage({
        content: msg,
        customType: "link",
        display: true,
        details: { level },
      });
    };

    linkNode.onTerminalsChanged = () => {
      updateStatusLine();
    };

    // The hub this client was joined to is gone. If it was a sibling terminal on this machine,
    // one of the survivors has to claim the port or the room dies with the terminal that hosted
    // it. An explicit `/link off` is not a vanished hub and never starts a takeover.
    linkNode.onHubDisconnected = () => {
      // A refusal is a closed socket: the pairing this agent was waiting on is over, and the
      // card must stop saying "waiting to be verified" forever.
      const wasPairing = awaitingPairing !== null;
      const pairingEndpoint = awaitingPairing?.endpoint;
      awaitingPairing = null;
      transition = null;
      updateStatusLine();
      if (wasPairing) {
        pi.sendMessage({
          content:
            `The host at ${pairingEndpoint} closed the connection before admitting this agent.\n`
            + `Nothing was shared. It was refused, timed out, or the code did not match — ask for a new code and run /link join ${pairingEndpoint} again.`,
          customType: "link",
          display: true,
          details: { endpoint: pairingEndpoint, outcome: "not-admitted" },
        });
        return;
      }
      if (intentionalDisconnect) return;
      void attemptLocalSuccession();
    };

    return linkNode;
  }

  /**
   * Which roster row is this terminal. A client's roster is published by the hub, and the hub
   * sends its own row with `isSelf: true` — wire attribution is never authoritative here, so
   * identity is decided locally by `agentInstanceId`.
   */
  function isSelfTerminal(t: TerminalDescriptor): boolean {
    return !!linkNode && t.agentInstanceId === linkNode.agentInstanceId;
  }

  function otherTerminals(): TerminalDescriptor[] {
    if (!linkNode) return [];
    return linkNode.getConnectedTerminalsList().filter((t) => !isSelfTerminal(t));
  }

  /**
   * Membership is authoritative and local on both roles — a hub builds it from live connections,
   * a client holds what the hub published — so a request aimed at a name nobody holds is
   * answerable here, before a frame leaves. It has to be: a client's `sendMessage` returns true
   * as soon as the hub takes the frame, and the hub then drops it for want of a resolvable
   * principal, so a typo'd or stale name reports success and is followed by silence. The
   * request/response tools do not lie, but they hang for their full timeout on the same input.
   */
  function unknownPeerRefusal(to: string, consequence: string): string | null {
    if (!linkNode) return null;
    const roster = linkNode.getConnectedTerminalsList();
    if (roster.some((t) => t.name === to)) return null;
    const reachable = roster.filter((t) => !isSelfTerminal(t)).map((t) => t.name);
    return `No agent named "${to}" is on the link, so ${consequence}. `
      + `Reachable now: ${reachable.join(", ") || "none"}.`;
  }

  function updateStatusLine(): void {
    const ctx = lastContext;
    if (!ctx?.ui?.setStatus) return;
    const state = linkState();
    if (state === "off") {
      ctx.ui.setStatus("link", "");
      return;
    }
    const peers = otherTerminals().length;
    const label = currentRoom?.label || linkNode?.currentSessionId || "link";
    ctx.ui.setStatus("link", `Link: ${label} · ${state} · ${peers} peer${peers === 1 ? "" : "s"}`);
  }

  /** Record a successful admission: clear pairing state and persist the room we just verified. */
  function completeJoin(node: LinkNode, endpoint: string, label?: string): void {
    awaitingPairing = null;
    blockedReason = null;
    const cert = node.getHubIdentity();
    if (!cert) return;
    rememberRoom({
      roomId: node.roomId,
      label: label || currentRoom?.label || "link",
      hubPrincipalId: cert.principalId,
      hubFingerprint: cert.fingerprint,
      endpoint,
      lastJoinedAt: Date.now(),
    });
  }

  /**
   * Wait out the host's pairing window for a verdict the connect promise can no longer deliver.
   * Stops on admission, on disconnect (which `onHubDisconnected` already handles), or when the
   * hub's own 60s window has closed.
   */
  async function watchForAdmission(
    node: LinkNode,
    endpoint: string,
    label: string | undefined,
    ctx?: ExtensionContext,
  ): Promise<void> {
    const deadline = Date.now() + getTimings().pairingWindowMs + PAIRING_WATCH_SLACK_MS;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 400));
      if (linkNode !== node) return;
      if (node.isAuthenticated) {
        completeJoin(node, endpoint, label);
        updateStatusLine();
        ctx?.ui.notify(`Verified by the host. Joined room "${currentRoom?.label || "link"}".`, "info");
        return;
      }
      if (node.role === "disconnected") return;
    }
    if (awaitingPairing?.endpoint === endpoint && !node.isAuthenticated) {
      awaitingPairing = null;
      updateStatusLine();
      ctx?.ui.notify(
        `The host at ${endpoint} did not approve this device within the pairing window. Nothing was shared. Run /link join to try again.`,
        "warning",
      );
    }
  }

  /**
   * Join a hub whose identity we can verify. Returns a human-readable failure, or null on
   * success. Never falls back to hosting: a failed join is a failed join.
   */
  async function joinEndpoint(
    endpoint: string,
    options: { pinnedFingerprint?: string; inviteSecret?: string; label?: string },
    ctx?: ExtensionContext,
  ): Promise<string | null> {
    const node = initNode();
    intentionalDisconnect = false;
    transition = "starting";
    updateStatusLine();
    try {
      const outcome = await node.connectToHub(
        `wss://${endpoint}`,
        options.pinnedFingerprint,
        options.inviteSecret,
      );
      transition = null;

      if (outcome.state === "pairing-required") {
        awaitingPairing = { endpoint, sasCode: outcome.sasCode };
        updateStatusLine();
        ctx?.ui.notify(
          `Waiting to be verified by the host at ${endpoint}.\n`
          + `Compare this code on BOTH screens: ${outcome.sasCode}\n`
          + `Nothing is shared until the host approves.`,
          "warning",
        );
        // The connect promise has already settled, so approval arrives only as a phase change on
        // the node. Without this watch the agent stays "pairing" forever after the host says yes.
        void watchForAdmission(node, endpoint, options.label, ctx);
        return null;
      }

      completeJoin(node, endpoint, options.label);
      updateStatusLine();
      return null;
    } catch (err: unknown) {
      transition = null;
      const message = err instanceof Error ? err.message : String(err);
      // tls.ts reports "Server certificate pinning mismatch!"; link-node reports a fingerprint
      // mismatch. Both mean the same thing and both must reach the blocked card.
      if (/fingerprint mismatch|pinning mismatch/i.test(message)) {
        blockedReason =
          `${endpoint} no longer matches the identity pinned for this room. `
          + `No invite, file or diff was sent to it.`;
      }
      updateStatusLine();
      return message;
    }
  }

  /** Probe for a hub already running on this machine, hosted by a sibling terminal. */
  async function findLocalHub(): Promise<{ roomId?: string; fingerprint?: string } | null> {
    try {
      const status = await fetchPublicHubStatus("127.0.0.1", DEFAULT_PORT, 400);
      if (!status) return null;
      return { roomId: status.roomId, fingerprint: status.spkiFingerprint };
    } catch {
      return null;
    }
  }

  /**
   * Terminals on one machine share a device certificate, so a sibling's hub presents exactly the
   * identity remote peers already pinned. That makes local hosting transferable: when the hub
   * terminal exits, another local terminal can claim the port and the room continues, with no
   * daemon and no re-pairing.
   */
  async function attemptLocalSuccession(): Promise<void> {
    if (!currentRoom || !linkNode || successionInFlight) return;
    const wasLocal = currentRoom.endpoint.startsWith("127.0.0.1");
    if (!wasLocal) return;
    successionInFlight = true;
    try {
      await runLocalSuccession();
    } finally {
      successionInFlight = false;
    }
  }

  async function runLocalSuccession(): Promise<void> {
    if (!currentRoom || !linkNode) return;

    // Randomized so several surviving terminals do not race in lockstep; the port decides.
    const delay = SUCCESSION_BASE_DELAY_MS + Math.floor(Math.random() * SUCCESSION_JITTER_MS);
    await new Promise((r) => setTimeout(r, delay));
    if (usable()) return;

    const stillThere = await findLocalHub();
    if (stillThere) {
      await joinEndpoint(`127.0.0.1:${DEFAULT_PORT}`, {
        pinnedFingerprint: linkNode.identity.fingerprint,
      });
      return;
    }

    try {
      await linkNode.startHub();
      appendAuditLog({
        type: "local_hub_succession",
        timestamp: Date.now(),
        roomId: linkNode.roomId,
        agentInstanceId: linkNode.agentInstanceId,
      });
      pi.sendMessage({
        content: `The terminal hosting "${currentRoom.label}" exited. This terminal is now hosting the room; peers keep the same pinned identity and reconnect automatically.`,
        customType: "link",
        display: true,
        details: { roomId: linkNode.roomId },
      });
      updateStatusLine();
    } catch {
      // Another local terminal won the port. Join it.
      await joinEndpoint(`127.0.0.1:${DEFAULT_PORT}`, {
        pinnedFingerprint: linkNode.identity.fingerprint,
      });
    }
  }

  /** `/link on` — resume a remembered room. Never creates one. */
  async function resumeRoom(ctx?: ExtensionContext): Promise<void> {
    if (ctx) lastContext = ctx;
    if (!currentRoom) {
      ctx?.ui.notify(
        "No room remembered on this machine.\n"
        + "  /link scan            see what is reachable\n"
        + "  /link join <ip:port>  join an existing room\n"
        + "  /link create <name>   host a new one",
        "warning",
      );
      return;
    }

    const node = initNode(currentRoom.roomId);

    // A sibling terminal on this machine may already be hosting this exact room.
    const local = await findLocalHub();
    if (local && local.roomId === currentRoom.roomId) {
      const err = await joinEndpoint(`127.0.0.1:${DEFAULT_PORT}`, {
        pinnedFingerprint: node.identity.fingerprint,
        label: currentRoom.label,
      }, ctx);
      if (!err) {
        ctx?.ui.notify(`Joined room "${currentRoom.label}" hosted by another terminal on this machine.`, "info");
        return;
      }
    }

    // We created this room: host it again under the same identity.
    if (currentRoom.hubPrincipalId === node.identity.principalId) {
      await hostRoom(currentRoom.label, currentRoom.roomId, ctx);
      return;
    }

    const err = await joinEndpoint(currentRoom.endpoint, {
      pinnedFingerprint: currentRoom.hubFingerprint,
      label: currentRoom.label,
    }, ctx);
    if (err) {
      ctx?.ui.notify(`Could not rejoin "${currentRoom.label}" at ${currentRoom.endpoint}: ${err}`, "error");
    } else if (usable()) {
      ctx?.ui.notify(`Rejoined room "${currentRoom.label}".`, "info");
    }
  }

  /** `/link create` — explicitly host a new room. */
  async function hostRoom(label: string, roomId: string | undefined, ctx?: ExtensionContext): Promise<void> {
    if (ctx) lastContext = ctx;
    const node = initNode(roomId);
    transition = "starting";
    updateStatusLine();
    try {
      await node.startHub();
      transition = null;
      const net = getNetworkInfo();
      const hostIp = networkMode === "tailscale"
        ? (net.tailscaleIp || "tailscale")
        : (net.lanIps[0] || "127.0.0.1");
      rememberRoom({
        roomId: node.roomId,
        label,
        hubPrincipalId: node.identity.principalId,
        hubFingerprint: node.identity.fingerprint,
        endpoint: `${hostIp}:${node.port}`,
        lastJoinedAt: Date.now(),
      });
      updateStatusLine();
      ctx?.ui.notify(
        `Hosting room "${label}" on ${hostIp}:${node.port}.\n`
        + `No peer is admitted until you approve it. Share access with /link invite.`,
        "info",
      );
    } catch (err: unknown) {
      transition = null;
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === "EADDRINUSE") {
        // Something already holds the port. If it is a sibling terminal's hub for this room,
        // join it; otherwise say so plainly rather than silently becoming a different thing.
        const local = await findLocalHub();
        if (local) {
          const joinErr = await joinEndpoint(`127.0.0.1:${DEFAULT_PORT}`, {
            pinnedFingerprint: node.identity.fingerprint,
            label,
          }, ctx);
          if (!joinErr) {
            ctx?.ui.notify(`A terminal on this machine is already hosting on port ${DEFAULT_PORT}. Joined it instead of starting a second room.`, "info");
            return;
          }
        }
        ctx?.ui.notify(
          `Port ${DEFAULT_PORT} is in use by something that is not an omp-link hub. `
          + `Free the port or run /link doctor to see what is holding it.`,
          "error",
        );
        updateStatusLine();
        return;
      }
      updateStatusLine();
      ctx?.ui.notify(`Failed to host "${label}": ${err instanceof Error ? err.message : String(err)}`, "error");
    }
  }

  /** `/link off` (alias `leave`) — detach THIS agent only. */
  async function leaveRoom(ctx?: ExtensionContext): Promise<void> {
    const wasHub = linkNode?.role === "hub";
    const wasOff = linkNode === null && awaitingPairing === null;
    const peerCount = otherTerminals().length;
    // Stopping our own client socket must not look like a hub that vanished.
    intentionalDisconnect = true;
    if (linkNode) {
      await linkNode.stop();
      linkNode = null;
    }
    revokeAllGrants("Link deactivated");
    awaitingPairing = null;
    transition = null;
    updateStatusLine();
    if (wasOff) {
      ctx?.ui.notify("Link was already off; nothing on this machine is shared.", "info");
    } else if (wasHub && peerCount > 0) {
      ctx?.ui.notify(
        `Left the room. You were hosting for ${peerCount} peer${peerCount === 1 ? "" : "s"}; `
        + `another terminal on this machine will take over hosting if one is running.`,
        "warning",
      );
    } else {
      ctx?.ui.notify("Left the room. Nothing on this machine is shared.", "info");
    }
  }

  // ── Status rendering ──────────────────────────────────────────────────────

  function permissionSummary(perms: DevicePermissions | undefined): string {
    if (!perms) return "nothing";
    const can: string[] = [];
    if (perms.message) can.push("send messages");
    if (perms.inspectMetadata) can.push("see repo status");
    if (perms.readContent) can.push("read approved files");
    if (perms.readDiff) can.push("read diffs");
    if (perms.fileInbox) can.push("send files");
    if (perms.compact) can.push("request compaction");
    if (perms.execRequest) can.push("request commands");
    return can.length ? can.join(", ") : "nothing";
  }

  function renderStatus(verbose: boolean): string {
    const state = linkState();
    const label = currentRoom?.label || "none";

    if (state === "off") {
      return [
        "Link · Off",
        "No room. Nothing on this machine is shared.",
        "",
        "  /link scan            see who is reachable",
        "  /link join <ip:port>  join an existing room",
        "  /link create <name>   host a new room",
      ].join("\n");
    }

    if (state === "blocked") {
      return [
        "Link · Blocked — identity changed",
        blockedReason || "The host identity does not match the pinned record.",
        "",
        "  /link devices show <device>   inspect the pinned identity",
        "  /link off                     stand down",
      ].join("\n");
    }

    if (state === "pairing" && awaitingPairing) {
      return [
        "Link · Pairing — not connected yet",
        `Host        ${awaitingPairing.endpoint} · identity not yet trusted`,
        `Compare on BOTH devices:   ${awaitingPairing.sasCode}`,
        "",
        "Shared now  nothing — no file, diff or command has been sent",
        "  Waiting for the host to approve this device.",
        "  /link off   cancel",
      ].join("\n");
    }

    if (state === "starting" || state === "reconnecting") {
      return `Link · ${state === "starting" ? "Starting" : "Reconnecting"}\nRoom "${label}" — no peer traffic is flowing yet.`;
    }

    const node = linkNode!;
    const others = otherTerminals();
    const net = getNetworkInfo();
    const endpoint = node.role === "hub"
      ? `${networkMode === "tailscale" ? (net.tailscaleIp || "tailscale") : (net.lanIps[0] || "127.0.0.1")}:${node.port}`
      : (currentRoom?.endpoint || "unknown");

    const lines: string[] = [];
    lines.push(node.role === "hub" && others.length === 0
      ? "Link · Hosting, no other agents"
      : "Link · Connected");
    lines.push(`Room          ${label}`);
    lines.push(`This agent    ${node.terminalName} · ${path.basename(node.workspaceRoot)} (this)`);
    lines.push(`Other agents  ${others.length}`);
    lines.push(`Network       ${networkMode} · ${node.role === "hub" ? `hosting ${endpoint}` : `host ${endpoint}`}`);
    lines.push(node.role === "hub"
      ? `Verification  ${others.length} peer${others.length === 1 ? "" : "s"} admitted after SPKI pinning`
      : `Verification  host SPKI pinned for this room`);

    if (others.length) {
      lines.push("");
      lines.push("Agent                Workspace        Identity");
      for (const t of others) {
        // On a client this roster is whatever the hub published, so it is untrusted data:
        // a missing or non-string field must not take the status card down.
        const name = typeof t.name === "string" && t.name ? t.name : "(unnamed)";
        const principal = typeof t.principalId === "string" && t.principalId ? t.principalId : "unknown";
        const workspace = typeof t.workspaceLabel === "string" && t.workspaceLabel ? t.workspaceLabel : "-";
        lines.push(`${name.padEnd(20)} ${workspace.padEnd(16)} ${principal.slice(0, 24)}…`);
      }
    }

    const grants = getActiveGrants();
    if (grants.length) {
      lines.push("");
      lines.push(`Live command grants: ${grants.map((g) => `${g.displayName} (${Math.ceil((g.expiresAt - Date.now()) / 60000)}m, ${g.remainingUses} use(s))`).join(", ")}`);
    }

    if (verbose) {
      const id = getOrCreateDeviceIdentity();
      lines.push("");
      lines.push("[verbose]");
      lines.push(`  device principal  ${id.principalId}`);
      lines.push(`  device SPKI       ${id.fingerprint}`);
      lines.push(`  agent instance    ${node.agentInstanceId}`);
      lines.push(`  room id           ${node.roomId}`);
      lines.push(`  config            ${path.join(getOmpDir(), "link.json")}`);
    } else {
      lines.push("");
      lines.push("  /link peers   /link shared   /link off");
    }
    return lines.join("\n");
  }

  // ── Tools ─────────────────────────────────────────────────────────────────

  pi.registerTool({
    name: "link_status",
    label: "Link Status",
    description: "Report this agent's link state, room, peers and what each peer is allowed to do. Structured; prefer this over reading the status card.",
    promptSnippet: "Check link state and peers",
    parameters: Type.Object({}),
    async execute() {
      const state = linkState();
      const roster = otherTerminals();
      const details = {
        state,
        usable: usable(),
        room: currentRoom ? { roomId: currentRoom.roomId, label: currentRoom.label, endpoint: currentRoom.endpoint } : null,
        role: linkNode?.role || "disconnected",
        agentInstanceId: linkNode?.agentInstanceId || null,
        terminalName,
        peers: roster.map((t) => ({
          name: t.name,
          principalId: t.principalId,
          agentInstanceId: t.agentInstanceId,
          workspace: t.workspaceLabel,
        })),
        activeGrants: getActiveGrants().length,
      };
      const summary = state === "off"
        ? "Link is off."
        : `Link is ${state}${currentRoom ? ` in room "${currentRoom.label}"` : ""} with ${details.peers.length} other agent(s).`;
      return textResult(summary, details);
    },
  });

  pi.registerTool({
    name: "link_send",
    label: "Link Send",
    description: "Send a message to one other Pi terminal on the link mesh, or to every peer with '*'.",
    promptSnippet: "Send message to a peer terminal on the link",
    parameters: Type.Object({
      to: Type.String({ description: "Target terminal name, or '*' to broadcast" }),
      message: Type.String({ description: "Message content" }),
    }),
    async execute(_id, params) {
      const blocked = requireUsable();
      if (blocked) return textResult(blocked);

      // A client's `sendMessage` returns true as soon as the hub has the frame, so success
      // there does not mean anyone received it. The roster is local and authoritative, so
      // check it here rather than reporting a delivery that never happened.
      //
      // Self is identified by `agentInstanceId`, never by the wire `isSelf` flag: the hub
      // publishes its own descriptor with `isSelf: true` and `absorbRoster` keeps the flag, so
      // filtering on it makes every client believe the hub terminal is itself and refuse to
      // send to the most common target of all.
      if (params.to === "*") {
        if (otherTerminals().length === 0) {
          return textResult("Nothing was sent: no other agent is on the link.", { error: "empty_room" });
        }
      } else {
        const refusal = unknownPeerRefusal(params.to, "nothing was sent");
        if (refusal) {
          return textResult(refusal, {
            to: params.to,
            error: "unknown_peer",
            reachable: otherTerminals().map((t) => t.name),
          });
        }
      }

      const success = linkNode!.sendMessage(params.to, params.message);
      return textResult(
        success
          ? `Message sent to "${params.to}".`
          : `Failed to deliver message to "${params.to}". Peer not found or offline.`,
        { to: params.to, delivered: success },
      );
    },
  });

  pi.registerTool({
    name: "link_list",
    label: "Link List",
    description: "List all Pi terminals currently connected to the link.",
    promptSnippet: "List connected Pi terminals on the link",
    parameters: Type.Object({}),
    async execute() {
      const blocked = requireUsable();
      if (blocked) return textResult(blocked);
      const terms = linkNode!.getConnectedTerminalsList();
      const list = terms
        .map((t) => `  - ${t.name}${isSelfTerminal(t) ? " (this agent)" : ""} [${t.workspaceLabel || "unknown workspace"}]`)
        .join("\n");
      return textResult(
        `Agents in room "${currentRoom?.label || "link"}" (${terms.length}):\n${list}`,
        { terminals: terms },
      );
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
        Type.String({ description: "Custom instructions to guide the compaction summary (optional)" }),
      ),
    }),
    async execute(_id, params) {
      const blocked = requireUsable();
      if (blocked) return textResult(blocked);
      if (params.to === terminalName) {
        return textResult("Cannot compact yourself - use /compact.", { to: params.to, error: "self_target" });
      }
      // Without this the request is handed to the hub, dropped for want of a resolvable
      // principal, and the caller blocks for the full 180s before failing on a typo.
      const unknown = unknownPeerRefusal(params.to, "no compaction was requested");
      if (unknown) {
        return textResult(unknown, {
          to: params.to,
          error: "unknown_peer",
          reachable: otherTerminals().map((t) => t.name),
        });
      }
      try {
        const res = await linkNode!.requestCompact(params.to, params.customInstructions);
        if (!res.ok) {
          return textResult(`Compact request declined by "${params.to}": ${res.reason || "unknown reason"}`);
        }
        return textResult(`Terminal "${params.to}" completed compaction successfully.`);
      } catch (err: unknown) {
        return textResult(`Compact request failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    },
  });

  pi.registerTool({
    name: "link_discover",
    label: "Link Discover",
    description: "Discover reachable omp-link hubs on LAN and Tailscale. Results are unverified candidates, not trusted peers.",
    promptSnippet: "Scan for active omp-link sessions on network",
    parameters: Type.Object({}),
    async execute() {
      const hubs = await discoverAllHubs(DEFAULT_PORT, getTimings().discoveryProbeMs, { mode: networkMode });
      if (hubs.length === 0) {
        return textResult("No omp-link hubs responded on LAN or Tailscale.");
      }
      const lines = hubs.map((h) => `  - ${h.host}:${h.port} [${h.source}] room ${h.roomId || "unknown"} (unverified)`);
      return textResult(
        `Reachable hubs (${hubs.length}). These are candidates only — joining requires verification:\n${lines.join("\n")}`,
        { hubs },
      );
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
      const blocked = requireUsable();
      if (blocked) return textResult(blocked);
      // A client cannot resolve an unknown name to a principal, so the hub drops the request
      // and the caller waits out the full RPC timeout to learn about a typo.
      const unknown = unknownPeerRefusal(params.to, "nothing was run");
      if (unknown) {
        return textResult(unknown, {
          to: params.to,
          error: "unknown_peer",
          reachable: otherTerminals().map((t) => t.name),
        });
      }
      try {
        const res = await linkNode!.executeRemoteRpc(params.to, params.action, {
          command: params.command,
          filePath: params.filePath,
          pattern: params.pattern,
          count: params.count,
        });
        if (!res.ok) {
          return textResult(`RPC execution error on "${params.to}": ${res.error}`);
        }
        return textResult(res.result || "[Success, no output]");
      } catch (err: unknown) {
        return textResult(`RPC failed: ${err instanceof Error ? err.message : String(err)}`);
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
      const blocked = requireUsable();
      if (blocked) return textResult(blocked);
      // Checked before the file is read and hashed: otherwise up to 50 MB is streamed to a hub
      // that drops every chunk, and the caller waits 60s for an ack naming only a transfer uuid.
      const unknown = unknownPeerRefusal(params.to, "nothing was sent");
      if (unknown) {
        return textResult(unknown, {
          to: params.to,
          error: "unknown_peer",
          reachable: otherTerminals().map((t) => t.name),
        });
      }
      try {
        const res = await linkNode!.sendFile(params.to, params.filePath);
        if (res.ok) {
          return textResult(`File "${path.basename(params.filePath)}" transferred successfully to "${params.to}".`);
        }
        return textResult(`File transfer failed: ${res.error}`);
      } catch (err: unknown) {
        return textResult(`Transfer error: ${err instanceof Error ? err.message : String(err)}`);
      }
    },
  });

  // ── Command surface ───────────────────────────────────────────────────────

  /**
   * The one table of user-facing capability names, shared by `accept --allow` and
   * `devices allow/deny`. Two tables would drift, and a name that silently matches nothing
   * reports a permission change that never happened.
   */
  const CAPABILITY_FIELDS: Record<string, readonly (keyof DevicePermissions)[]> = {
    message: ["message"],
    compact: ["compact"],
    inspect: ["inspect", "inspectMetadata", "readContent", "readDiff"],
    metadata: ["inspectMetadata"],
    inspectmetadata: ["inspectMetadata"],
    content: ["readContent"],
    readcontent: ["readContent"],
    diff: ["readDiff"],
    readdiff: ["readDiff"],
    file: ["fileInbox"],
    fileinbox: ["fileInbox"],
    exec: ["execRequest"],
    execrequest: ["execRequest"],
  };

  function parseCapabilities(list: string[]): { fields: (keyof DevicePermissions)[]; unknown: string[] } {
    const fields: (keyof DevicePermissions)[] = [];
    const unknown: string[] = [];
    for (const raw of list) {
      const name = raw.trim().toLowerCase();
      if (!name) continue;
      const mapped = CAPABILITY_FIELDS[name];
      if (!mapped) {
        unknown.push(raw.trim());
        continue;
      }
      for (const field of mapped) if (!fields.includes(field)) fields.push(field);
    }
    return { fields, unknown };
  }

  function capabilityHelp(): string {
    return `Capabilities: ${Object.keys(CAPABILITY_FIELDS).join(", ")}`;
  }

  function permissionsFrom(fields: (keyof DevicePermissions)[]): DevicePermissions {
    const perms: DevicePermissions = {
      observe: true,
      message: false,
      compact: false,
      inspectMetadata: false,
      readContent: false,
      readDiff: false,
      fileInbox: false,
      execRequest: false,
      inspect: false,
    };
    for (const field of fields) perms[field] = true;
    return perms;
  }

  async function pickHub(hubs: DiscoveredHub[], ctx: ExtensionContext): Promise<DiscoveredHub | null> {
    if (hubs.length === 0 || !ctx.ui.select) return null;
    // The chosen value comes back as the option string, so resolution is by exact row.
    const options = hubs.map((h) => `${h.host}:${h.port} [${h.source}] room ${h.roomId || "unknown"}`);
    const choice = await ctx.ui.select(
      "Which hub do you want to join? Discovery does not verify identity.",
      options,
    );
    if (choice === null || choice === undefined) return null;
    const index = options.indexOf(String(choice));
    return index >= 0 ? hubs[index] : null;
  }

  async function runCommand(rawArgs: string, ctx: ExtensionContext, forced?: string): Promise<void> {
    lastContext = ctx;
    if (configLoadWarning) {
      const warning = configLoadWarning;
      configLoadWarning = null;
      ctx.ui.notify(warning, "warning");
    }
    const argv = rawArgs.trim().split(/\s+/).filter(Boolean);
    if (forced) argv.unshift(forced);
    const inv = parseInvocation(argv, { surface: "agent" });
    if (inv.error) {
      ctx.ui.notify(inv.error, "warning");
      return;
    }

    switch (inv.command) {
      case "help":
        ctx.ui.notify(renderHelp(inv.positionals[0], "agent"), "info");
        return;

      case "status":
        ctx.ui.notify(renderStatus(Boolean(inv.flags.verbose)), usable() ? "info" : "warning");
        return;

      case "on":
        await resumeRoom(ctx);
        return;

      case "off":
        await leaveRoom(ctx);
        return;

      case "create": {
        const label = inv.positionals.join(" ").trim();
        if (!label) {
          ctx.ui.notify("Name the room: /link create <name>", "warning");
          return;
        }
        await hostRoom(label, undefined, ctx);
        return;
      }

      case "end": {
        if (linkNode?.role !== "hub") {
          ctx.ui.notify("This agent is not hosting a room. Use /link off to leave.", "warning");
          return;
        }
        const peers = otherTerminals();
        const impact = peers.length
          ? `This drops ${peers.length} connected agent${peers.length === 1 ? "" : "s"}: ${peers.map((p) => p.name).join(", ")}.`
          : "No other agent is connected.";
        if (peers.length && !inv.flags.yes) {
          const agreed = ctx.ui.confirm
            ? await ctx.ui.confirm(`Stop hosting "${currentRoom?.label || "this room"}"?`, impact)
            : false;
          if (!agreed) {
            ctx.ui.notify(`${impact}\nStill hosting. Run /link end --yes to stop anyway.`, "warning");
            return;
          }
        }
        await leaveRoom();
        ctx.ui.notify(
          peers.length
            ? `Stopped hosting. ${peers.length} agent${peers.length === 1 ? " was" : "s were"} disconnected. Nothing on this machine is shared.`
            : "Stopped hosting. Nothing on this machine is shared.",
          "info",
        );
        return;
      }

      case "join": {
        const target = inv.positionals[0];
        if (target) {
          const normalized = normalizeEndpoint(target);
          if ("error" in normalized) {
            ctx.ui.notify(normalized.error, "warning");
            return;
          }
          const pin = inv.positionals[2];
          if (pin && !/^([0-9A-Fa-f]{2}[:-]?){31}[0-9A-Fa-f]{2}$/.test(pin)) {
            ctx.ui.notify(
              `"${pin}" is not an SPKI fingerprint. The third argument is the host's 32-byte `
              + `SHA-256 fingerprint in colon hex, as printed by /link invite.\n`
              + `Usage: /link join <ip:port> [invite-secret] [fingerprint]`,
              "warning",
            );
            return;
          }
          const endpoint = normalized.endpoint;
          const err = await joinEndpoint(endpoint, {
            inviteSecret: inv.positionals[1],
            pinnedFingerprint: pin,
          }, ctx);
          if (err) ctx.ui.notify(`Could not join ${endpoint}: ${err}`, "error");
          else if (usable()) ctx.ui.notify(`Joined ${endpoint}.`, "info");
          return;
        }

        ctx.ui.notify("Looking for reachable hubs...", "info");
        const hubs = await discoverAllHubs(DEFAULT_PORT, getTimings().discoveryProbeMs, { mode: networkMode });
        if (hubs.length === 0) {
          ctx.ui.notify("No hubs responded. Give an address: /link join <ip:port>", "warning");
          return;
        }
        // Discovery never chooses for the user, not even when there is exactly one answer.
        const picked = await pickHub(hubs, ctx);
        if (!picked) {
          const list = hubs.map((h) => `  /link join ${h.host}:${h.port}   [${h.source}] room ${h.roomId || "unknown"}`).join("\n");
          ctx.ui.notify(`Reachable hubs (unverified):\n${list}`, "info");
          return;
        }
        const err = await joinEndpoint(`${picked.host}:${picked.port}`, {}, ctx);
        if (err) ctx.ui.notify(`Could not join ${picked.host}:${picked.port}: ${err}`, "error");
        return;
      }

      case "scan": {
        ctx.ui.notify(`Scanning ${networkMode} for hubs...`, "info");
        const hubs = await discoverAllHubs(DEFAULT_PORT, getTimings().discoveryProbeMs, { mode: networkMode });
        if (hubs.length === 0) {
          ctx.ui.notify(`No hubs responded on ${networkMode}.`, "warning");
          return;
        }
        const lines = hubs.map((h) =>
          `  ${h.host}:${h.port} [${h.source}] room ${h.roomId || "unknown"}\n    join: /link join ${h.host}:${h.port}`);
        ctx.ui.notify(
          `Reachable hubs (${hubs.length}). Unverified — joining still requires a code or a pin:\n${lines.join("\n")}`,
          "info",
        );
        return;
      }

      case "peers": {
        const blocked = requireUsable();
        if (blocked) {
          ctx.ui.notify(blocked, "warning");
          return;
        }
        const roster = linkNode!.getConnectedTerminalsList();
        const devices = loadPairedDevices();
        const lines = roster.map((t) => {
          const name = typeof t.name === "string" && t.name ? t.name : "(unnamed)";
          const workspace = typeof t.workspaceLabel === "string" && t.workspaceLabel ? t.workspaceLabel : "-";
          if (isSelfTerminal(t)) return `  ${name} (this agent) · ${workspace}`;
          const dev = [...devices.values()].find((d) => d.principalId === t.principalId);
          return `  ${name} · ${workspace} · can: ${permissionSummary(dev?.permissions)}`;
        });
        ctx.ui.notify(`Agents in "${currentRoom?.label || "link"}":\n${lines.join("\n")}`, "info");
        return;
      }

      case "invite": {
        if (linkNode?.role !== "hub") {
          ctx.ui.notify("Only the hosting terminal can issue invites. Use /link create <name> first.", "warning");
          return;
        }
        const invite = createInvite(getOrCreateDeviceIdentity(), { expiresInMs: 300_000 });
        const net = getNetworkInfo();
        const hostIp = networkMode === "tailscale" ? (net.tailscaleIp || "tailscale") : (net.lanIps[0] || "127.0.0.1");
        ctx.ui.notify(
          `One-time invite, expires in 5 minutes. Single use.\n`
          + `  On the other machine run:\n`
          + `  /link join ${hostIp}:${linkNode.port} ${invite.secret} ${invite.hubFingerprint}`,
          "info",
        );
        return;
      }

      case "accept": {
        const reqId = parseInt(inv.positionals[0] || "", 10);
        const code = inv.positionals[1];
        if (!Number.isInteger(reqId) || reqId <= 0 || !code) {
          ctx.ui.notify(
            `"${inv.positionals[0]}" is not a pairing request id.\n`
            + "Usage: /link accept <request-id> <code>\n"
            + "The code is required: it proves you compared the words on both screens.",
            "warning",
          );
          return;
        }
        if (linkNode?.role !== "hub") {
          ctx.ui.notify(
            "This agent is not hosting a room, so it has no pairing requests to approve. "
            + "Only the hosting terminal approves pairings.",
            "warning",
          );
          return;
        }
        const allowFlag = typeof inv.flags.allow === "string" ? inv.flags.allow : "";
        let perms = { ...DEFAULT_PERMISSIONS };
        if (allowFlag) {
          const parsed = parseCapabilities(allowFlag.split(","));
          if (parsed.unknown.length) {
            ctx.ui.notify(
              `Unknown capability: ${parsed.unknown.join(", ")}. Nothing was approved.\n${capabilityHelp()}`,
              "warning",
            );
            return;
          }
          perms = permissionsFrom(parsed.fields);
        }
        const approved = linkNode.approvePairing(reqId, perms, code);
        if (approved) {
          ctx.ui.notify(
            `Approved "${approved.deviceName}".\n  They can: ${permissionSummary(approved.permissions)}`,
            "info",
          );
        } else {
          ctx.ui.notify(
            `Request #${reqId} was not approved: unknown id, expired, or the code did not match. `
            + `If the request was still live, the device was told and disconnected.`,
            "error",
          );
        }
        return;
      }

      case "deny": {
        const reqId = parseInt(inv.positionals[0] || "", 10);
        if (!Number.isInteger(reqId) || reqId <= 0) {
          ctx.ui.notify(
            `"${inv.positionals[0]}" is not a pairing request id.\nUsage: /link deny <request-id>`,
            "warning",
          );
          return;
        }
        if (linkNode?.role !== "hub") {
          ctx.ui.notify(
            "This agent is not hosting a room, so it has no pairing requests to refuse.",
            "warning",
          );
          return;
        }
        const denied = linkNode.denyPairing(reqId);
        ctx.ui.notify(
          denied
            ? `Denied pairing request #${reqId}. The device was told and disconnected.`
            : `Pairing request #${reqId} not found: it may have expired or already been answered.`,
          denied ? "info" : "warning",
        );
        return;
      }

      case "devices": {
        const action = (inv.positionals[0] || "list").toLowerCase();
        const target = inv.positionals[1];
        const extra = inv.positionals.slice(2).join(" ");
        const devices = loadPairedDevices();
        const actions = ["list", "show", "allow", "deny", "workspace", "remove"];
        if (!actions.includes(action)) {
          ctx.ui.notify(
            `"${action}" is not a devices subcommand. Use one of: ${actions.join(", ")}.\n`
            + `Usage: /link devices [${actions.join("|")}]`,
            "warning",
          );
          return;
        }

        if (action === "list") {
          if (devices.size === 0) {
            ctx.ui.notify("No paired devices yet.", "info");
            return;
          }
          const lines = [...devices.values()].map((d) =>
            `  ${d.deviceName}\n    can: ${permissionSummary(d.permissions)}\n    paired: ${new Date(d.pairedAt).toISOString().slice(0, 10)}`);
          ctx.ui.notify(`Paired devices (${devices.size}):\n${lines.join("\n")}`, "info");
          return;
        }

        const matched = target ? getPairedDevice(target) : null;
        if (!matched) {
          ctx.ui.notify(target ? `Device "${target}" not found.` : `Usage: /link devices ${action} <device>`, "error");
          return;
        }

        if (action === "show") {
          ctx.ui.notify(
            `${matched.deviceName}\n`
            + `  principal    ${matched.principalId}\n`
            + `  SPKI         ${matched.fingerprint}\n`
            + `  can          ${permissionSummary(matched.permissions)}\n`
            + `  workspaces   ${matched.workspaces?.join(", ") || "all registered"}\n`
            + `  paired       ${new Date(matched.pairedAt).toISOString()}\n`
            + `  last seen    ${matched.lastSeen ? new Date(matched.lastSeen).toISOString() : "never"}`,
            "info",
          );
          return;
        }

        if (action === "allow" || action === "deny") {
          if (!extra) {
            ctx.ui.notify(
              `Usage: /link devices ${action} <device> <capability,capability>\n${capabilityHelp()}`,
              "warning",
            );
            return;
          }
          const parsed = parseCapabilities(extra.split(","));
          if (parsed.unknown.length) {
            ctx.ui.notify(
              `Unknown capability: ${parsed.unknown.join(", ")}. Nothing was changed.\n${capabilityHelp()}`,
              "warning",
            );
            return;
          }
          const value = action === "allow";
          const updates: Partial<DevicePermissions> = {};
          for (const field of parsed.fields) updates[field] = value;

          const ok = linkNode
            ? linkNode.updatePeerPermissions(matched.principalId, updates)
            : updateDevicePermissions(matched.fingerprint, updates);
          ctx.ui.notify(
            ok
              ? `${matched.deviceName} can now: ${permissionSummary({ ...matched.permissions, ...updates })}`
              : `Failed to update "${matched.deviceName}".`,
            ok ? "info" : "error",
          );
          return;
        }

        if (action === "workspace") {
          if (!extra) {
            ctx.ui.notify("Usage: /link devices workspace <device> <ws1,ws2>", "warning");
            return;
          }
          const requested = extra.split(",").map((s) => s.trim()).filter(Boolean);
          const known = getAllRegisteredWorkspaces().map((w) => w.id);
          const unknown = requested.filter((id) => !known.includes(id));
          matched.workspaces = requested;
          savePairedDevice(matched);
          ctx.ui.notify(
            `${matched.deviceName} is limited to: ${requested.join(", ")}`
            + (unknown.length
              ? `\n  Not exported by this terminal: ${unknown.join(", ")} — that scope matches nothing here.`
                + `\n  Exported now: ${known.join(", ") || "none"}`
              : ""),
            unknown.length ? "warning" : "info",
          );
          return;
        }

        if (action === "remove") {
          const ok = linkNode ? linkNode.revokeDevice(matched.principalId) : removePairedDevice(matched.principalId);
          ctx.ui.notify(ok ? `Removed "${matched.deviceName}".` : "Removal failed.", ok ? "info" : "error");
          return;
        }

        ctx.ui.notify(`Unknown: /link devices ${action}. Try list, show, allow, deny, workspace, remove.`, "warning");
        return;
      }

      case "grant": {
        const target = inv.positionals[0];
        if (!target) {
          ctx.ui.notify("Usage: /link grant <device> [--workspace <id>] [--for 10m] [--uses 1]", "warning");
          return;
        }
        const matched = getPairedDevice(target);
        if (!matched) {
          ctx.ui.notify(`No paired device matching "${target}".`, "error");
          return;
        }
        if (!linkNode) {
          ctx.ui.notify("Link is off; there is no connection to grant against.", "warning");
          return;
        }
        if (!linkNode.allowRemoteExec) {
          ctx.ui.notify(
            "Remote command execution is disabled on this terminal, so a grant would do nothing. "
            + "Nothing was granted. To enable it, restart this terminal with --unsafe-remote-exec; "
            + "that peer would then be able to run commands as your local user. Structured "
            + "inspection (link_exec git_status, git_diff, read_file, list_dir) needs no grant.",
            "warning",
          );
          return;
        }

        const peer = otherTerminals().find(
          (t) => t.name === target || t.principalId === matched.principalId,
        );
        if (!peer) {
          ctx.ui.notify(
            `"${matched.deviceName}" is not connected right now. A grant is bound to a live agent instance, so connect first.`,
            "warning",
          );
          return;
        }

        const workspaceId = typeof inv.flags.workspace === "string" ? inv.flags.workspace : "*";
        const uses = typeof inv.flags.uses === "string" ? Math.max(1, parseInt(inv.flags.uses, 10) || 1) : 1;
        // No `--for`: the operator's configured grant lifetime, not a literal duplicated here.
        let durationMs = getTimings().grantDefaultMs;
        if (typeof inv.flags.for === "string") {
          const m = inv.flags.for.match(/^(\d+)(s|m|h)?$/);
          if (!m) {
            ctx.ui.notify(
              `"--for ${inv.flags.for}" is not a duration. Use a number with s, m or h, e.g. --for 10m. Nothing was granted.`,
              "warning",
            );
            return;
          }
          const value = parseInt(m[1], 10);
          durationMs = m[2] === "h" ? value * 3_600_000 : m[2] === "s" ? value * 1000 : value * 60_000;
        }

        if (!matched.permissions.execRequest) {
          ctx.ui.notify(
            `"${matched.deviceName}" does not have the execRequest capability. `
            + `Grant it deliberately with /link devices allow ${matched.deviceName} exec, then re-run this.`,
            "warning",
          );
          return;
        }

        createExecGrant(matched.principalId, peer.agentInstanceId, matched.deviceName, {
          workspaceId,
          durationMs,
          maxUses: uses,
        });
        ctx.ui.notify(
          `Command grant issued to "${matched.deviceName}" (agent ${peer.name}).\n`
          + `  workspace ${workspaceId} · ${Math.ceil(durationMs / 60000)}m · ${uses} use(s)\n`
          + `  ${MUTATION_GUARD_ADVISORY}`,
          "warning",
        );
        return;
      }

      case "revoke": {
        const target = inv.positionals[0];
        if (!target) {
          const count = revokeAllGrants("Manual revoke all");
          ctx.ui.notify(`Revoked ${count} active command grant(s). Paired devices are unchanged.`, "info");
          return;
        }
        const matched = getPairedDevice(target);
        if (!matched) {
          ctx.ui.notify(`Device "${target}" not found.`, "error");
          return;
        }
        const grants = revokeGrantsForPrincipal(matched.principalId, undefined, "Manual revocation");
        const unpaired = linkNode ? linkNode.revokeDevice(matched.principalId) : removePairedDevice(matched.principalId);
        ctx.ui.notify(
          `"${matched.deviceName}": ${grants} grant(s) revoked, ${unpaired ? "device unpaired and disconnected" : "device record not found"}.`,
          "info",
        );
        return;
      }

      case "shared": {
        // The receipt is rendered from the audit log, which is the only record of what actually
        // left this machine. Every type below is one that src/ really emits.
        const auditFile = path.join(getOmpDir(), "audit.log");
        let readable = true;
        if (fs.existsSync(auditFile)) {
          try {
            fs.accessSync(auditFile, fs.constants.R_OK);
          } catch {
            readable = false;
          }
        }
        if (!readable) {
          ctx.ui.notify(
            `${auditFile} exists but cannot be read, so no receipt can be shown. `
            + `Fix its permissions (it should be 0600 and owned by you).`,
            "error",
          );
          return;
        }

        const limitFlag = typeof inv.flags.limit === "string" ? parseInt(inv.flags.limit, 10) : NaN;
        if (typeof inv.flags.limit === "string" && (!Number.isInteger(limitFlag) || limitFlag < 1)) {
          ctx.ui.notify(`"--limit ${inv.flags.limit}" is not a positive whole number.`, "warning");
          return;
        }
        const limit = Number.isInteger(limitFlag) ? Math.min(limitFlag, 200) : 15;

        const events = readAuditLogs(2000);
        const matching = events.filter((e) => RECEIPT_EVENT_TYPES[String(e.type)] === true);
        const recent = matching.slice(-limit);
        // "Nothing recorded" and "nothing could be recorded" look identical to a user, and only
        // one of them means their machine is safe. Never print the reassuring one for the other.
        const receiptLog = getAuditLogStatus();
        if (recent.length === 0) {
          ctx.ui.notify(
            receiptLog.writable
              ? `No sharing or authorization decision is recorded yet.\nRecord: ${auditFile}`
              : `The audit log could not be written, so this receipt is incomplete and may be `
                + `missing decisions that were made.\nReason: ${receiptLog.error}\n`
                + `Fix write access to ${path.dirname(receiptLog.path)}, or set OMP_DIR to a writable directory, then run /link doctor.`,
            receiptLog.writable ? "info" : "error",
          );
          return;
        }
        const lines = recent.map((e) => {
          const when = new Date(Number(e.timestamp)).toISOString().slice(11, 19);
          const who = String(e.peer || e.displayName || e.principalId || e.target || e.from || "unknown").slice(0, 28);
          return `  ${when}Z ${String(e.type).padEnd(28)} ${who}`;
        });
        ctx.ui.notify(
          `Security decisions on this machine (${recent.length} of ${matching.length} recorded):\n${lines.join("\n")}\n\n`
          + (receiptLog.writable
            ? ""
            : `WARNING: the audit log is not writable (${receiptLog.error}), so newer decisions are missing.\n`)
          + `Note: a served inspection RPC is not logged individually; denials are.\n`
          + `Full record: ${auditFile}\n`
          + `Revoke every live command grant: /link revoke`,
          receiptLog.writable ? "info" : "warning",
        );
        return;
      }

      case "doctor": {
        const id = getOrCreateDeviceIdentity();
        const lines: string[] = ["omp-link doctor"];
        lines.push(`  version            ${getVersion()} (protocol 5)`);
        lines.push(`  device principal   ${id.principalId}`);
        lines.push(`  state directory    ${getOmpDir()}`);
        lines.push(`  paired devices     ${loadPairedDevices().size}`);
        if (wasPairedStoreReset()) {
          lines.push("  NOTE               the paired-device store was reset by an upgrade; re-pair your devices");
        }

        // Measured, not asserted.
        const state = linkState();
        lines.push(`  link state         ${state}`);
        if (linkNode?.role === "hub") {
          lines.push(`  listening          ${linkNode.bindHost}:${linkNode.port}`);
        }
        const probe = await findLocalHub();
        lines.push(`  port ${DEFAULT_PORT}         ${probe ? `omp-link hub, room ${probe.roomId || "unknown"}` : "no omp-link hub responded"}`);
        if (linkNode?.role === "client") {
          const negotiated = linkNode.getNegotiatedProtocol();
          lines.push(`  tls to host        ${negotiated || "not connected"}`);
          const hub = linkNode.getHubIdentity();
          lines.push(`  host identity      ${hub ? `${hub.principalId.slice(0, 28)}… pinned` : "unverified"}`);
        }
        const net = getNetworkInfo();
        lines.push(`  network            ${networkMode} · lan ${net.lanIps[0] || "none"} · tailscale ${net.tailscaleIp || "not detected"}`);
        // Re-read rather than reuse the load from activation: doctor must describe the file as
        // it is right now, including a fix the user just made.
        const configNow = loadConfig();
        const configOrigin = configNow.exists && !configNow.usedDefaults ? "file values" : "defaults";
        lines.push(`  config             ${configNow.path} (${configOrigin} in force)`);
        if (configNow.warning) {
          lines.push(`  config problem     ${configNow.warning}`);
        }
        lines.push(`  audit events       ${readAuditLogs(50).length} recent`);
        // A log that cannot be written makes every "no denials recorded" line a lie.
        const auditStatus = getAuditLogStatus();
        if (!auditStatus.writable) {
          lines.push(`  AUDIT LOG          NOT WRITABLE — security decisions are not being recorded`);
          lines.push(`                     ${auditStatus.error}`);
          lines.push(`                     Fix write access to ${path.dirname(auditStatus.path)} or set OMP_DIR to a writable directory.`);
        }
        ctx.ui.notify(lines.join("\n"), "info");
        return;
      }

      default:
        // Every agent-surface verb above has a case; this can only be a registry entry with no
        // handler, which is a bug in this file rather than something the user did wrong.
        ctx.ui.notify(
          `"/link ${inv.command}" is listed in the command registry but this build has no handler `
          + `for it. Nothing was done. Run /link help for what works.`,
          "error",
        );
    }
  }

  /**
   * A throw out of a command handler surfaces as an extension crash in the middle of a session,
   * which is a worse outcome than any single command failing. Local faults (an unwritable state
   * directory is the common one) are reported as what they are.
   */
  async function safeRunCommand(rawArgs: string, ctx: ExtensionContext, forced?: string): Promise<void> {
    try {
      await runCommand(rawArgs, ctx, forced);
    } catch (err: unknown) {
      const verb = forced || rawArgs.trim().split(/\s+/)[0] || "status";
      const message = err instanceof Error ? err.message : String(err);
      ctx.ui.notify(
        `/link ${verb} stopped on a local error: ${message}\n`
        + `  This is an omp-link fault on this machine, not a decision about a peer.\n`
        + `  Check that the state directory is readable and writable: ${getOmpDir()}`,
        "error",
      );
    }
  }

  /** The registry already knows every verb and what it does; offer them while typing. */
  function verbCompletions(argumentPrefix: string) {
    const typed = argumentPrefix.trimStart().toLowerCase();
    if (typed.includes(" ")) return null;
    return COMMANDS.filter((spec) => spec.surface !== "cli" && spec.name.startsWith(typed)).map((spec) => ({
      value: spec.name,
      label: spec.usage,
      description: spec.summary,
    }));
  }

  pi.registerCommand("link", {
    description: "Coordinate this terminal with other agents. Usage: /link [command]",
    getArgumentCompletions: verbCompletions,
    handler: async (args, ctx) => safeRunCommand(args, ctx),
  });

  // Legacy aliases delegate to the same parser; they never carry their own logic.
  for (const spec of COMMANDS) {
    if (spec.surface === "cli") continue;
    for (const alias of spec.aliases) {
      // `--help` and friends are CLI flag spellings, not slash commands.
      if (alias.startsWith("-")) continue;
      pi.registerCommand(alias, {
        description: `${spec.summary} (alias for /link ${spec.name})`,
        handler: async (args, ctx) => safeRunCommand(args, ctx, spec.name),
      });
    }
  }

  // `--link` is advertised as "connect to link on startup", so it has to actually do it.
  // Both host APIs are probed before use: an exception here runs before the renderer is
  // registered and would take the whole extension down with it.
  const linkFlag = typeof pi.getFlag === "function" ? pi.getFlag("link") : undefined;
  if (linkFlag === true && typeof pi.on === "function") {
    pi.on("session_start", async (_event, ctx) => {
      lastContext = ctx;
      await resumeRoom(ctx);
    });
  }

  pi.registerMessageRenderer("link", (message, _options, theme) => {
    const details = message.details as Record<string, unknown> | undefined;
    const from = details?.from ?? "link";
    const text = theme.fg("accent", `[${from}] `) + theme.fg("text", String(message.content));
    return new Text(text, 0, 0);
  });
}
