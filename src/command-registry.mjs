// Single source of truth for the omp-link command surface.
//
// Plain ESM so `bin/*.mjs` can import it under bare `node` (no loader, no build
// step) while `index.ts` imports it typed through the hand-written
// `command-registry.d.mts` under NodeNext resolution.
//
// Every help text, alias, arity rule and exit code lives here exactly once.

import { readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

// ── Exit codes ───────────────────────────────────────────────────────────────

export const EXIT = Object.freeze({
  /** Command completed. */
  OK: 0,
  /** Command ran and failed. */
  ERROR: 1,
  /** Caller's fault: unknown command, unknown flag, bad arity, wrong surface. */
  USAGE: 2,
  /** A required runtime, binary or state directory is missing. */
  UNAVAILABLE: 3,
  /** Refused on purpose: ownership unproven, confirmation withheld. */
  REFUSED: 4,
});

// ── Version (read from package.json, never hardcoded) ────────────────────────

const PACKAGE_JSON_PATH = path.join(path.dirname(path.dirname(fileURLToPath(import.meta.url))), "package.json");

let cachedVersion = null;

export function getVersion() {
  if (cachedVersion !== null) return cachedVersion;
  try {
    const pkg = JSON.parse(readFileSync(PACKAGE_JSON_PATH, "utf8"));
    cachedVersion = typeof pkg.version === "string" && pkg.version ? pkg.version : "unknown";
  } catch {
    cachedVersion = "unknown";
  }
  return cachedVersion;
}

// ── Flags ────────────────────────────────────────────────────────────────────

/**
 * Accepted on every command. `surface` is where the flag is actually honoured: a flag advertised
 * on a surface that ignores it is a lie, so the parser rejects it there instead.
 */
export const GLOBAL_FLAGS = Object.freeze([
  Object.freeze({
    name: "--json",
    kind: "boolean",
    surface: "cli",
    summary: "Emit machine-readable JSON instead of a rendered card",
  }),
  Object.freeze({
    name: "--no-input",
    kind: "boolean",
    surface: "cli",
    summary: "Never prompt; refuse instead of waiting for a human",
  }),
  Object.freeze({
    name: "--yes",
    kind: "boolean",
    surface: "both",
    summary: "Pre-approve the confirmation a command would otherwise ask for",
  }),
]);

/** The global flags a given surface honours. */
export function globalFlagsFor(surface) {
  return GLOBAL_FLAGS.filter((f) => f.surface === "both" || f.surface === surface);
}

function flag(name, kind, summary, placeholder) {
  return Object.freeze({ name, kind, summary, placeholder: placeholder ?? null });
}

// ── Commands ─────────────────────────────────────────────────────────────────

function command(spec) {
  return Object.freeze({
    name: spec.name,
    aliases: Object.freeze(spec.aliases ?? []),
    surface: spec.surface,
    usage: spec.usage,
    summary: spec.summary,
    details: Object.freeze(spec.details ?? []),
    flags: Object.freeze(spec.flags ?? []),
    minArgs: spec.minArgs ?? 0,
    maxArgs: spec.maxArgs ?? 0,
    hubOnly: spec.hubOnly ?? false,
  });
}

/**
 * The complete v3.4.0 command set. `surface` says where a command is real:
 * "agent" needs the live LinkNode inside OMP/Pi, "cli" only makes sense from a
 * shell, "both" works in either place.
 */
export const COMMANDS = Object.freeze([
  command({
    name: "status",
    surface: "both",
    usage: "status [--verbose]",
    summary: "Show the live link status card (this is the default command)",
    details: [
      "Reports role, authentication state and roster. A terminal that is not",
      "authenticated is never rendered as active.",
    ],
    flags: [flag("--verbose", "boolean", "Include raw SPKI principals, ports and grant details")],
  }),
  command({
    name: "on",
    surface: "agent",
    usage: "on",
    summary: "Rejoin the room this machine last used",
    details: [
      "Resumes a remembered room, reusing its pinned host identity. It never creates a room",
      "and never joins something merely because it was discovered: use `create` or `join`.",
    ],
  }),
  command({
    name: "off",
    aliases: ["leave", "link-leave"],
    surface: "agent",
    usage: "off",
    summary: "Leave the mesh from this terminal only",
    details: ["Other terminals, including a room you host, keep running. Use `end` to stop hosting."],
  }),
  command({
    name: "create",
    surface: "agent",
    usage: "create <name>",
    summary: "Host a new room called <name>",
    details: [
      "Always creates. It never silently joins something it found.",
      "A name may contain spaces; it is a label for humans, never sent on the wire.",
    ],
    minArgs: 1,
    maxArgs: 6,
  }),
  command({
    name: "join",
    aliases: ["link-join"],
    surface: "agent",
    usage: "join [endpoint|invite]",
    summary: "Join an existing room by endpoint or invite code",
    details: [
      "Positionals: <endpoint> [invite-secret] [fingerprint].",
      "Never creates a room. Discovery offers candidates; you choose one.",
    ],
    maxArgs: 3,
  }),
  command({
    name: "end",
    surface: "agent",
    usage: "end",
    summary: "Stop hosting for everyone (hub only)",
    details: ["Every joined peer is disconnected. The impact is named before it happens."],
    hubOnly: true,
  }),
  command({
    name: "scan",
    surface: "both",
    usage: "scan",
    summary: "Probe loopback, LAN and Tailnet for reachable hubs",
    details: ["Discovery is not trust: results are unverified until you pair."],
  }),
  command({
    name: "peers",
    surface: "agent",
    usage: "peers",
    summary: "List connected terminals with agent state and context usage",
  }),
  command({
    name: "invite",
    surface: "agent",
    usage: "invite",
    summary: "Mint a single-use, 5-minute pairing invite",
  }),
  command({
    name: "accept",
    surface: "agent",
    usage: "accept <id> <code>",
    summary: "Approve a pending pairing request",
    details: ["The 4-word SAS code is required. Compare it out of band first."],
    flags: [flag("--allow", "value", "Permissions to store, comma separated", "perms")],
    minArgs: 2,
    maxArgs: 2,
  }),
  command({
    name: "deny",
    surface: "agent",
    usage: "deny <id>",
    summary: "Reject a pending pairing request",
    minArgs: 1,
    maxArgs: 1,
  }),
  command({
    name: "devices",
    surface: "agent",
    usage: "devices [list|show|allow|deny|workspace|remove]",
    summary: "Inspect and edit paired device trust",
    details: [
      "devices                      list paired devices",
      "devices show <device>        full record for one device",
      "devices allow <device> <p1,p2>   add permissions",
      "devices deny <device> <p1,p2>    remove permissions",
      "devices workspace <device> <w1,w2>  scope a device to workspaces",
      "devices remove <device>      unpair (see also `revoke`)",
    ],
    maxArgs: 3,
  }),
  command({
    name: "grant",
    surface: "agent",
    usage: "grant <device>",
    summary: "Grant single-use remote exec to a paired device",
    details: ["The grant is bound to this agent instance, one workspace and one command digest."],
    flags: [
      flag("--workspace", "value", "Workspace the grant is bound to", "id"),
      flag("--for", "value", "Lifetime, e.g. 10m (default 10m)", "duration"),
      flag("--uses", "value", "Number of executions (default 1)", "n"),
    ],
    minArgs: 1,
    maxArgs: 1,
  }),
  command({
    name: "revoke",
    surface: "agent",
    usage: "revoke [device]",
    summary: "Revoke a device: drops its exec grants and unpairs it",
    details: [
      "One verb, no half state. Re-pairing requires a fresh SAS.",
      "With no device it revokes every live command grant and leaves pairings alone.",
    ],
    minArgs: 0,
    maxArgs: 1,
  }),
  command({
    name: "shared",
    surface: "both",
    usage: "shared [--limit <n>]",
    summary: "Sharing receipt: what this machine shared and decided",
    details: ["Rendered from the audit log, not from memory, so it survives restarts."],
    flags: [flag("--limit", "value", "Maximum receipt entries (default 20)", "n")],
  }),
  command({
    name: "doctor",
    aliases: ["link-doctor"],
    surface: "both",
    usage: "doctor",
    summary: "Measured diagnostics: identity, TLS, ports, listeners, policy",
    details: ["Reports observed values, never adjectives."],
  }),
  command({
    name: "cleanup",
    surface: "cli",
    usage: "cleanup [--apply]",
    summary: "Preview link-owned leftovers; only --apply changes anything",
    details: [
      "A terminal command: it inspects processes, ports and symlinks, which is",
      "shell work, not agent work. Targets are limited to state this tool owns:",
      "a legacy `hub` entry in link.json, orphaned inbox staging directories whose",
      "owner process is gone, and dead omp-link symlinks. A listening hub is only",
      "ever stopped when its ownership is proven and you confirm.",
    ],
    flags: [flag("--apply", "boolean", "Actually perform the previewed cleanup")],
  }),
  command({
    name: "help",
    aliases: ["--help", "-h"],
    surface: "both",
    usage: "help [command]",
    summary: "Show this help, or detailed help for one command",
    maxArgs: 1,
  }),
  command({
    name: "update",
    surface: "cli",
    usage: "update",
    summary: "Pull the latest omp-link and re-run setup",
  }),
  command({
    name: "version",
    aliases: ["--version", "-v"],
    surface: "cli",
    usage: "version",
    summary: "Print the installed omp-link version",
  }),
]);

/** Release that dropped the verbs below; used verbatim in the error text. */
const REMOVED_IN = "3.4.0";

/**
 * Verbs removed in v3.4.0, mapped to their replacement (or null when the verb
 * described something that never existed). Kept so both surfaces can fail with
 * a useful sentence instead of a generic "unknown command".
 */
export const REMOVED_COMMANDS = Object.freeze({
  start: "create",
  "link-start": "create",
  "revoke-grant": "revoke",
  unpair: "revoke",
  clean: "cleanup",
  reset: "cleanup",
  kill: "cleanup",
  find: "scan",
  discover: "scan",
  search: "scan",
  "link-network": null,
  "link-pin": null,
});

const BY_NAME = new Map();
for (const spec of COMMANDS) {
  BY_NAME.set(spec.name, spec);
  for (const alias of spec.aliases) BY_NAME.set(alias, spec);
}

export function findCommand(nameOrAlias) {
  if (typeof nameOrAlias !== "string") return null;
  return BY_NAME.get(nameOrAlias.trim().toLowerCase()) ?? null;
}

// ── Invocation parsing ───────────────────────────────────────────────────────

function flagKey(name) {
  return name.replace(/^-+/, "").replace(/-([a-z0-9])/g, (_m, c) => c.toUpperCase());
}

function knownFlags(spec, surface) {
  const map = new Map();
  for (const f of [...globalFlagsFor(surface), ...spec.flags]) map.set(f.name, f);
  return map;
}

function invocationPrefix(surface) {
  return surface === "agent" ? "/link" : "omp-link";
}

function usageLine(spec, surface) {
  return `Usage: ${invocationPrefix(surface)} ${spec.usage}`;
}

function fail(command, error) {
  return { command, positionals: [], flags: {}, error };
}

/**
 * Parse an argument vector (already stripped of the program name) against the
 * registry. Unknown flags and unknown commands are errors — never ignored.
 */
export function parseInvocation(argv, options) {
  const tokens = Array.isArray(argv) ? argv.filter((t) => typeof t === "string") : [];
  const surface = options?.surface ?? "cli";
  const defaultCommand = options?.defaultCommand ?? "status";

  if (tokens.some((t) => t === "--help" || t === "-h")) {
    const named = tokens.find((t) => !t.startsWith("-") && findCommand(t));
    return { command: "help", positionals: named ? [findCommand(named).name] : [], flags: {}, error: null };
  }

  const head = tokens[0];
  let spec;
  let rest;

  if (head !== undefined && head.startsWith("-") && findCommand(head)) {
    // A flag spelling of a verb: `--version`, `--help`.
    spec = findCommand(head);
    rest = tokens.slice(1);
  } else if (head === undefined || head.startsWith("-")) {
    // Leading global flags are allowed: `omp-link --json status` names the status command.
    const verbIndex = tokens.findIndex((t) => !t.startsWith("-") && findCommand(t));
    if (verbIndex >= 0) {
      spec = findCommand(tokens[verbIndex]);
      rest = tokens.filter((_t, i) => i !== verbIndex);
    } else {
      spec = findCommand(defaultCommand);
      rest = tokens;
    }
  } else {
    spec = findCommand(head);
    rest = tokens.slice(1);
    if (!spec) {
      const lowered = head.toLowerCase();
      if (Object.prototype.hasOwnProperty.call(REMOVED_COMMANDS, lowered)) {
        const replacement = REMOVED_COMMANDS[lowered];
        return fail(
          null,
          replacement
            ? `"${lowered}" was removed in v${REMOVED_IN}. Use "${invocationPrefix(surface)} ${replacement}" instead.`
            : `"${lowered}" was removed in v${REMOVED_IN}. It never had an implementation. Run "${invocationPrefix(surface)} help".`,
        );
      }
      return fail(null, `Unknown command "${head}". Run "${invocationPrefix(surface)} help" for the command list.`);
    }
  }

  if (!spec) return fail(null, `Unknown command "${defaultCommand}".`);

  if (spec.surface !== "both" && spec.surface !== surface) {
    const where =
      spec.surface === "agent"
        ? `runs inside the agent — type "/link ${spec.name}" in OMP or Pi`
        : `runs in a terminal — type "omp-link ${spec.name}" in a shell`;
    return fail(spec.name, `"${spec.name}" ${where}.`);
  }

  const accepted = knownFlags(spec, surface);
  const flags = {};
  const positionals = [];
  let literal = false;

  for (let i = 0; i < rest.length; i++) {
    const token = rest[i];

    if (literal || !token.startsWith("-") || token === "-") {
      positionals.push(token);
      continue;
    }
    if (token === "--") {
      literal = true;
      continue;
    }

    const eq = token.indexOf("=");
    const name = eq === -1 ? token : token.slice(0, eq);
    const inlineValue = eq === -1 ? null : token.slice(eq + 1);
    const known = accepted.get(name);

    if (!known) {
      const offered = [...accepted.keys()].join(", ");
      return fail(
        spec.name,
        `Unknown flag "${name}" for "${spec.name}". Accepted: ${offered}.\n${usageLine(spec, surface)}`,
      );
    }

    if (known.kind === "boolean") {
      if (inlineValue !== null) {
        return fail(spec.name, `Flag "${name}" takes no value.\n${usageLine(spec, surface)}`);
      }
      flags[flagKey(name)] = true;
      continue;
    }

    const value = inlineValue !== null ? inlineValue : rest[++i];
    if (value === undefined || value === "") {
      return fail(spec.name, `Flag "${name}" needs a value.\n${usageLine(spec, surface)}`);
    }
    flags[flagKey(name)] = value;
  }

  if (positionals.length < spec.minArgs) {
    return fail(spec.name, `"${spec.name}" needs ${spec.minArgs} argument(s).\n${usageLine(spec, surface)}`);
  }
  if (positionals.length > spec.maxArgs) {
    const extra = positionals.slice(spec.maxArgs).join(" ");
    return fail(spec.name, `Unexpected argument(s) "${extra}".\n${usageLine(spec, surface)}`);
  }

  return { command: spec.name, positionals, flags, error: null };
}

// ── Help rendering ───────────────────────────────────────────────────────────

/** Widest usage column before a row wraps its summary onto the next line. */
const COLUMN_WIDTH = 40;

function pad(text, width) {
  return text.length >= width ? text : text + " ".repeat(width - text.length);
}

function renderFlagList(flags, indent) {
  const rows = flags.map((f) => [f.kind === "value" ? `${f.name} <${f.placeholder ?? "value"}>` : f.name, f.summary]);
  const width = Math.max(...rows.map((r) => r[0].length));
  return rows.map(([left, right]) => `${indent}${pad(left, width)}  ${right}`).join("\n");
}

function renderCommandList(specs, prefix) {
  const rows = specs.map((spec) => [`${prefix} ${spec.usage}`, spec.summary]);
  const fitting = rows.map((r) => r[0].length).filter((len) => len <= COLUMN_WIDTH);
  const width = fitting.length > 0 ? Math.max(...fitting) : COLUMN_WIDTH;
  return rows
    .map(([left, right]) =>
      left.length > width ? `  ${left}\n  ${" ".repeat(width)}  ${right}` : `  ${pad(left, width)}  ${right}`,
    )
    .join("\n");
}

function renderOverview(surface) {
  const agentCommands = COMMANDS.filter((c) => c.surface === "agent" || c.surface === "both");
  const cliCommands = COMMANDS.filter((c) => c.surface === "cli" || c.surface === "both");

  return [
    `omp-link v${getVersion()} — peer-hosted coordination mesh for Oh My Pi and Pi`,
    "",
    "Usage:",
    "  omp-link [agent-options...]   Launch OMP/Pi with the omp-link extension loaded",
    "  omp-link <command> [args]     Run a terminal command",
    "  /link <command> [args]        Run a command inside the agent",
    "",
    "In the agent:",
    renderCommandList(agentCommands, "/link"),
    "",
    "In a terminal:",
    renderCommandList(cliCommands, "omp-link"),
    "",
    surface === "agent" ? "Global flags (in the agent):" : "Global flags:",
    renderFlagList([...globalFlagsFor(surface)], "  "),
    "",
    `Aliases: ${COMMANDS.filter((c) => c.aliases.length > 0)
      .map((c) => `${c.aliases.join(", ")} -> ${c.name}`)
      .join("; ")}`,
    "",
    `Detailed help: omp-link help <command>`,
    "",
  ].join("\n");
}

function renderCommand(spec, surface) {
  const lines = [
    `${spec.name} — ${spec.summary}`,
    "",
    `  In the agent : ${spec.surface === "cli" ? "not available" : `/link ${spec.usage}`}`,
    `  In a terminal: ${spec.surface === "agent" ? "not available" : `omp-link ${spec.usage}`}`,
  ];
  if (spec.hubOnly) lines.push("  Requires     : hosting this room");
  if (spec.aliases.length > 0) lines.push(`  Aliases      : ${spec.aliases.join(", ")}`);
  if (spec.details.length > 0) {
    lines.push("", ...spec.details.map((d) => `  ${d}`));
  }
  if (spec.flags.length > 0) {
    lines.push("", "  Flags:", renderFlagList([...spec.flags], "    "));
  }
  lines.push("", "  Global flags:", renderFlagList([...globalFlagsFor(surface)], "    "), "");
  return lines.join("\n");
}

/**
 * The one and only source of help text for both surfaces. `surface` decides which global flags
 * are advertised, because each surface only honours some of them.
 */
export function renderHelp(name, surface) {
  const where = surface === "agent" ? "agent" : "cli";
  if (name === undefined || name === null || name === "") return renderOverview(where);

  const spec = findCommand(name);
  if (spec) return renderCommand(spec, where);

  const lowered = String(name).trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(REMOVED_COMMANDS, lowered)) {
    const replacement = REMOVED_COMMANDS[lowered];
    const note = replacement
      ? `"${lowered}" was removed in v${REMOVED_IN}. Use "${replacement}" instead.`
      : `"${lowered}" was removed in v${REMOVED_IN}. It never had an implementation.`;
    return `${note}\n\n${renderOverview(where)}`;
  }
  return `Unknown command "${name}".\n\n${renderOverview(where)}`;
}
