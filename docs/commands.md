# Command reference

Derived from [`src/command-registry.mjs`](../src/command-registry.mjs), which is the single
source of truth for verbs, aliases, arity, flags, surfaces, help text and exit codes. Both
`index.ts` (`/link`) and `bin/omp-link.mjs` (`omp-link`) parse through the same
`parseInvocation`, so the refusal messages below are literal.

- [Surfaces](#surfaces)
- [Global flags](#global-flags)
- [The commands](#the-commands)
- [Removed verbs](#removed-verbs)
- [Refusal messages](#refusal-messages)
- [Exit codes](#exit-codes)
- [Two things to know](#two-things-to-know)

Related: [tools.md](tools.md), [security.md](security.md), [mcp.md](mcp.md),
[troubleshooting.md](troubleshooting.md).

---

## Surfaces

| `surface` | Where it runs | Invocation prefix |
|---|---|---|
| `agent` | Needs the live `LinkNode` inside OMP/Pi | `/link` |
| `cli` | Only makes sense from a shell | `omp-link` |
| `both` | Either | both |

The default command is `status`: bare `/link` and bare `omp-link status` are the same
verb, and `parseInvocation([], …)` returns `{command: "status"}`. Bare `omp-link` with no
arguments is **not** the status command — it is a launcher invocation that starts OMP/Pi
with the extension loaded.

`omp-link-mcp` is a **separate binary**, not a verb in this registry: it is the MCP stdio
server an MCP host launches, and it takes only `--name`, `--omp-dir`, `--help` and
`--version` ([mcp.md](mcp.md)). Everything a human decides — creating a room, joining one,
approving a pairing — stays on the surfaces below.

`omp-link help` renders the full list at any time:

```bash
omp-link help
```

```
omp-link v3.5.0 — peer-hosted coordination mesh for Oh My Pi and Pi

Usage:
  omp-link [agent-options...]   Launch OMP/Pi with the omp-link extension loaded
  omp-link <command> [args]     Run a terminal command
  /link <command> [args]        Run a command inside the agent
```

## Global flags

Accepted on every command, on the surface each one names (`GLOBAL_FLAGS`, `globalFlagsFor`).
A flag is only offered where it is honoured, so spelling a CLI-only flag at the `/link`
prompt is an unknown-flag error rather than a silent no-op.

| Flag | Kind | Surface | Summary | Actually honoured by |
|---|---|---|---|---|
| `--json` | boolean | `cli` | Emit machine-readable JSON instead of a rendered card | `omp-link status/scan/shared/doctor/cleanup/help/version` |
| `--no-input` | boolean | `cli` | Never prompt; refuse instead of waiting for a human | `omp-link cleanup`, `omp-link update` (via `confirm()`) |
| `--yes` | boolean | `both` | Pre-approve the confirmation a command would otherwise ask for | `/link end`, `omp-link cleanup`, `omp-link update` |

Unknown flags are errors, never ignored:

```bash
omp-link status --bogus
```

```
Unknown flag "--bogus" for "status". Accepted: --json, --no-input, --yes, --verbose.
Usage: omp-link status [--verbose]
```

Value flags accept `--flag value` and `--flag=value`. A boolean flag given a value is an
error (`Flag "--json" takes no value.`), and a value flag without one is too
(`Flag "--for" needs a value.`). `--` ends flag parsing; everything after it is a
positional.

> **Leading global flags are fine on the CLI.** `omp-link --json status` is the status
> command: dispatch looks for the first argv token that is not a flag (or is a flag
> spelling of a verb), and `parseInvocation` lifts the verb out of a flag-led argv. Only an
> argv with no recognised verb at all is forwarded to the agent binary as a launcher
> invocation. `--help`/`-h` and `--version`/`-v` work anywhere, because they are registered
> aliases.

## The commands

`Args` shows `minArgs..maxArgs` as enforced by `parseInvocation`.

| Verb | Surface | Usage | Args | Flags | Aliases |
|---|---|---|---|---|---|
| `status` | both | `status [--verbose]` | 0..0 | `--verbose` | — |
| `on` | agent | `on` | 0..0 | — | — |
| `off` | agent | `off` | 0..0 | — | `leave`, `link-leave` |
| `create` | agent | `create <name>` | 1..6 | — | — |
| `join` | agent | `join [endpoint\|invite]` | 0..3 | — | `link-join` |
| `end` | agent | `end` | 0..0 | — | — |
| `scan` | both | `scan` | 0..0 | — | — |
| `peers` | agent | `peers` | 0..0 | — | — |
| `invite` | agent | `invite` | 0..0 | — | — |
| `accept` | agent | `accept <id> <code>` | 2..2 | `--allow <perms>` | — |
| `deny` | agent | `deny <id>` | 1..1 | — | — |
| `devices` | agent | `devices [list\|show\|allow\|deny\|workspace\|remove]` | 0..3 | — | — |
| `grant` | agent | `grant <device>` | 1..1 | `--workspace <id>`, `--for <duration>`, `--uses <n>` | — |
| `revoke` | agent | `revoke [device]` | 0..1 | — | — |
| `shared` | both | `shared [--limit <n>]` | 0..0 | `--limit <n>` | — |
| `doctor` | both | `doctor` | 0..0 | — | `link-doctor` |
| `cleanup` | cli | `cleanup [--apply]` | 0..0 | `--apply` | — |
| `help` | both | `help [command]` | 0..1 | — | `--help`, `-h` |
| `update` | cli | `update` | 0..0 | — | — |
| `version` | cli | `version` | 0..0 | — | `--version`, `-v` |

`end` additionally carries `hubOnly: true`, which the registry renders as
`Requires     : hosting this room` and `index.ts` enforces at run time.

### status

Role, authentication state, roster. **Never renders an unauthenticated terminal as
active** — the card is a projection of `linkState()`, which returns `off`, `starting`,
`pairing`, `hosting`, `connected`, `reconnecting` or `blocked`.

`--verbose` adds the raw device principal, device SPKI, agent instance uuid, room id and
the config path. `--json` is CLI-only and is rejected at the `/link` prompt; on the CLI it
emits `{version, ompDir, config, localHub}`.

Refuses nothing. Works with the link off.

### on

Resumes the room in `link.json`'s `currentRoomId`, reusing its pinned host identity.

Refuses to create a room, and refuses to join something merely because it was discovered:

```
No room remembered on this machine.
  /link scan            see what is reachable
  /link join <ip:port>  join an existing room
  /link create <name>   host a new one
```

### off

Leaves the mesh from this terminal only: `linkNode.stop()` plus
`revokeAllGrants("Link deactivated")`. Other terminals, including a room you host, keep
running. Use `end` to stop hosting for everyone.

### create

Always creates a new room: a fresh `roomId` uuid bound to this device's principal. Never
silently joins something it found. The one exception is a genuine `EADDRINUSE` where the
port holder answers `/status` as an omp-link hub, in which case it joins the local sibling
rather than pretending to have created a second room — and says so.

Refuses an empty name: `Name the room: /link create <name>`.

### join

`Positionals: <endpoint> [invite-secret] [fingerprint]`.

With an endpoint it connects to `wss://<endpoint>`. With no positionals it discovers, then
asks you to pick through `ctx.ui.select`, and if the UI cannot present a choice it prints
the candidate list with copy-pasteable commands instead. **Discovery never chooses for
you, not even when there is exactly one answer.**

Refuses to create a room, ever. A failed join is a failed join — there is no fallback to
hosting.

> The usage string reads `join [endpoint|invite]`, but the handler always treats
> positional 0 as an endpoint (`connectToHub("wss://" + endpoint)`). An invite is
> `join <endpoint> <secret> <fingerprint>`, which is exactly what `/link invite` prints.

### end

Stops hosting for everyone. Names the impact before acting, and will not proceed without
`--yes` while peers are connected:

```
This will drop 2 connected agents: linux-box, other-mac.
Run /link end --yes to confirm.
```

Refuses when this terminal is not the hub:
`This agent is not hosting a room. Use /link off to leave.`

### scan

Probes loopback, then LAN UDP broadcast and/or the Tailnet according to `networkMode`.

```
Reachable hubs (1). Unverified — joining still requires a code or a pin:
  192.168.1.42:9900 [lan] room 6f1c0a5e-...
    join: /link join 192.168.1.42:9900
```

Refuses to establish trust. `[…]` sources are `local`, `lan`, `tailscale`. The CLI version
adds the negotiated TLS version and the claimed SPKI, and labels it plainly:

```
These fingerprints are claims by an unauthenticated endpoint. Compare them out of band
during pairing (/link accept <id> <code>); nothing here establishes trust.
```

### peers

Roster plus, for each remote agent, what its paired-device record permits.

```
Agents in "backend":
  mac-mini (this agent) · omp-link
  linux-box · api · can: send messages
```

Refuses when the link is not usable, with the reason:
`Link is off. Use /link join to enter an existing room, or /link create <name> to host one.`

### invite

Mints a single-use, 5-minute pairing invite held in memory.

Refuses on a non-hub:
`Only the hosting terminal can issue invites. Use /link create <name> first.`

### accept

Approves a pending pairing request. **The code is required** and compared in constant
time after stripping non-alphanumerics and upper-casing.

`--allow <perms>` **replaces** the whole stored capability set (anything not listed becomes
`false`); omitting it stores `DEFAULT_PERMISSIONS`. Tokens are the same as
`devices allow`, listed in [security.md#capabilities](security.md#capabilities).

```
/link accept 1 canyon-ember-violet-rapid --allow message,metadata
```

Refuses a missing code at parse time (`"accept" needs 2 argument(s).`), a non-numeric id,
and a wrong code — auditing `pairing_rejected_invalid_sas` and telling the peer so it
fails fast rather than hanging for the pairing window (`pairingWindowMs`, 60 s by
default).

### deny

Rejects a pending pairing request, sends `pair_response{approved:false}` with reason
`Pairing request was denied by the host`, closes `4403`, audits `pairing_denied`.

### devices

| Sub-verb | Effect |
|---|---|
| `devices` / `devices list` | Every paired device with its capabilities and pairing date |
| `devices show <device>` | Principal, SPKI, capabilities, workspace scope, paired-at, last-seen |
| `devices allow <device> <p1,p2>` | **Merges** the named capabilities on |
| `devices deny <device> <p1,p2>` | **Merges** the named capabilities off |
| `devices workspace <device> <w1,w2>` | Stores a workspace list on the record |
| `devices remove <device>` | Unpairs (see also `revoke`) |

`<device>` matches on device name, full principal id, or an SPKI fingerprint prefix
(`findDevice`, case-insensitive on the fingerprint). `allow`/`deny` take effect on live
connections immediately, not at the next reconnect (`updatePeerPermissions`).

Refuses an unknown device (`Device "<x>" not found.`), a missing device
(`Usage: /link devices show <device>`), a missing capability list
(`Usage: /link devices allow <device> <capability,capability>` plus the token list), an
unrecognised capability token (`Unknown capability: frob. Nothing was changed.`), and an
unknown sub-verb, which is caught before anything is loaded:

```
"frob" is not a devices subcommand. Use one of: list, show, allow, deny, workspace, remove.
Usage: /link devices [list|show|allow|deny|workspace|remove]
```

> `devices workspace` persists the list and warns when an id is not exported by this
> terminal (`Not exported by this terminal: <id> — that scope matches nothing here.`), but
> nothing *enforces* it: the value is only echoed back in `system_status`. Scope by launch
> directory instead — [scenarios.md#e-nested-repositories](scenarios.md#e-nested-repositories).

### grant

Issues a single-use exec grant bound to `(principalId, agentInstanceId)`, one
`workspaceId`, and — once used — a sha256 command digest.

`--for` accepts `<n>[s|m|h]`, default `10m`. `--uses` defaults `1`. `--workspace` defaults
`*`.

Refuses, in this order: no device argument, unknown device, link off
(`Link is off; there is no connection to grant against.`), exec disabled on this terminal,
peer not currently connected
(`"<name>" is not connected right now. A grant is bound to a live agent instance, so connect first.`),
and finally a device lacking the base `execRequest` capability:

```
"linux-box" does not have the execRequest capability. Grant it deliberately with /link devices allow linux-box exec, then re-run this.
```

On success it prints the advisory verbatim:

```
Command grant issued to "linux-box" (agent linux-box).
  workspace * · 10m · 1 use(s)
  Full shell access granted. Mutation Guard is advisory and does not provide containment. Treat this peer as having local-user access.
```

> Remote execution is off unless this terminal was launched with `--unsafe-remote-exec`.
> `index.ts` registers that flag and passes its value as `allowRemoteExec`; it is never
> written to `link.json`, so it has to be re-stated every time the terminal starts. Without
> it this command stops before issuing anything:
> `Remote command execution is disabled on this terminal, so a grant would do nothing. Nothing was granted. To enable it, restart this terminal with --unsafe-remote-exec; that peer would then be able to run commands as your local user. Structured inspection (link_exec git_status, git_diff, read_file, list_dir) needs no grant.`
>
> The flag is only the first of the three gates: the device still needs `execRequest`, and
> the grant is still single-use. Clearing all three hands that peer local-user access.

### revoke

One verb, no half state: drops the device's exec grants **and** unpairs it, closing any
live socket with `4403 Device pairing revoked`.

```
"linux-box": 1 grant(s) revoked, device unpaired and disconnected.
```

With no argument it revokes every active grant and leaves pairings alone:

```
Revoked 3 active command grant(s). Paired devices are unchanged.
```

### shared

Sharing receipt rendered from `audit.log`, not from memory, so it survives restarts. See
[security.md#reading-the-audit-log](security.md#reading-the-audit-log). Both surfaces
filter the log down to event types `src/` really emits, and format differently: `--limit`
clamps to 1..500 (default 20) on the CLI and to 1..200 (default 15) in the agent, and
`--json` is CLI-only.

### doctor

Measured diagnostics: observed values, never adjectives. Line-by-line reading:
[troubleshooting.md#reading-doctor](troubleshooting.md#reading-doctor).

### cleanup

CLI only. Preview by default; `--apply` acts. Targets are limited to state this tool owns:

- a stale `hub` key in `link.json` (only when nothing answers at that endpoint),
- inbox staging directories `rx-<pid>-…` whose owner pid is dead **and** which are idle
  past 120 s (`ORPHAN_STAGING_IDLE_MS`, mirroring `ABSOLUTE_TIMEOUT_MS`),
- dangling omp-link/pi-link symlinks.

Refuses to signal a listener it cannot prove is an omp-link hub owned by you, and even
then asks:

```
      REFUSING to stop it: the listener did not answer /status as an omp-link hub
      This CLI never signals a process it cannot prove is an omp-link hub owned by you.
```

With `--apply` and no `--yes` under `--no-input`, it exits `4` (`REFUSED`):
`Skipped stopping the hub: --no-input was given and --yes was not.`

### help

`help` or `help <command>`; `--help`/`-h` anywhere in argv short-circuits to help, and a
recognised verb elsewhere in argv selects that verb's page. `--json` on the CLI emits
`{version, globalFlags, commands, removed}`.

### update

CLI only. `git pull --rebase --autostash`, `npm install --silent`, then `setup.sh`.

Refuses without a git checkout:
`No git checkout at <dir>. Extract the new version and run ./setup.sh.` (exit `3`), and
refuses `--json` because it streams subprocess output (exit `2`).

### version

CLI only. Reads `version` from `package.json` at runtime — never a hardcoded string; falls
back to `unknown` if the read fails.

## Removed verbs

`REMOVED_COMMANDS` exists so both surfaces fail with a useful sentence instead of a generic
"unknown command".

| Removed verb | Replacement | Message |
|---|---|---|
| `start` | `create` | `"start" was removed in v3.4.0. Use "omp-link create" instead.` |
| `link-start` | `create` | same shape |
| `revoke-grant` | `revoke` | same shape |
| `unpair` | `revoke` | same shape |
| `clean` | `cleanup` | same shape |
| `reset` | `cleanup` | same shape |
| `kill` | `cleanup` | same shape |
| `find` | `scan` | same shape |
| `discover` | `scan` | same shape |
| `search` | `scan` | same shape |
| `link-network` | none | `"link-network" was removed in v3.4.0. It never had an implementation. Run "omp-link help".` |
| `link-pin` | none | same shape |

The prefix in the message adapts to the surface: `/link create` inside the agent,
`omp-link create` in a shell. `omp-link help <removed-verb>` prints the note followed by
the full overview.

`link-network` having no replacement is the reason `networkMode` is edited in
`link.json` directly — see
[scenarios.md#c-two-machines-over-tailscale](scenarios.md#c-two-machines-over-tailscale).

## Refusal messages

Wrong surface, checked before arity and before flags:

```
"on" runs inside the agent — type "/link on" in OMP or Pi.
"update" runs in a terminal — type "omp-link update" in a shell.
```

Arity:

```
"accept" needs 2 argument(s).
Usage: /link accept <id> <code>
```

```
Unexpected argument(s) "extra words".
Usage: /link create <name>
```

Unknown verb:

```
Unknown command "frobnicate". Run "omp-link help" for the command list.
```

## Exit codes

CLI only (`EXIT` in the registry). The `/link` surface has no exit code; it notifies.

| Code | Name | Meaning |
|---|---|---|
| 0 | `OK` | Command completed |
| 1 | `ERROR` | Command ran and failed |
| 2 | `USAGE` | Caller's fault: unknown command, unknown flag, bad arity, wrong surface |
| 3 | `UNAVAILABLE` | A required runtime, binary or state directory is missing |
| 4 | `REFUSED` | Refused on purpose: ownership unproven, confirmation withheld |

`omp-link doctor` returns `3` when Node is older than 18, `0` otherwise. A launcher
invocation exits with the agent process's own code.

## Two things to know

1. **`cleanup` is a shell command, and the registry says so.** It is `surface: "cli"`, so
   it is absent from the agent help and `/link cleanup` is refused before anything runs:
   `"cleanup" runs in a terminal — type "omp-link cleanup" in a shell.` The real thing is
   `omp-link cleanup`.
2. **`--json` and `--no-input` do not exist on the `/link` surface.** `GLOBAL_FLAGS`
   carries a `surface` per flag and `knownFlags` only accepts the ones the current surface
   honours, so `/link status --json` fails with
   `Unknown flag "--json" for "status". Accepted: --yes, --verbose.` instead of being
   quietly dropped. For machine-readable state inside the agent use the `link_status` tool,
   which returns a structured `details` payload —
   [tools.md#link_status](tools.md#link_status).
