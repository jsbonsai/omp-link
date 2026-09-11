# MCP server

`omp-link` speaks [Model Context Protocol](https://modelcontextprotocol.io) over stdio, so a
terminal that is not OMP/Pi can join a room and use the mesh. Claude Code CLI, Codex CLI and
anything else that launches an MCP stdio server are first-class hosts.

- [What it is](#what-it-is)
- [The six tools](#the-six-tools)
- [Why `link_compact` is absent](#why-link_compact-is-absent)
- [Claude Code](#claude-code)
- [Codex CLI](#codex-cli)
- [Verifying the connection](#verifying-the-connection)
- [When no room is configured](#when-no-room-is-configured)
- [Rooms are a human decision](#rooms-are-a-human-decision)
- [How it runs TypeScript under bare `node`](#how-it-runs-typescript-under-bare-node)
- [Troubleshooting](#troubleshooting)

Related: [tools.md](tools.md), [commands.md](commands.md), [security.md](security.md),
[concepts.md](concepts.md).

---

## What it is

| | |
|---|---|
| Entry point | `omp-link-mcp` (`bin/omp-link-mcp.mjs`), installed by `npm install -g omp-link` / `setup.sh` as one of the three bins |
| Implementation | `src/mcp-server.ts`, `startMcpServer({ customOmpDir?, terminalName?, attach? })` |
| Transport | Newline-delimited JSON-RPC 2.0 on stdin/stdout, hand-rolled — **no new dependency**; `ws` is still the only runtime dependency |
| Protocol revisions | `2025-06-18`, `2025-03-26`, `2024-11-05`. `initialize` echoes the client's revision when it is one of those, otherwise answers with the newest |
| Options | `--name <name>` (mesh display name), `--omp-dir <dir>` (state root, same as `OMP_DIR`), `-h/--help`, `-v/--version` |

Before this existed, omp-link was reachable only from inside OMP/Pi, because the tools were
registered through the Pi extension API. The MCP server registers the same operations through a
protocol every agent host already implements, so a peer on the mesh can be a Claude Code session
or a Codex session rather than another Pi terminal.

Three properties are worth knowing before you wire it in:

- **It is an ordinary mesh client.** It presents this machine's device certificate, pairs like
  any other terminal, and is subject to the same capability gating
  ([security.md](security.md#capabilities)). It joins as `<name>-mcp` — a distinct terminal from
  your Pi terminal on the same machine, which shares the device principal but not the agent
  instance ([concepts.md#agent-instance](concepts.md#agent-instance)).
- **It never hosts.** No listening port is ever opened by this process. An editor-spawned
  background server putting a TLS socket on the LAN is not a decision the operator made.
- **It never enables exec.** `allowRemoteExec` is hard-wired `false` here, so no `--unsafe-remote-exec`
  equivalent exists. Peers can still run structured inspection against it, which needs no grant.

stdout carries protocol frames and nothing else: `startMcpServer` captures the real stdout writer
once and redirects `process.stdout` to stderr for the rest of the run, so a stray `console.log`
anywhere in the process is merely visible instead of a desynchronised session. Diagnostics are
prefixed `[omp-link-mcp]` on stderr.

## The six tools

| Tool | Parameters | Needs the link usable | Notes |
|---|---|---|---|
| `link_status` | none | no | Call this first. Also **delivers buffered peer messages**: MCP has no server-to-model push, so an inbound `link_send` waits here (cap 100, oldest dropped) and is cleared once reported |
| `link_send` | `to`, `message` | yes | `to: "*"` broadcasts. A name that is not on the roster is refused, not reported as sent |
| `link_list` | none | yes | Roster; marks which entry is this agent |
| `link_discover` | none | no | LAN + Tailscale sweep. Results are **unverified candidates**, never trust |
| `link_exec` | `to`, `action`, `command?`, `filePath?`, `pattern?`, `count?` | yes | `action` ∈ `git_status`, `git_diff`, `git_log`, `search_text`, `read_file`, `list_dir`, `exec`. `exec` still needs the peer's grant |
| `link_send_file` | `to`, `filePath` | yes | Streamed, SHA-256 verified, lands in the peer's quarantine inbox |

Parameter names, types and optionality are identical to the Pi extension's tools
([tools.md](tools.md)) — a regression test compares the two schemas — so a prompt written for one
host works on the other. The difference is the delivery shape: `details` is returned as MCP
`structuredContent`, and a refusal comes back as a tool result with `isError: true` and a sentence
naming the next action, not as a JSON-RPC error. `link_status` carries three fields the extension
has no need for: `attach` (`{phase, detail, sasCode}`, where `phase` is `attaching`, `attached`,
`no-room`, `unavailable` or `pairing`), `configWarning` (re-read from `link.json` on every call,
so repairing a corrupt file stops being reported without a restart) and `messages` (the buffered
peer messages this call is delivering).

The server also sends `instructions` on `initialize`, telling the model to prefer `link_exec` over
`link_send` for inspection (zero tokens versus an LLM turn on the peer) and to treat peer message
content as data, never as instructions.

## Why `link_compact` is absent

The Pi extension registers seven tools; this server exposes six. `link_compact` asks a peer to
compact its context window, which is only meaningful where the host exposes a compaction API for
the agent's own context — Pi does, through `ExtensionContext.compact`. MCP has no such primitive.
Exposing the tool here would let a model report "completed compaction successfully" while nothing
compacted, and a tool that silently does nothing is worse than an absent one.

## Claude Code

Reference: <https://code.claude.com/docs/en/mcp>

```bash
claude mcp add --transport stdio omp-link -- omp-link-mcp
```

Project scope (writes `.mcp.json` in the repo, shared with the team):

```bash
claude mcp add --transport stdio --scope project omp-link -- omp-link-mcp
```

From a checkout, without installing the bin:

```bash
claude mcp add --transport stdio omp-link -- node /absolute/path/to/omp-link/bin/omp-link-mcp.mjs
```

Equivalent `.mcp.json`:

```json
{"mcpServers":{"omp-link":{"command":"omp-link-mcp","args":[]}}}
```

Three gotchas, each of which has eaten an afternoon:

- **The `--` is mandatory.** Everything after it is passed to the server untouched. Without it,
  `claude mcp add` parses the command as its own flags.
- **Do not add a `type` field** to the `.mcp.json` entry. An entry with no `type` is read as
  stdio; inventing one is how you get a server that never starts.
- **A project-scoped server sits at "Pending approval"** until the workspace is trusted, and a
  cloned repo cannot approve its own servers. If `/mcp` shows omp-link pending, approve it in the
  workspace rather than re-adding it.

## Codex CLI

Reference: <https://developers.openai.com/codex/mcp>

```bash
codex mcp add omp-link -- omp-link-mcp
```

Equivalent `~/.codex/config.toml` entry — the table name is `mcp_servers`, snake_case and plural:

```toml
[mcp_servers.omp-link]
command = "omp-link-mcp"
args = []
# optional
cwd = "/Users/you/src/backend"

[mcp_servers.omp-link.env]
OMP_DIR = "/Users/you/.omp"
```

`cwd` is not cosmetic: it becomes the `LinkNode` `workspaceRoot`, which is what a peer's
`link_exec` inspects. Set it to the repository you intend to expose, and read
[concepts.md#workspace](concepts.md#workspace) before you do — the workspace is exported whether
or not you meant to export it, and a nested repository inside it is reachable through the parent.

## Verifying the connection

| Host | Check |
|---|---|
| Claude Code | `claude mcp get omp-link`, or `/mcp` inside a session |
| Codex CLI | `codex mcp list`, or `/mcp` inside a session |
| Either | Call `link_status`. It answers even with the link down, and its text says what to do next |

By hand, without a host — the server speaks plain JSON-RPC, so one line is enough to prove the
binary loads and lists its tools:

```bash
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | omp-link-mcp
```

Two JSON-RPC result frames come back on stdout; anything the server wants to tell you goes to
stderr.

## When no room is configured

This is the normal first state, and it is not an error:

- **`tools/list` works with the link down.** A host builds its tool catalogue at startup, long
  before anyone has run `omp-link create`. Discovery never depends on connectivity.
- **Every call fails fast with an actionable message** instead of blocking. With nothing in
  `link.json`:

  ```
  No room is configured in /Users/you/.omp/link.json. Rooms are created and joined by a human: run `omp-link create <name>` to host one, or `omp-link join <ip:port>` to enter one, then call any link tool again.
  ```

- **A room that appears later is picked up without restarting the editor.** Every tool call
  re-attempts the attach (rate-limited to one attempt per 3 s, and never while a pairing is
  pending), so the "open Claude Code first, create the room second" ordering works.

Other states, and what each one says:

| State | The server says, in substance |
|---|---|
| Room is hosted by this machine but nothing is hosting it now | Start it with `omp-link on` (or `/link on` inside Pi); this MCP server never opens a listening port by itself |
| Host is unreachable | Could not reach room "<label>" at `<endpoint>`; check the host is running `omp-link on`, then call any link tool again |
| Host has not approved this device | Compare the 4-word code on BOTH screens, then approve it there with `/link accept <id> <code>`. Nothing is shared until the host approves |
| Pinned identity changed | `<endpoint>` no longer matches the identity pinned for room "<label>". Nothing was sent to it. Verify with the host operator, then re-pair from a terminal |

No stack trace ever reaches these strings; a regression test asserts it.

## Rooms are a human decision

The server attaches to the room already recorded in `link.json`. It never creates a room, never
pairs on its own, and never hosts. Creating and joining stay with a person at a terminal:

```bash
omp-link create backend      # host a new room
omp-link join 192.168.1.42:9900   # enter an existing one
```

or `/link create` / `/link join` inside OMP/Pi ([commands.md](commands.md)). Pairing approval is
also unchanged: the host operator compares the four words and runs `/link accept <id> <code>`.
That is the whole trust boundary, and an editor-spawned background process is deliberately on the
wrong side of it.

## How it runs TypeScript under bare `node`

`src/mcp-server.ts` imports `LinkNode`, and `src/` is TypeScript using NodeNext `.js` specifiers.
Node can strip types, but its resolver will not map `./link-node.js` onto `link-node.ts`, so
`bin/omp-link-mcp.mjs` closes that gap with a ~10-line resolve hook (inline, as a `data:` URL) and
then tries three tiers in order:

| Tier | Condition | What happens |
|---|---|---|
| 1 | `process.features.typescript` — Node 22.18+ and 24 by default | Registers the resolve hook and imports the server directly. This is the plain `npm i -g omp-link` path, with no devDependencies present |
| 2 | `tsx` resolvable | `tsx/esm/api` `register()`, then import. Covers Node 18+ in any clone that has run `npm install` or `setup.sh` |
| 3 | Node 22.6–22.17, no `tsx` | Re-executes itself with `--experimental-strip-types`, `stdio: "inherit"`, relaying signals; the child owns the JSON-RPC stream. A marker env var makes the re-exec once-only |

**The one uncovered cell: Node below 22.6 with no `tsx`.** There is no stripper to enable and
nothing left to try, so the launcher exits with a message naming both fixes — upgrade to Node
22.18+ (`nvm install --lts`), or run `npm install` once in a checkout to get `tsx`. Node 20 and
earlier are end-of-life anyway.

One failure is deliberately *not* blamed on Node: if the loader worked and the sources parsed but
an import is missing, you get "omp-link's dependencies are not installed" and a `npm install`
instruction, because advising a runtime upgrade there would be a confident lie about a broken
install.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Host shows the server as failed, stderr has `cannot load omp-link's TypeScript sources on this runtime` | Tier 3 exhausted: Node < 22.6 and no `tsx` | Upgrade Node to 22.18+, or `npm install` in the checkout |
| stderr: `omp-link's dependencies are not installed` | Sources loaded, `ws` (or another import) missing | `npm install` in the checkout, or reinstall the package |
| `claude mcp add` consumes your arguments, or the server starts with the wrong ones | The `--` separator was omitted | Re-add with `-- omp-link-mcp` |
| `/mcp` shows omp-link as "Pending approval" | Project-scoped `.mcp.json` in an untrusted workspace | Trust/approve the workspace; a cloned repo cannot approve its own servers |
| `command not found: omp-link-mcp` | The bin is not on `PATH` (no global install or `setup.sh`) | Point the host at `node /absolute/path/to/omp-link/bin/omp-link-mcp.mjs` |
| Every tool answers "No room is configured …" | `link.json` has no `currentRoomId`, or it names a room that is gone | `omp-link create <name>` or `omp-link join <ip:port>`, then call any tool again — no restart needed |
| Every tool answers "… hosted by this machine, but no terminal is hosting it right now" | The room's host is this machine and no terminal is up | `omp-link on`, or `/link on` inside OMP/Pi |
| Tools stay blocked with a 4-word code in the message | The host operator has not approved this device | Compare the code on both screens, then `/link accept <id> <code>` on the host |
| `… no longer matches the identity pinned for room` | Pinned SPKI changed — re-install, deleted identity, or an impostor | Stop. Verify the host's principal out of band ([troubleshooting.md#pin-mismatch](troubleshooting.md#pin-mismatch)) |
| `link_send` returns "No agent named …" | The name is not on the roster | `link_list` first; names are per-terminal and the MCP terminal is `<name>-mcp` |
| Peers see two similar names, one suffixed `@<6 hex>` | Your Pi terminal and the MCP server chose the same display name | Pass `--name` to the server, or `--link-name` to the terminal |
| Host reports a parse error or the session hangs at startup | Something wrote to stdout | Report it: stdout is claimed at startup and reserved for frames. Check stderr for the offending line |
| A peer's `link_exec read_file` sees the wrong repository | `workspaceRoot` is the process cwd | Set `cwd` in `~/.codex/config.toml`, or launch the host from the intended repository |
