# omp-link

> **Multi-Machine & Multi-Codebase Inter-Terminal Coordination Mesh for [Oh-My-Pi (OMP)](https://github.com/can1357/oh-my-pi) and [Pi](https://github.com/badlogic/pi-mono).**  
> Turn multiple terminal windows across your Mac, Linux workstation, Raspberry Pi, or cloud VMs into a unified collaborative swarm over **Tailscale** and **LAN**.  
> **Not OMP-only:** an MCP stdio server (`omp-link-mcp`) puts the same mesh inside **Claude Code**, **Codex CLI** and anything else that speaks MCP — no new dependency, no relay, same TLS 1.3 and pairing. See [docs/mcp.md](docs/mcp.md).

---

## What It Looks Like When It Works

When `omp-link` is running, type `/link` inside OMP to see your live mesh dashboard:

```text
⚡ OMP-LINK: HOSTING (authenticated)
  Room     : "team-swarm" (r-8f31c2) [TAILSCALE]
  Endpoint : 100.82.12.4:9900
  Terminal : macbook-pro
  Peers (3): macbook-pro (this), linux-workstation, cloud-vm

Quick Commands:
  /link on | off          Turn the mesh on, or leave from this terminal
  /link scan              Look for reachable hubs (unverified candidates)
  /link join [ip:port]    Join an existing room
  /link invite            Create a one-time pairing invite code
  /link doctor            Measured TLS and system diagnostics
  /link help              Show the full command reference
```

### Live Peer Joining & Message Stream
When another terminal connects or sends a message, OMP displays live status notifications:

```text
⚡ Joined room "team-swarm" (r-8f31c2) [Tailscale: 100.82.12.4:9900]
"linux-workstation" joined the link

[Link: 1 message(s) received]

From "linux-workstation" (ed25519-sha256:40:E0:8C:...):
I have refactored auth.ts and run the test suite. All 14 tests pass.
```

---

## Why omp-link? (Zero-Infrastructure Peer-Hosted Coordination)

Most multi-agent or remote terminal tools require setting up an external relay server, deploying Docker containers, managing cloud brokers (like MQTT), or routing traffic through a third-party service.

`omp-link` takes an entirely different approach: **zero infrastructure, zero central servers, and zero manual port forwarding.**

| Feature | Centralized Relays | `omp-link` |
|---|---|---|
| **Infrastructure** | Requires dedicated cloud server or VPS | **Zero**. Runs 100% inside your local OMP terminal |
| **Server Management** | Must maintain, monitor, and pay for background daemons | **None**. No daemon processes, no external services |
| **Connection Topology** | Hub-and-spoke routed through third-party cloud | **Peer-Hosted Network** across Tailscale & local LAN |
| **Security Architecture** | Third-party relay operator can read and retain your traffic | **Mutual TLS 1.3** with client & server SPKI pinning. The hub is one of *your* machines — it terminates TLS and routes every message, so there is no client-to-client E2EE (`SECURITY.md` §1) |
| **Reachability** | Manual port-forwarding or relay join tokens | **Autonomous discovery** across Tailnet & LAN UDP |

### The Peer-Hosted Model
Instead of requiring external servers, `omp-link` uses an autonomous peer-host model:
1. **Zero-Config Discovery**: When you launch OMP or type `/link on`, it automatically checks if an active session already exists on `localhost`, your Tailnet, or local LAN. If found, it joins immediately as a client node. If no session exists, it anchors the session as the Host Hub.
2. **Local Terminal Multiplexing**: If you open multiple terminal windows on the same laptop, subsequent terminals automatically detect the local host on port 9900 and join as clients without port collision errors.
3. **Link in a Single Command**: You don't manage IP tables or firewalls. Start your terminals and run `/link on` or `/link scan` to coordinate your machines into a unified swarm.

---

## Consolidated Slash Command Interface

All coordination happens directly inside OMP through the unified `/link` command:

Every command is defined once in `src/command-registry.mjs`, which is what the agent surface, the
`omp-link` CLI and `omp-link help` all read from. If a verb is not in the table below it does not exist.

| Command | Usage | Description |
|---|---|---|
| **`/link`** | `/link`<br>`/link status [--verbose]` | **Dashboard**: live status card — role, room, endpoint, authentication state and roster. A terminal that is not authenticated is never shown as active. `--verbose` adds raw SPKI principals. |
| **`/link on` / `/link off`** | `/link on`<br>`/link off` | **Mesh control for this terminal**: join a reachable room or host one; `off` leaves without disturbing anyone else. *(Alias: `/link-leave`, `/link leave`)* |
| **`/link create`** | `/link create <name>` | **Host**: always creates a new room under `<name>`. It never silently joins something it discovered. |
| **`/link join`** | `/link join [endpoint\|invite]` | **Connect**: join an existing room by endpoint or invite. Never creates one. *(Alias: `/link-join`)* |
| **`/link end`** | `/link end` | **Stop hosting for everyone** (hub only): names the peers that will be dropped, then disconnects them. |
| **`/link scan`** | `/link scan` | **Discovery**: probe loopback, LAN broadcast and Tailnet for reachable hubs. Results are unverified candidates — discovery is not trust. |
| **`/link peers`** | `/link peers` | **Roster**: connected terminals with agent state and context-window usage. |
| **`/link invite`** | `/link invite` | **One-time pairing**: single-use, 5-minute invite code for a new device. |
| **`/link accept` / `/link deny`** | `/link accept <id> <code>`<br>`/link deny <id>` | **Pairing governance**: the 4-word SAS code is **required** — approving without one fails closed. |
| **`/link devices`** | `/link devices [list\|show\|allow\|deny\|workspace\|remove]` | **Trusted devices**: inspect paired identities and edit their permissions or workspace scope. |
| **`/link grant`** | `/link grant <device>` | **Execution elevation**: single-use exec grant bound to this agent instance, one workspace and one command digest (requires `--unsafe-remote-exec`). |
| **`/link revoke`** | `/link revoke <device>` | **One verb, no half state**: drops the device's exec grants *and* unpairs it. Re-pairing needs a fresh SAS. |
| **`/link shared`** | `/link shared` | **Sharing receipt**: what this machine actually shared and decided, rendered from `audit.log`. |
| **`/link doctor`** | `/link doctor` | **Measured diagnostics**: identity files, negotiated TLS version, listeners, effective policy — observed values, not adjectives. *(Alias: `/link-doctor`)* |
| **`/link cleanup`** | `/link cleanup [--apply]` | **Leftovers**: preview link-owned state (stale cached hub, orphaned inbox staging dirs, dead symlinks). Changes nothing without `--apply`. |
| **`/link help`** | `/link help [command]` | **Command reference**: the same text as `omp-link help`. |

Global flags on every command: `--json`, `--no-input`, `--yes`.

> [!NOTE]
> Removed in v3.4.0: `/link start` (use `create`), `/link revoke-grant` and `/link unpair` (both use `revoke`),
> and the never-implemented `/link-start`, `/link-network` and `/link-pin`. Only three convenience aliases
> survive: `/link-join`, `/link-leave` and `/link-doctor`.

---

## Agent Tools (Autonomous Swarm Operation)

Agents running inside OMP have access to 7 registered coordination and execution tools. Six of them — everything except `link_compact` — are also exposed to MCP hosts by `omp-link-mcp`, with identical parameters ([docs/mcp.md](docs/mcp.md)):

### 1. `link_exec` (Direct Tool RPC — Structured Inspection, Zero LLM Tokens)
Execute fast, safe, structured inspection operations directly on a remote terminal without shell injection risks or waking up the remote agent's LLM reasoning loop!
```json
{
  "to": "linux-workstation",
  "action": "git_status"
}
```
Supported structured inspection actions (all executed with **no shell** via `execFile`):
- `git_status`: Clean, porcelain repository status.
- `git_diff`: Working tree diff (`--no-ext-diff`, `--no-textconv` prevents arbitrary external filter execution).
- `git_log`: Recent commit history (bounded between 1 and 100 commits via `count`).
- `search_text`: Grep repository files using `pattern` (`git grep -n -I`).
- `read_file`: Confined workspace file reading (canonical `fs.realpath` verification protects against symlink escapes and denies `.env*`, `.git/*`, and keys).
- `list_dir`: Confined directory listing filtering sensitive directories.
- `exec`: Blocked by default under Territorial Sovereignty. When disabled, common read commands like `git status` or `git diff` automatically route to safe structured operations. A host unlocks arbitrary execution per device with `/link grant <device>` (single use, and only when the host process was started with `--unsafe-remote-exec`).

### 2. `link_send_file` (Hardened Out-of-Band File Transfer)
Stream files directly between machines across LAN or Tailscale with chunked delivery, SHA-256 integrity verification, and automatic quarantine into `.omp/inbox/<transferId>/<safeFilename>`:
```json
{
  "to": "linux-workstation",
  "sourcePath": "./dist/app.bundle.js"
}
```
*Files are transmitted in 64KB chunks over the mutually authenticated TLS 1.3 link to the hub, which decrypts and forwards them — there is no client-to-client E2EE (`SECURITY.md` §1). Transfers are verified against a 50MB ceiling and reassembled with SHA-256 verification, strictly isolated to dedicated quarantine directories so they never overwrite existing project code.*

### 3. `link_send` (Agent-to-Agent Reasoning Delegation)
Send a high-level task or prompt to another terminal's LLM across the mesh:
```json
{
  "to": "linux-workstation",
  "message": "Please review src/auth.ts and verify if token expiration is handled."
}
```
*Delivery is batched (50ms window) and injected directly into the recipient's reasoning cycle.*

### 4. `link_list`
Inspect all connected terminals, their hostnames, projects, CPU/agent states (`idle`, `thinking`, `compacting`, `tool:<name>`), context window token usage (`45K/200K (22%)`), room, and network mode.

### 5. `link_status`
Structured mesh state for the agent itself, so it never has to scrape the human status card:
```json
{
  "state": "authenticated",
  "usable": true,
  "room": { "roomId": "r-8f31…", "label": "team-swarm", "endpoint": "100.82.12.4:9900" },
  "role": "hub",
  "agentInstanceId": "1f2c…",
  "terminalName": "macbook-pro",
  "peers": [{ "name": "linux-workstation", "principalId": "ed25519-sha256:40:E0:…", "agentInstanceId": "9ab4…", "workspace": "backend" }],
  "activeGrants": 0
}
```
`usable` is the one field to branch on: it is false whenever this terminal is not authenticated, so an agent
cannot mistake "socket open" for "allowed to talk".

### 6. `link_compact`
Request that a target terminal compact its context window before dispatching a large task to it.

### 7. `link_discover`
Scan the active network for reachable hubs. Every result is labelled **unverified**: discovery returns
candidates, and trust is only established by pairing.

---

## Using omp-link from Claude Code or Codex CLI (MCP)

`omp-link-mcp` is an MCP stdio server: hand-rolled JSON-RPC 2.0, **no new dependency**, and it joins a room as an ordinary mesh client — same device certificate, same pairing, same capability gating. It never hosts, never creates or joins a room on its own, and never enables remote exec.

**Claude Code** ([docs](https://code.claude.com/docs/en/mcp)):

```bash
claude mcp add --transport stdio omp-link -- omp-link-mcp
```

Add `--scope project` to write a shared `.mcp.json`, or point it at a checkout with `-- node /absolute/path/to/omp-link/bin/omp-link-mcp.mjs`. The `--` is mandatory; do not add a `type` field to `.mcp.json`. Verify with `claude mcp get omp-link` or `/mcp`.

**Codex CLI** ([docs](https://developers.openai.com/codex/mcp)):

```bash
codex mcp add omp-link -- omp-link-mcp
```

or in `~/.codex/config.toml`, under `[mcp_servers.omp-link]` with `command = "omp-link-mcp"` and `args = []`. Verify with `codex mcp list` or `/mcp`.

Tools: `link_status`, `link_send`, `link_list`, `link_discover`, `link_exec`, `link_send_file`. `link_compact` is excluded because MCP has no compaction primitive to drive, and a tool that reports success while doing nothing is worse than an absent one. Creating and joining rooms stays a human decision (`omp-link create <name>` / `omp-link join <ip:port>`); with no room configured, `tools/list` still works and every call answers with the command that fixes it. Full wiring, gotchas and troubleshooting: [docs/mcp.md](docs/mcp.md).

---

## Understanding Agent Speed & Latency

### Direct Tool RPC vs. LLM Agent Turns

| Feature | Direct Tool RPC (`link_exec`) | Agent Turn (`link_send`) |
|---|---|---|
| **Latency** | **10–25 milliseconds** | **10–30 seconds** |
| **Token Cost** | **Zero tokens** | **30,000–80,000 tokens** (full context round-trip) |
| **LLM Woken Up?** | **No** (executes on host OS) | **Yes** (triggers reasoning & generation) |
| **Best Used For** | Running tests, building code, checking git diffs, reading config files | Architecture planning, code generation, debugging, refactoring |

### Why does agent-to-agent messaging (`link_send`) take 15–25 seconds?
When you send a message with `link_send` and wait for a reply, the turn takes 15–25 seconds because of **LLM inference**, not the network:

1. **Network Transport (< 5ms)**: The WebSocket message over Tailscale or LAN takes less than 5 milliseconds.
2. **Inbox Flush (50ms)**: The incoming message is batched and injected into OMP within 50ms.
3. **LLM Thinking & Generation (5–15 seconds per turn)**:
   - When the receiving agent receives the message, it loads its full conversation history (often 30,000–80,000 tokens).
   - If using a reasoning model (e.g. Claude 3.7 Sonnet Thinking, o3-mini), the model spends 5–15 seconds generating hidden thinking tokens.
   - The model streams its response and executes any needed tool calls.
4. **Round-Trip Math**:
   - Agent A sends task $\rightarrow$ 5ms network $\rightarrow$ Agent B thinks (10s) $\rightarrow$ Agent B replies $\rightarrow$ 5ms network $\rightarrow$ Agent A reads reply and thinks (10s) $\rightarrow$ **Total elapsed: ~20–25 seconds**.

### Pro-Tips for Maximum Swarm Speed:
- **Use `link_exec` for Information Gathering**: If you just need to know `git status`, view a log, or run a build on a remote machine, invoke `link_exec`! It returns the terminal output in **15ms** without spending any LLM tokens.
- **Use Faster / Lighter Models for Workers**: For routine subtasks, use models like Claude 3.5 Haiku, Gemini 2.0 Flash, or GPT-4o-mini on worker terminals. Reserve heavier reasoning models for the orchestrator.
- **Prevent Endless Ping-Pong Loops**: When an agent completes a task, instruct it to conclude with `[FINAL ANSWER - No reply needed]` or state: *"Do not acknowledge; only reply when the task is complete."* Otherwise, agents will spend 15 seconds per turn thanking each other!
- **Watch Context Window Size**: Use `/link` or `link_list` to monitor context token usage. As context grows past 100k tokens, time-to-first-token (TTFT) increases. Run `/compact` when needed.

---

## Security & Cryptographic Architecture (Protocol v5)

`omp-link` v5 provides standard TLS 1.3 mutual certificate authentication, strict capability governance, and defense-in-depth path confinement:

1. **Persistent Device Identity & Principals (TLS 1.3 Self-Signed Certificates)**:
   - Each node generates a persistent self-signed device certificate and private key (`~/.omp/identity/device-cert.pem`, `device-key.pem`).
   - Device principals are derived exclusively from the canonical SHA-256 fingerprint of the certificate/SPKI: `ed25519-sha256:<full-256-bit-fingerprint>`.
   - Node names, hostnames, and device IDs are untrusted mutable metadata. Only the cryptographic principal is authoritative.
2. **Mutual TLS 1.3 Transport with SPKI Pinning (Authenticated Encrypted Transport, Hop-by-Hop)**:
   - All connections across LAN and Tailscale require TLS 1.3 mutual certificate exchange (`minVersion: "TLSv1.3"`).
   - Ephemeral key exchange in TLS 1.3 provides forward secrecy, directional traffic keys, and tamper protection.
   - The TLS handshake's `CertificateVerify` proves possession of the presented device private key.
   - Previously paired devices pin the remote certificate fingerprint. If a certificate changes, the connection is rejected immediately.
   - The topology is a star, not a peer-to-peer mesh: **the hub terminates TLS and reads and routes every message.** Protection is client-to-hub, not client-to-client — there is no E2EE between terminals (`SECURITY.md` §1). Host the hub only on a machine you trust with the traffic.
3. **Deterministic Connection Phase State Machine**:
   - Every connection progresses through strictly enforced phases: `tls-connected` $\rightarrow$ `awaiting-pairing` $\rightarrow$ `authenticated`.
   - Application messages received prior to pairing approval are rejected and close the socket. Handshake frames received after authentication are rejected.
   - Handshake timeouts (10s by default) and pairing request expiries (60s by default) prevent orphaned or hanging connections; both are `link.json` settings, and the close reason carries the configured value.
   - **Liveness, not hope.** Every authenticated connection is pinged on an interval; a peer silent for `heartbeatIntervalMs × heartbeatMissesBeforeDrop` (15s × 2 by default) is closed `4408`, audited `peer_liveness_timeout`, and torn down through the normal path — grants revoked, transfers cleaned, roster rebroadcast. A client that hears nothing from its hub for `clientHubSilenceTimeoutMs` (45s) goes disconnected; the asymmetry is deliberate, because a premature takeover is worse than a briefly stale roster. A terminal that reconnects evicts its own stale connection (`peer_connection_superseded`) instead of appearing twice. All four values are settings in `link.json`, not recompilation.
4. **Capability Authorization & Authoritative Origin Binding**:
   - Inbound actions are evaluated against fine-grained stored permissions: `observe`, `message`, `compact`, `inspect`, `fileInbox`, `execRequest`.
   - The hub derives the origin strictly from the authenticated TLS socket context, overwriting any claimed sender name or ID in the payload.
5. **Single-Use Device-Principal Keyed Execution Grants**:
   - Arbitrary remote command execution (`action: "exec"`) is disabled by default under Territorial Sovereignty policy.
   - Hosts can grant temporary execution elevation via `/link grant <device>`.
   - Grants are keyed by `(device principalId, agentInstanceId)` — never mutable terminal names — so two terminals on one machine no longer share a grant. They default to single-use (1 execution), auto-expire (10m), and are revoked immediately upon peer disconnection or mesh shutdown. `/link revoke <device>` drops the grants and unpairs the device in one step.
   - *Advisory Warning*: Mutation Guard acts as an accident-prevention warning layer and does not provide containerization sandbox boundaries. Treat elevated peers as having local-user access.
6. **Hardened File Transfer & Receiver Quarantine**:
   - Files are transferred in 64KB chunks directly into an external quarantine directory (`~/.omp/inbox/<workspace>/<receiver-generated-id>/`) using exclusive creation (`openSync` with `wx` flag).
   - Sender streams chunks with backpressure awareness without allocating the full file into memory.
   - Strict validation binds chunk indices (`chunkIndex === nextExpectedChunk`), sender, and recipient to the accepted offer with streaming SHA-256 integrity verification.
7. **Sanitized Public Discovery (`GET /status`)**:
   - Discovery status over HTTPS returns minimal public metadata with strict security headers (`Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'`, `X-Content-Type-Options: nosniff`).
   - It advertises an **opaque `roomId`**, not the human room label. A room is the pair `(roomId, hub principalId)`, so two machines sharing a name are not in the same room — and a discovered endpoint is an unverified candidate until pairing pins its SPKI.
   - Host paths, active peers, and internal configurations are never exposed. Public keys and fingerprints are never accepted as bearer authorization. Detailed status is available exclusively over authenticated WebSocket RPC.
8. **Short Authentication String (SAS) & Single-Use Pairing Invites**:
   - First-time pairing derives a 4-word Short Authentication String on **both** sides from the TLS exporter; it is never transmitted. Compare it out of band, then `/link accept <id> <code>` — the code is **required** and pairing fails closed without it.
   - Headless workflows can generate single-use, 5-minute pairing invitations via `/link invite`.

---

## Quick Start (60 Seconds)

### Step 1: Clone repo on each machine
```bash
git clone https://github.com/jsbonsai/omp-link.git
cd omp-link
```

### Step 2: Run turnkey setup
On **every machine**, run:
```bash
./setup.sh
```
*(Installs dependencies, symlinks `omp-link` into `~/.local/bin/`, registers the extension with `~/.omp/agent/extensions/`, and removes legacy `pi-link` registrations. It never kills processes and never edits your `link.json` — port and state cleanup is `omp-link cleanup`, which previews first.)*

### Step 3: Launch OMP Normally
```bash
omp
```
- On startup, `omp-link` probes loopback, LAN and your Tailnet for a reachable hub.
- A discovered hub is a **candidate**: joining pins its SPKI on first pairing, and only a paired, authenticated peer is shown as active.
- With nothing reachable it hosts a room itself. Type `/link` for the status card.

---

## Maintenance & CLI Commands

Outside OMP, these CLI commands are available:

| Command | Description |
|---|---|
| `omp-link` | Launch OMP/Pi with the extension loaded; all extra arguments are forwarded untouched. |
| `omp-link status` | Terminal view: state dir, cached hub, and whether a local hub answers `/status`. |
| `omp-link scan` | Probe loopback, LAN broadcast and Tailnet over HTTPS. Results are printed as **unverified**. |
| `omp-link doctor` | Measured diagnostics: node version, identity file modes, install symlinks, port ownership. |
| `omp-link shared` | Sharing receipt rendered from `audit.log`. |
| `omp-link cleanup [--apply]` | Preview link-owned leftovers; changes nothing without `--apply`. A listening hub is only stopped when ownership is proven over `/status` **and** you confirm. |
| `omp-link update` | `git pull --rebase --autostash`, reinstall dependencies, re-run `setup.sh`. |
| `omp-link help [command]` | The single source of command help, shared with `/link help`. |
| `omp-link --version` | Print installed version (read from `package.json`). |
| `omp-link-mcp` | MCP stdio server for Claude Code, Codex CLI and other MCP hosts. Launched by the host, not by hand; `--name` sets the mesh display name, `--omp-dir` the state root ([docs/mcp.md](docs/mcp.md)). |

Global flags: `--json` for machine-readable output, `--no-input` to refuse instead of prompting, `--yes` to pre-approve a confirmation.

---

## Origin & Credits

`omp-link` is an intelligent network fork of [Alberto Vivar's `pi-link`](https://github.com/alvivar/pi-link).  
Alberto designed the foundational localhost protocol (WebSocket transport, inbox delivery, context window metrics, compaction gating). `omp-link` extends this architecture with Tailscale/LAN hub-hosted networking, mutual TLS 1.3 device authentication with SPKI pinning, capability-scoped RPC, and a room-centric `/link` command surface.
