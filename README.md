# omp-link

> **Multi-Machine & Multi-Codebase Inter-Terminal Coordination Mesh for [Oh-My-Pi (OMP)](https://github.com/can1357/oh-my-pi) and [Pi](https://github.com/badlogic/pi-mono).**  
> Turn multiple terminal windows across your Mac, Linux workstation, Raspberry Pi, or cloud VMs into a unified collaborative swarm over **Tailscale** and **LAN**.

---

## What It Looks Like When It Works

When `omp-link` is running, type `/link` inside OMP to see your live mesh dashboard:

```text
⚡ OMP-LINK: ACTIVE (Host Hub)
  Session  : "team-swarm" [TAILSCALE]
  Endpoint : 100.82.12.4:9900
  Terminal : macbook-pro
  Nodes (3): macbook-pro (this), linux-workstation, cloud-vm

Quick Commands:
  /link on | off          Turn link mesh ON or OFF
  /link scan              Scan LAN & Tailscale for active sessions
  /link join [ip:port]    Connect to an active session
  /link invite            Create a one-time pairing invite code
  /link doctor            Run system and TLS security diagnostic
  /link help              Show full command reference
```

### Live Peer Joining & Message Stream
When another terminal connects or sends a message, OMP displays live status notifications:

```text
⚡ Connected to session "team-swarm" [Tailscale: 100.82.12.4:9900]
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
| **Security Architecture** | Central server can inspect or log unencrypted traffic | **Mutual TLS 1.3** with client & server SPKI pinning |
| **Reachability** | Manual port-forwarding or relay join tokens | **Autonomous discovery** across Tailnet & LAN UDP |

### The Peer-Hosted Model
Instead of requiring external servers, `omp-link` uses an autonomous peer-host model:
1. **Zero-Config Discovery**: When you launch OMP or type `/link on`, it automatically checks if an active session already exists on `localhost`, your Tailnet, or local LAN. If found, it joins immediately as a client node. If no session exists, it anchors the session as the Host Hub.
2. **Local Terminal Multiplexing**: If you open multiple terminal windows on the same laptop, subsequent terminals automatically detect the local host on port 9900 and join as clients without port collision errors.
3. **Link in a Single Command**: You don't manage IP tables or firewalls. Start your terminals and run `/link on` or `/link scan` to coordinate your machines into a unified swarm.

---

## Consolidated Slash Command Interface

All coordination happens directly inside OMP through the unified `/link` command:

| Command | Usage | Description |
|---|---|---|
| **`/link`** | `/link`<br>`/link status [--verbose]` | **Dashboard**: Live status card showing session ID, network mode, endpoint, and online peers. Use `--verbose` for raw SPKI principals. |
| **`/link on` / `/link off`** | `/link on`<br>`/link off` | **Deterministic Mesh Control**: Enable or cleanly disable the mesh, stopping background listeners and retries. |
| **`/link scan`** | `/link scan` | **Network Scan**: Actively scan LAN and Tailscale for active link sessions with 1-click join instructions. |
| **`/link join`** | `/link join`<br>`/link join <ip:port> [invite]` | **Connect**: With no arguments, auto-discovers and joins active sessions! Or specify an explicit endpoint. *(Alias: `/link-join`)* |
| **`/link start`** | `/link start [session-id]` | **Host**: Anchor or switch to hosting a session under a custom project or session name. |
| **`/link invite`** | `/link invite` | **One-Time Pairing**: Generate a single-use 5-minute cryptographic invite code for pairing a new device. |
| **`/link accept` / `/link deny`** | `/link accept <id> [code]`<br>`/link deny <id>` | **Pairing Governance**: Approve or reject pending pairing requests with channel-bound SAS verification. |
| **`/link devices`** | `/link devices`<br>`/link devices revoke <id>` | **Trusted Devices**: List paired devices and SPKI fingerprints or revoke a device's trust. |
| **`/link doctor`** | `/link doctor` | **System & Security Diagnostics**: Comprehensive check of Ed25519 identity, TLS certificate, confinement, and ports. *(Alias: `/link-doctor`)* |
| **`/link grant`** | `/link grant <peer> exec` | **Execution Elevation**: Grant temporary single-use shell execution elevation to a trusted peer (requires `--unsafe-remote-exec`). |
| **`/link revoke-grant`** | `/link revoke-grant [peer]` | **Revoke Elevation**: Immediately cancel active execution elevation for a peer. |
| **`/link help`** | `/link help` | **Command Reference**: Print comprehensive summary of all `/link` subcommands. |

> [!NOTE]
> To preserve a clean command palette, all operations are consolidated under `/link <subcommand>`, while preserving only 3 essential convenience aliases: `/link-join`, `/link-leave`, and `/link-doctor`.

---

## Agent Tools (Autonomous Swarm Operation)

Agents running inside OMP have access to 7 built-in coordination and execution tools:

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
- `exec`: Blocked by default under Territorial Sovereignty. When disabled, common read commands like `git status` or `git diff` automatically route to safe structured operations. Hosts can unlock arbitrary execution via `/link-exec-mode allow`.

### 2. `link_send_file` (Hardened Out-of-Band File Transfer)
Stream files directly between machines across LAN or Tailscale with chunked delivery, SHA-256 integrity verification, and automatic quarantine into `.omp/inbox/<transferId>/<safeFilename>`:
```json
{
  "to": "linux-workstation",
  "sourcePath": "./dist/app.bundle.js"
}
```
*Files are transmitted in 64KB chunks over the E2EE wire, verified against a 50MB ceiling, and reassembled with SHA-256 verification. Transferred files are strictly isolated to dedicated transfer directories to guarantee they never overwrite existing project code.*

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
Inspect all connected terminals, their hostnames, projects, CPU/agent states (`idle`, `thinking`, `compacting`, `tool:<name>`), context window token usage (`45K/200K (22%)`), session ID, and network mode.

### 5. `link_connect`
Autonomous self-healing tool. If an agent detects a temporary disconnection, it calls:
```json
{ "action": "join" }
```
This automatically scans the active network, discovers the peer session, and reconnects without human intervention.

### 6. `link_compact`
Request that a target terminal compact its context window before dispatching a large task to it.

### 7. `link_discover`
Scan the active network mode for other sessions and online terminals.

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
2. **Mutual TLS 1.3 Transport with SPKI Pinning (Authenticated Encrypted Transport)**:
   - All connections across LAN and Tailscale require TLS 1.3 mutual certificate exchange (`minVersion: "TLSv1.3"`).
   - Ephemeral key exchange in TLS 1.3 provides forward secrecy, directional traffic keys, and tamper protection.
   - The TLS handshake's `CertificateVerify` proves possession of the presented device private key.
   - Previously paired devices pin the remote certificate fingerprint. If a certificate changes, the connection is rejected immediately.
3. **Deterministic Connection Phase State Machine**:
   - Every connection progresses through strictly enforced phases: `tls-connected` $\rightarrow$ `awaiting-pairing` $\rightarrow$ `authenticated`.
   - Application messages received prior to pairing approval are rejected and close the socket. Handshake frames received after authentication are rejected.
   - Handshake timeouts (10s) and pairing request expiries (60s) prevent orphaned or hanging connections.
4. **Capability Authorization & Authoritative Origin Binding**:
   - Inbound actions are evaluated against fine-grained stored permissions: `observe`, `message`, `compact`, `inspect`, `fileInbox`, `execRequest`.
   - The hub derives the origin strictly from the authenticated TLS socket context, overwriting any claimed sender name or ID in the payload.
5. **Single-Use Device-Principal Keyed Execution Grants**:
   - Arbitrary remote command execution (`action: "exec"`) is disabled by default under Territorial Sovereignty policy.
   - Hosts can grant temporary execution elevation via `/link grant <device> exec`.
   - Grants are keyed by the peer's cryptographic `principalId` (never mutable terminal names), default to single-use (1 execution), auto-expire (10m), and are revoked immediately upon peer disconnection or mesh shutdown.
   - *Advisory Warning*: Mutation Guard acts as an accident-prevention warning layer and does not provide containerization sandbox boundaries. Treat elevated peers as having local-user access.
6. **Hardened File Transfer & Receiver Quarantine**:
   - Files are transferred in 64KB chunks directly into an external quarantine directory (`~/.omp/inbox/<workspace>/<receiver-generated-id>/`) using exclusive creation (`openSync` with `wx` flag).
   - Sender streams chunks with backpressure awareness without allocating the full file into memory.
   - Strict validation binds chunk indices (`chunkIndex === nextExpectedChunk`), sender, and recipient to the accepted offer with streaming SHA-256 integrity verification.
7. **Sanitized Public Discovery (`GET /status`)**:
   - Discovery status over HTTPS returns minimal public metadata with strict security headers (`Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'`, `X-Content-Type-Options: nosniff`).
   - Host paths, active peers, and internal configurations are never exposed over HTTP. Public keys and fingerprints are never accepted as bearer authorization. Detailed status is available exclusively over authenticated WebSocket RPC.
8. **Short Authentication String (SAS) & Single-Use Pairing Invites**:
   - First-time pairing derives a Short Authentication String (SAS) from both certificate DERs and nonces (`/link accept <id> [code]`).
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
*(Installs dependencies, symlinks `omp-link` into `~/.local/bin/`, registers the extension with `~/.omp/agent/extensions/`, and purges any legacy configs or ports).*

### Step 3: Launch OMP Normally
```bash
omp
```
- On startup, `omp-link` automatically detects active sessions on your network.
- If a session already exists for your project, it joins automatically!
- Otherwise, it starts hosting. Type `/link` to view the session card.

---

## Maintenance & CLI Commands

Outside OMP, these CLI commands are available:

| Command | Description |
|---|---|
| `omp-link clean` | Release ports 9900/9901 and reset stale cached configs. |
| `omp-link update` | Pull latest code from GitHub, refresh dependencies, and update extensions. |
| `omp-link find` | Probe the network for active sessions from the command line. |
| `omp-link --version` | Print installed version. |

---

## Origin & Credits

`omp-link` is an intelligent network fork of [Alberto Vivar's `pi-link`](https://github.com/alvivar/pi-link).  
Alberto designed the foundational localhost protocol (WebSocket transport, inbox delivery, context window metrics, compaction gating). `omp-link` extends this architecture with distributed Tailscale/LAN mesh networking, cryptographic WireGuard authentication, session-centric slash commands, and autonomous agent self-healing.
