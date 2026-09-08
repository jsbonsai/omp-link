# omp-link

> **Multi-Machine & Multi-Codebase Inter-Terminal Coordination Mesh for [Oh-My-Pi (OMP)](https://github.com/can1357/oh-my-pi) and [Pi](https://github.com/badlogic/pi-mono).**  
> Turn multiple terminal windows across your Mac, Linux workstation, Raspberry Pi, or cloud VMs into a unified collaborative swarm over **Tailscale** and **LAN**.

---

## What It Looks Like When It Works

When `omp-link` is running, type `/link` inside OMP to see your live mesh dashboard:

```text
⚡ OMP LINK: ACTIVE (E2EE: AES-256-GCM)
────────────────────────────────────────────────────────────
  Session ID : team-swarm
  Network    : LAN (PIN: 4821)  [or TAILSCALE: auto-verified via WireGuard]
  Endpoint   : 192.168.1.50:9900
  Encryption : Hardware-accelerated AES-256-GCM (Zero plaintext wire leakage)
  Role       : Host (macbook-pro)
────────────────────────────────────────────────────────────
  Online Peers (3):
    • macbook-pro       (you) [host: mac-1   · project: web-app] (idle)
    • linux-workstation       [host: linux-2 · project: backend] (idle)
    • cloud-vm                [host: vm-3    · project: ai-models] (idle)
────────────────────────────────────────────────────────────
  Direct RPC  : < 25ms execution round-trip (link_exec)
  File Xfer   : Out-of-band streaming + ephemeral HTTP (:9900/transfer/...)
────────────────────────────────────────────────────────────
  Quick join from another machine:
    /link-join team-swarm 4821
    (or /link-join 192.168.1.50:9900 4821)
```

### Live Peer Joining & Message Stream
When another terminal connects or sends a message, OMP displays live status notifications:

```text
⚡ Connected to session "team-swarm" on LAN (2 online) [E2EE Active]
"linux-workstation" joined the link

[Link: 1 message(s) received]

From "linux-workstation on linux-2 (project: backend)":
I have refactored auth.ts and run the test suite. All 14 tests pass.
```

---

## Consolidated Slash Command Interface

All coordination happens directly inside OMP through the unified `/link` command:

| Command | Usage | Description |
|---|---|---|
| **`/link`** | `/link` | **Dashboard**: Live status card showing session ID, network mode, endpoint, peers, and cryptographic fingerprints. |
| **`/link on` / `/link off`** | `/link on`<br>`/link off` | **Deterministic Mesh Control**: Enable or cleanly disable the mesh, stopping all background sockets and retries. |
| **`/link join`** | `/link join`<br>`/link join [id\|ip] [pin]` | **Connect**: With no arguments, auto-discovers active sessions! Or specify session ID / IP and PIN. *(Alias: `/link-join`)* |
| **`/link leave`** | `/link leave` | **Disconnect**: Cleanly leave the session and release network ports. *(Alias: `/link-leave`)* |
| **`/link start`** | `/link start [id] [pin]` | **Host**: Start or switch to hosting a session with a custom ID or PIN. |
| **`/link accept` / `/link deny`** | `/link accept [id]`<br>`/link deny [id]` | **Pairing Governance**: Approve or reject pending device join requests with Ed25519 key verification. |
| **`/link requests`** | `/link requests` | **Pairing Queue**: View all pending device join requests awaiting host approval. |
| **`/link devices`** | `/link devices`<br>`/link devices revoke <id>` | **Trusted Devices**: List paired devices and fingerprints or revoke a device's trust. |
| **`/link grant`** | `/link grant <peer> [min]` | **Territorial Sovereignty Elevation**: Grant temporary (1–60 min) shell execution elevation to a trusted peer. |
| **`/link revoke-grant`** | `/link revoke-grant <peer>` | **Revoke Elevation**: Immediately cancel active execution elevation for a peer. |
| **`/link mutation`** | `/link mutation`<br>`/link mutation [on\|off\|log]` | **Mutation Guard**: Inspect, toggle, or view the real-time blocked mutation audit log. |
| **`/link network`** | `/link network [tailscale\|lan]` | **Interface Selection**: Switch between Tailscale and LAN mode. |
| **`/link doctor`** | `/link doctor` | **System & Security Diagnostics**: Comprehensive check of Ed25519 identity, TLS certificate, confinement, and ports. *(Alias: `/link-doctor`)* |
| **`/link pin`** | `/link pin [pin]` | **LAN Security**: View or set session PIN for LAN connections. |
| **`/link name`** | `/link name [name]` | **Mesh Identity**: Change terminal display name across the swarm. |
| **`/link discover`** | `/link discover` | **Network Scan**: Scan active network interfaces and list all discovered sessions. |
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

## Security & Cryptographic Architecture

`omp-link` provides zero-dependency, defense-in-depth cryptographic security across both local LAN and Tailscale networks:

1. **Cryptographic Device Identities & Pairing (Ed25519 TOFU)**:
   - Each terminal generates an Ed25519 identity keypair (`~/.omp/identity.json`) with an authenticable SHA-256 fingerprint.
   - Private keys and bearer credentials never cross the wire. Authentication uses cryptographic challenge-response nonces signed with Ed25519.
   - When a new device connects, the host displays its public key fingerprint for verification (`🔔 [Link Request #1] "<name>" (FP: 7B:19:52:AF...)`). Host approves via `/link accept 1`.
2. **Forward-Secret Wire Encryption (Ephemeral X25519 + HKDF-SHA256)**:
   - Prior to message exchange, connecting nodes perform an ephemeral **X25519** Diffie-Hellman key agreement.
   - A forward-secret 256-bit symmetric session key is derived using **HKDF-SHA256**. Compromise of long-term identity keys or past sessions cannot decrypt future or historical traffic.
   - Enforces strict plaintext frame rejection after handshake: any unencrypted frame received after initialization is dropped immediately without fallback.
3. **Authenticated Additional Data (AAD) & Replay Defense**:
   - Every wire frame binds protocol version (`v: 4`), monotonic sequence counter (`seq`), unique message ID (`mid`), sender identity (`from`), and timestamp (`ts`) into the AES-256-GCM Authenticated Additional Data buffer.
   - Any tampering with header fields, frame ordering, or payload results in immediate GCM authentication tag rejection.
   - A bounded replay cache (`seenMessageIds`) deterministically drops duplicated or delayed packets.
4. **Self-Signed ECDSA TLS on LAN (Certificate Pinning)**:
   - In LAN mode, `omp-link` generates a self-signed ECDSA (P-256) TLS certificate (`~/.omp/tls/`), serving over `https://` and `wss://`.
   - Protects local network transport against passive network observers, with peer certificate fingerprints verified during pairing.
5. **Passive & Sanitized Subprocess Execution (`safeGitExecFile`)**:
   - Structured git operations (`git_status`, `git_diff`, `git_log`, `search_text`) execute via `execFile` (never a shell) using sanitized environments.
   - Prepend passive flags: `-c core.fsmonitor=false -c core.pager=cat -c pager.status=false -c pager.diff=false -c pager.log=false -c diff.external=`.
   - Strips dangerous environment variables (`LD_PRELOAD`, `NODE_OPTIONS`, `GIT_DIR`, `GIT_WORK_TREE`, `GIT_CONFIG`, etc.) and sets `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_TERMINAL_PROMPT=0`.
6. **Canonical Path Confinement (`resolveConfinedPath`)**:
   - Enforces canonical `fs.realpath` verification against the workspace root for both `params.cwd` and file targets.
   - Rejects directory traversal escapes (`../`), symlink bypasses, null bytes, and sensitive files (`.env*`, `.git/*`, `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, credentials, secrets).
7. **Hardened Streaming File Inbox & DoS Protection**:
   - `transferId` is strictly validated (`^[a-zA-Z0-9_-]{1,64}$`).
   - Transfers stream in bounded 64KB chunks directly to disk (`.tmp-<id>.part` with mode `0600`), bounding RAM consumption to 64KB regardless of transfer size.
   - Strict verification of `totalChunks`, byte limits, and SHA-256 integrity before atomically renaming to destination.
8. **Sanitized Public Discovery (`GET /status`)**:
   - Unauthenticated discovery requests receive minimal safe telemetry (`{ service: "omp-link", protocolVersion: 4, instanceId, pairingRequired: true, fingerprint, tls }`).
   - Fully conceals host paths, working directories, active peers, and tokens. Query-string credential passing is strictly rejected. `Cache-Control: no-store` prevents intermediate caching.
9. **Territorial Sovereignty & Ephemeral Execution Elevation**:
   - **The Principle**: Every agent is the sole authoritative writer of its own local workspace.
   - **Deterministic Blocking**: Arbitrary remote command execution (`action: "exec"`) is disabled by default. Read-only commands like `git status` or `git diff` transparently route to safe structured inspection operations.
   - **Temporary Elevation**: When a remote peer genuinely needs to execute commands, the host can grant temporary elevation via `/link grant <peer> [minutes]`. Grants automatically expire and are logged in `~/.omp/audit.log`.
   - **Mutation Guard**: Protects working trees by blocking destructive commands (`rm`, `sed -i`, `git commit`, `chmod`, `>`/`>>` redirects, and package installations).
10. **Deterministic Silence & Diagnostic Doctor**:
   - Run `/link off` to completely detach from the mesh, terminate listeners, and suppress background reconnect loops.
   - Run `/link doctor` (or `/link-doctor`) to verify cryptographic key generation, TLS certificates, workspace confinement, and network interfaces.

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
