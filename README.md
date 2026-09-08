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

## Core Slash Commands to Memorize

All coordination happens directly inside OMP via slash commands:

| Command | Most Common Usage | Description |
|---|---|---|
| **`/link`** | `/link` | **The Dashboard**: Instant status card showing session ID, network mode, PIN, endpoint, encryption, and online peers. |
| **`/link off`** | `/link off` | **Deterministic Silence**: Instantly disables the link mesh, terminates connections, and guarantees **zero** reconnect spam or disconnected warnings. |
| **`/link on`** | `/link on` | **Re-enable**: Re-enables the link mesh and re-connects/re-hosts the project session. |
| **`/link-join`** | `/link-join`<br>`/link-join [id] [pin]` | **Connect**: With no arguments, scans your network and **auto-joins** the active session! Or specify session ID / IP and PIN. |
| **`/link-start`** | `/link-start [id] [pin]` | **Host**: Start or switch to hosting a session with a custom ID or PIN. |
| **`/link-accept`** | `/link-accept [id]` | **Approve Pairing**: Approve a new device's join request and issue a permanent token. |
| **`/link-deny`** | `/link-deny [id]` | **Reject Pairing**: Reject a new device's join request. |
| **`/link-requests`** | `/link-requests` | **Pairing Queue**: View all pending join requests awaiting host approval. |
| **`/link-devices`** | `/link-devices`<br>`/link-devices revoke <id>` | **Device Tokens**: List paired devices or revoke a device's permanent token. |
| **`/link-exec-mode`**| `/link-exec-mode [allow\|block]`| **Exec Mode**: Inspect or toggle remote arbitrary shell command execution. |
| **`/link-mutation`** | `/link-mutation`<br>`/link-mutation [on\|off\|log]` | **Mutation Guard**: Inspect, toggle, or view the real-time blocked command audit log. |
| **`/link-leave`** | `/link-leave` | **Disconnect**: Cleanly leave the session and release the network port. |

### Secondary Slash Commands & Environment Flags
- `/link-network <tailscale | lan>`: Switch between Tailscale (WireGuard auto-auth) and LAN mode.
- `/link-discover`: Scan the active network and list all available sessions.
- `/link-pin [pin]`: Inspect or set a new 4-digit PIN for LAN mode.
- `/link-name [name]`: Change your terminal's display name on the mesh.
- `OMP_LINK_OFF=1` or `omp --no-link`: Launch OMP with link completely disabled from startup.
- `OMP_LINK_EXEC_MODE=allow`: Allow remote arbitrary shell execution by default.
- `OMP_LINK_ALLOW_MUTATION=1`: Disable the Mutation Guard to allow unrestricted remote shell execution.

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

## Security & End-to-End Encryption (E2EE) Model

`omp-link` incorporates military-grade, zero-dependency cryptographic security across both local LAN and Tailscale networks:

1. **Native End-to-End Encryption (AES-256-GCM)**:
   - Every payload on the wire (messages, tool RPC commands, outputs, file chunks) is encrypted using native Node.js hardware-accelerated `aes-256-gcm`.
   - Keys are derived via **PBKDF2-HMAC-SHA256** (50,000 rounds) using a cryptographically isolated session salt (`omp-link-salt-<sessionId>`).
   - Encryption takes less than 0.05ms per message and eliminates plaintext eavesdropping on untrusted Wi-Fi or public networks.
2. **Cryptographic Tamper Resistance (GCM Auth Tag)**:
   - Each frame carries a 128-bit authentication tag and a fresh 12-byte initialization vector (IV).
   - Any packet modification or replay attempt causes an immediate GCM authentication failure and is dropped silently before parsing.
3. **Dual-Tier Network Isolation**:
   - **Tailscale Mode**: Strict binding to `100.64.0.0/10` with WireGuard kernel-level identity verification. PINs are optional.
   - **LAN Mode**: Subnet binding with mandatory 4-digit PIN authentication. Non-matching PINs are rejected with `4001: Invalid session PIN`.
4. **Always-Prompt First-Time Pairing ("Request Mode")**:
   - Any new or unpaired device connecting across LAN or Tailscale is placed into a host-controlled pairing queue.
   - The host terminal alerts in real time (`🔔 [Link Request #1] "<name>" requested to join...`) and requires human approval via `/link-accept 1` (or `/link-deny 1`).
   - Approved devices receive a cryptographically unique permanent device token saved in `~/.omp/paired-devices.json` and client's `~/.omp/client-tokens.json`, allowing instant automatic reconnection for paired nodes without repeated prompts.
5. **Structured Inspection Operations (No-Shell `execFile`)**:
   - Direct Tool RPC eliminates shell execution (`exec`) in favor of fixed, deterministic operations: `git_status`, `git_diff` (`--no-ext-diff`, `--no-textconv`), `git_log` (bounded 1–100 commits), `search_text` (`git grep`), `read_file`, and `list_dir`.
   - Operations execute directly via `execFile`, eliminating shell metacharacter injections, parameter expansion, and pipe tampering.
6. **Canonical Path Confinement & Traversal Defense**:
   - `resolveConfinedPath` enforces canonical `fs.realpath` verification against the workspace root.
   - Rejects directory traversal escapes (`../`), symlink bypasses, null bytes, and sensitive files (`.env*`, `.git/*`, `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, credentials, secrets).
7. **Hardened 50MB Quarantine Inboxes**:
   - Incoming file transfers save strictly into `.omp/inbox/<transferId>/<safeFilename>`, ensuring peer files can never overwrite or collide with project code.
   - 50MB transfer ceiling prevents memory exhaustion or buffer overflow.
8. **Sanitized Public Discovery (`GET /status`)**:
   - Unauthenticated network probes receive minimal safe telemetry (`{ service: "omp-link", version: "3.1.0", active: true, authRequired: true }`).
   - Completely conceals host file paths, working directories, active peers, and session PINs unless authenticated with a paired token or PIN.
9. **Deterministic Link ON/OFF & Circuit Breaker**:
   - Run `/link off` to completely detach from the mesh, terminate listeners, and suppress all background reconnect loops.
   - 3-strike circuit breaker: after 3 consecutive failed reconnection attempts, OMP ceases dialing and stays silent until explicit user activation (`/link on` or `/link-join`).
10. **Territorial Sovereignty & The Mutation Guard**:
   - **The Problem**: In multi-machine swarms, an eager agent on Machine A that spots a bug on Machine B might attempt to directly edit, overwrite, or commit code on Machine B, clobbering Machine B's working tree and desynchronizing its LLM context.
   - **The Principle**: Every agent is the sole authoritative writer of its own local workspace.
   - **Deterministic Blocking**: Arbitrary remote command execution (`action: "exec"`) is disabled by default. Common read-only commands like `git status` or `git diff` automatically route to safe structured inspection operations.
   - **The Guard**: If execution is unlocked via `/link-exec-mode allow`, the **Mutation Guard** continues enforcing read-only sovereignty by blocking mutating commands (`rm`, `sed -i`, `git commit`, `chmod`, `>`/`>>` redirects, and package updates).
   - **Monitoring & Audit Log**: Blocked attempts are alerted on-screen in real time (`🛡️ [Mutation Guard] BLOCKED...`) and recorded in a live audit log viewable via `/link-mutation log`.

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
