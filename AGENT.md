# AGENT.md — AI Agent Setup & Coordination Guide

> **For AI Assistants (OMP, Pi, Antigravity, Claude Code, Cursor, Codex, etc.)**
> If your human user pointed you to this folder and said: *"Get this set up to use with OMP"*, follow this guide.

---

## 1. What This Project Is

`omp-link` (also accessible as `pi-link`) is a multi-machine, multi-codebase inter-terminal communication mesh for **Oh-My-Pi (OMP)** and **Pi**. It allows multiple agent terminals running on different machines (Mac, Linux, Raspberry Pi, Windows) across a **Tailscale** tailnet or local LAN to:
- Discover each other automatically with zero manual configuration.
- Send messages and delegate tasks to each other using `link_send`.
- Coordinate work across different repositories and directories.
- Share status, active tool usage, and context window metrics with `link_list` and `omp-link --status`.
- Request and gate context compactions with `link_compact`.

It is a fork of Alberto Vivar's `pi-link`, extended with intelligent network mesh routing, Tailnet/LAN auto-discovery, and turnkey CLI tools.

---

## 2. Automated Setup (Run This First)

Execute the turnkey setup script from the root of this repository:

```bash
./setup.sh
```

### What `./setup.sh` does automatically:
1. Cleans up legacy versions, removes old `pi-link` extension links, resets stale hub addresses from config, and terminates any orphan processes on port 9900/9901.
2. Installs npm dependencies (`ws`, etc.).
3. Makes `bin/omp-link.mjs` and `bin/pi-link.mjs` executable.
4. Symlinks `omp-link` and `pi-link` into `~/.local/bin/` (and ensures it is in `PATH`).
5. Registers the extension by symlinking the repository into:
   - `~/.omp/agent/extensions/omp-link`
   - `~/.pi/agent/extensions/omp-link`
   *(This ensures OMP loads omp-link automatically on every startup without needing `--extension` flags).*
6. Detects the machine's Tailscale IP (`100.x.y.z`) and LAN IP.

---

## 3. Launching & Linking

There is **no external hub vs worker launcher required**. You launch OMP normally:

```bash
omp
# or:
omp-link
```

OMP automatically loads `omp-link` on startup from `~/.omp/agent/extensions/omp-link`.
- By default, it creates an active session using the project/directory name (e.g. `ag-exp`).
- If another session with this name is already active on your network, it joins automatically.
- Otherwise, it begins hosting the session on port 9900.

---

## 4. In-Session Slash Commands

All session control is driven directly inside OMP via the consolidated `/link` command:

| Command | Usage | Description |
|---|---|---|
| `/link` | `/link` | Displays the link status card: session ID, network mode, E2EE status, endpoints, and online peers. |
| `/link on` / `/link off` | `/link on`<br>`/link off` | Instantly activates or deactivates the mesh, stopping all background sockets, discovery, and reconnect loops. |
| `/link join` | `/link join`<br>`/link join [id\|ip] [pin]` | Connects to an active session. If no target is given, auto-discovers active sessions on your network. *(Alias: `/link-join`)* |
| `/link leave` | `/link leave` | Cleanly leaves the session and releases the port. *(Alias: `/link-leave`)* |
| `/link start` | `/link start [id] [pin]` | Starts or switches to hosting a session with the given ID and PIN. |
| `/link accept` / `/link deny` | `/link accept [id]`<br>`/link deny [id]` | Approves or rejects a pending device join request with Ed25519 fingerprint verification. |
| `/link requests` | `/link requests` | Displays all pending join requests awaiting host approval. |
| `/link devices` | `/link devices`<br>`/link devices revoke <id>` | Lists paired devices or revokes a device's trust. |
| `/link grant` | `/link grant <peer> [min]` | Grants temporary (1–60 min) shell execution elevation to a trusted peer under Territorial Sovereignty. |
| `/link revoke-grant` | `/link revoke-grant <peer>` | Immediately cancels active execution elevation for a peer. |
| `/link mutation` | `/link mutation [on\|off\|log]` | Inspects, toggles, or displays the audit log for the Mutation Guard. |
| `/link network` | `/link network [tailscale\|lan]` | Switches strictly between Tailscale and LAN to prevent duplicate probing. |
| `/link doctor` | `/link doctor` | Runs comprehensive system, cryptographic, and confinement diagnostics. *(Alias: `/link-doctor`)* |
| `/link pin` | `/link pin [pin]` | Displays current PIN or sets a new 4-digit PIN for LAN connections. |
| `/link name` | `/link name [name]` | Changes the terminal's display name on the mesh. |
| `/link discover` | `/link discover` | Scans the selected network mode and lists all discovered sessions. |
| `/link help` | `/link help` | Displays complete command usage reference. |

---

## 5. Security & Hardened Cryptographic Model

`omp-link` enforces defense-in-depth security across local LAN and Tailscale networks:

1. **Ed25519 Cryptographic Identity & Challenge-Response Authentication**:
   - Each node generates a local Ed25519 keypair (`~/.omp/identity.json`). Permanent private keys never cross the wire.
   - Authentication uses cryptographic nonces signed by the joining device, and public key fingerprints are verified during host approval (`/link accept`).
2. **Forward-Secret Session Keys (Ephemeral X25519 + HKDF-SHA256)**:
   - Peers negotiate ephemeral X25519 Diffie-Hellman shared secrets on connection, deriving 256-bit AES-GCM session keys via HKDF-SHA256.
   - Forward secrecy guarantees that compromise of long-term credentials cannot decrypt previous or future communications.
   - Strict plaintext frame rejection: any unencrypted frame after handshake is rejected and terminated without fallback.
3. **Authenticated Additional Data (AAD) & Replay Prevention**:
   - Frame metadata (`v: 4`, monotonic `seq`, unique `mid`, sender `from`, and timestamp `ts`) is bound to the AES-256-GCM authentication tag.
   - Header tampering results in immediate GCM authentication rejection. Monotonic counters and `seenMessageIds` replay caches reject replayed packets.
4. **Self-Signed ECDSA TLS on LAN**:
   - In LAN mode, traffic is served over `https://` and `wss://` using a locally generated ECDSA P-256 TLS certificate (`~/.omp/tls/`), preventing LAN wiretapping.
5. **Passive & Sanitized Subprocess Execution (`safeGitExecFile`)**:
   - Structured inspection operations execute via `execFile` (never a shell) using sanitized environments.
   - Enforces passive git flags (`-c core.fsmonitor=false -c core.pager=cat -c pager.status=false -c pager.diff=false -c pager.log=false -c diff.external=`), strips dangerous environment variables (`LD_PRELOAD`, `NODE_OPTIONS`, `GIT_DIR`, `GIT_CONFIG`, etc.), and enforces `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_TERMINAL_PROMPT=0`.
6. **Canonical Path Confinement & Traversal Protection**:
   - Canonical `fs.realpath` verification (`resolveConfinedPath`) guarantees all file and directory operations remain confined strictly within the project workspace.
   - Traversal escapes (`../`), symlink bypasses, null bytes, and sensitive files (`.env*`, `.git/*`, `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, credentials, secrets) are deterministically blocked.
7. **Hardened Streaming File Inbox**:
   - Validates `transferId` (`^[a-zA-Z0-9_-]{1,64}$`) and limits chunk sizes to 64KB.
   - Streams chunks directly to disk (`.tmp-<id>.part` with mode `0600`) with streaming SHA-256 calculation, bounding RAM to 64KB and preventing DoS.
8. **Sanitized Public Discovery (`GET /status`)**:
   - Unauthenticated discovery requests receive minimal safe metadata (`{ service: "omp-link", protocolVersion: 4, instanceId, pairingRequired: true, fingerprint, tls }`).
   - Conceals all local paths, working directories, peer lists, and tokens. Query-string authentication is disabled, and `Cache-Control: no-store` is enforced.
9. **Territorial Sovereignty & Ephemeral Execution Elevation**:
   - Arbitrary remote shell execution is blocked by default. Read-only commands (`git status`, `git diff`) automatically redirect to safe structured operations.
   - Host can temporarily grant execution elevation via `/link grant <peer> [minutes]`. Grants expire automatically, revoke on disconnect, and log to `~/.omp/audit.log`.
   - The **Mutation Guard** protects repositories against accidental mutation (`rm`, `git commit`, `sed -i`, package installations).

---

## 6. LLM Agent Tools Reference

Agents inside OMP have access to 7 coordination and execution tools:

| Tool | Purpose | Key Parameters | Latency |
|---|---|---|---|
| `link_exec` | **Direct Tool RPC (Safe Structured Inspection)**: Execute safe inspection actions (`git_status`, `git_diff`, `git_log`, `search_text`, `read_file`, `list_dir`) across the mesh with canonical path confinement (< 30ms latency). Arbitrary shell execution is blocked by default under Territorial Sovereignty. | `{ to: "name", action: "git_status" \| "git_diff" \| "git_log" \| "search_text" \| "read_file" \| "list_dir" \| "exec", count?: 10, pattern?: "...", filePath?: "..." }` | **< 25ms** (Zero Tokens) |
| `link_send_file` | **Quarantined Out-of-band File Transfer**: Stream files across machines with 64KB chunking, SHA-256 verification, and automatic quarantine into `.omp/inbox/<transferId>/<safeFilename>`. 50MB ceiling limit. Also generates ephemeral direct HTTP links on `:9900/transfer/:token/:filename`. | `{ to: "name", sourcePath: "./dist/app.js" }` | **< 50ms** |
| `link_send` | **Agent-to-Agent Reasoning Delegation**: Send tasks or prompts directly into another agent's LLM reasoning loop. Use when code changes or planning are required! | `{ to: "name", message: "..." }` | **15–25s** (LLM turn) |
| `link_list` | Inspect all connected terminals, their hostnames, projects, status, context window usage, session ID, and network mode. | `{}` | < 5ms |
| `link_connect` | **Autonomous self-healing**: inspect status, auto-discover & join sessions, start hosting, switch network, or disconnect. | `{ action: "status" \| "join" \| "start" \| "leave", target?: "...", pin?: "...", network?: "tailscale" \| "lan" }` | < 100ms |
| `link_discover` | Scan the active network mode for other sessions and online terminals. | `{}` | ~500ms |
| `link_compact` | Request that another terminal compact its context window before delegating a large task. | `{ to: "name", customInstructions?: "..." }` | Variable |

### Autonomous Self-Healing for Agents:
If an agent ever encounters `"Not connected to link"` on a tool call, the agent should invoke:
```json
{
  "name": "link_connect",
  "parameters": { "action": "join" }
}
```
This automatically scans the active network, discovers the peer session, and rejoins without user intervention.

---

## 7. Agent Guidelines for Fast Swarm Collaboration

When acting as an agent on the link:

1. **Territorial Sovereignty (Local Domain Authority)**:
   - **Rule**: Every agent is the sole authoritative writer of its own local workspace.
   - **Never mutate peer code directly**: Never attempt to run `sed`, `rm`, `git commit`, or overwrite files on another machine. That desynchronizes the peer's context window and clobbers working trees.
   - **Observe -> Advise -> Local Execution**: Use `link_exec` to inspect peer code (`git diff`, `cat`, test runs). If changes are needed, send a task to the peer agent via `link_send` asking it to review and make the fix.
2. **Prefer `link_exec` for Information Gathering & Actions**:
   - If you only need to run a build, run tests, check `git status`, or read a file on another machine, use **`link_exec`**!
   - `link_exec` runs in **10–25ms** and costs **zero LLM tokens**.
   - Only use `link_send` when you specifically require the remote agent's brain to reason, refactor code, or plan architecture.
3. **Prevent Conversational Ping-Pong Loops**:
   - Every `link_send` message triggers an LLM turn on the receiving agent (`triggerTurn: true`), which takes 5–15 seconds of LLM inference.
   - **Never** send polite conversational acknowledgments (e.g. "Thanks!", "Got it, standing by!", "You're welcome!").
   - When finishing an assigned task, state your results clearly and conclude with: `[FINAL ANSWER - No reply needed]`.
4. **Pre-flight Status Check**:
   - Run `link_list` before dispatching tasks.
   - Verify the target agent is `idle`. If it is `thinking` or `compacting`, your message will queue in its inbox until its current turn completes.
5. **Context Window Hygiene**:
   - Check peer context utilization via `link_list`.
   - If a peer is above 75% context, call `link_compact` before sending a large code payload.
6. **Targeting by Role or Project**:
   - In your initial discovery, use `link_list` to see which machine has which project directory open, and dispatch repository-specific tasks to the terminal located in that project folder.

---

## 8. Maintenance & Debugging CLI

Outside OMP, these CLI commands assist with maintenance:

- **Clean up lingering processes & reset stale configs:**
  ```bash
  omp-link clean
  ```
  *(Kills processes on ports 9900/9901 and resets cached hub).*
- **Update to latest version from GitHub:**
  ```bash
  omp-link update
  ```
- **Scan network for active sessions:**
  ```bash
  omp-link find
  ```
- **Check version:**
  ```bash
  omp-link --version
  ```
