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

All session control is driven directly inside OMP via slash commands:

| Command | Usage | Description |
|---|---|---|
| `/link` | `/link` | Displays the link status card: session ID, network mode, LAN PIN, E2EE status, and all online peers. |
| `/link off` | `/link off` | Instantly deactivates the mesh, suppresses auto-reconnect, and stops all disconnected logs. |
| `/link on` | `/link on` | Re-enables the mesh, reconnects to the network, and resumes peer sync. |
| `/link-start` | `/link-start [id] [pin]` | Starts or switches to hosting a session with the given ID and PIN. |
| `/link-join` | `/link-join [id \| ip[:port]] [pin]` | Joins an active session. If no target is given, auto-discovers active sessions on your network mode. |
| `/link-accept` | `/link-accept [id]` | Approves a pending device join request and issues a persistent device token. |
| `/link-deny` | `/link-deny [id]` | Rejects a pending device join request. |
| `/link-requests` | `/link-requests` | Displays all pending join requests awaiting host approval. |
| `/link-devices` | `/link-devices [revoke <id>]` | Lists paired devices or revokes a device's permanent token. |
| `/link-exec-mode` | `/link-exec-mode [allow\|block]` | Inspects or toggles remote arbitrary shell execution. |
| `/link-leave` | `/link-leave` | Disconnects from the current session. (Alias: `/link-disconnect`). |
| `/link-network` | `/link-network <tailscale \| lan>` | Switches strictly between Tailscale and LAN to prevent duplicate device probing. |
| `/link-pin` | `/link-pin [pin]` | Displays current PIN or sets a new 4-digit PIN. |
| `/link-name` | `/link-name [name]` | Changes the terminal's display name on the mesh. |
| `/link-discover` | `/link-discover` | Scans the selected network mode and lists all discovered sessions. |
| `/link-mutation` | `/link-mutation [on\|off\|log]` | Inspects, toggles, or displays the audit log for the Mutation Guard. |

---

## 5. Security & Hardened Architecture Model

`omp-link` enforces defense-in-depth security across local LAN and Tailscale networks:

1. **Always-Prompt First-Time Pairing ("Request Mode")**:
   - New devices connecting over LAN or Tailscale must be approved on the host terminal via `/link-accept 1`.
   - Approving issues a persistent cryptographic device token (`~/.omp/paired-devices.json`), enabling automatic reconnects on subsequent sessions without repeated prompts.
2. **Structured Inspection Operations (No-Shell `execFile`)**:
   - Replaces shell execution with dedicated structured operations: `git_status`, `git_diff` (`--no-ext-diff`, `--no-textconv`), `git_log`, `search_text` (`git grep`), `read_file`, and `list_dir`.
   - Executes via `execFile` without invoking a shell interpreter, eliminating shell injection risks.
3. **Workspace Path Confinement & Traversal Protection**:
   - Canonical `fs.realpath` verification (`resolveConfinedPath`) guarantees read operations cannot escape the project root.
   - Denies access to sensitive patterns (`.env*`, `.git/*`, `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, credentials, secrets).
4. **Hardened 50MB Quarantine Inboxes**:
   - Ingested files save strictly into `.omp/inbox/<transferId>/<safeFilename>`, ensuring peer files cannot overwrite project files.
   - Enforces a 50MB transfer ceiling.
5. **Sanitized Public Discovery (`GET /status`)**:
   - Unauthenticated discovery requests receive minimal safe metadata (`{ service: "omp-link", version: "3.1.0", active: true, authRequired: true }`).
   - Completely conceals host paths, working directories, active peers, and PINs.
6. **Native Hardware-Accelerated E2EE (AES-256-GCM)**:
   - All WebSocket frames are encrypted via native Node.js `aes-256-gcm` with PBKDF2-HMAC-SHA256 key derivation.
   - 128-bit authentication tags ensure automatic tamper rejection.
7. **Territorial Sovereignty & Mutation Guard**:
   - Arbitrary remote shell execution is blocked by default. Common read-only commands (`git status`, `git diff`) automatically redirect to safe structured operations.
   - When remote execution is unlocked (`/link-exec-mode allow`), the **Mutation Guard** blocks mutating commands (`rm`, `sed -i`, `git commit`, `chmod`, `>`/`>>` redirects, package updates).

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
