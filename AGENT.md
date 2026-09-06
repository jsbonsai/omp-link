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
| `/link` | `/link` | Displays the link status card: current session ID, network mode, LAN PIN, and all online peers. |
| `/link-start` | `/link-start [id] [pin]` | Starts or switches to hosting a session with the given ID and PIN. |
| `/link-join` | `/link-join [id \| ip[:port]] [pin]` | Joins an active session. If no target is given, auto-discovers active sessions on your network mode. |
| `/link-leave` | `/link-leave` | Disconnects from the current session. (Alias: `/link-disconnect`). |
| `/link-network` | `/link-network <tailscale \| lan>` | Switches strictly between Tailscale and LAN to prevent duplicate device probing. |
| `/link-pin` | `/link-pin [pin]` | Displays current PIN or sets a new 4-digit PIN. |
| `/link-name` | `/link-name [name]` | Changes the terminal's display name on the mesh. |
| `/link-discover` | `/link-discover` | Scans the selected network mode and lists all discovered sessions. |

---

## 5. Security & Authentication Model

`omp-link` enforces a strict **either/or network model** with dual-tier security:

1. **Tailscale Mode (Default when active):**
   - Connections strictly use the Tailscale network (`100.64.0.0/10`).
   - Authentication is **automatically verified** via WireGuard cryptographic peer identity (`isTailscaleOrLocalIp`). No PIN entry is needed when linking over Tailscale!
2. **LAN Mode:**
   - Connections use the local subnet.
   - Remote peers **must provide the 4-digit session PIN** to join.
   - Non-Tailscale connection attempts without a valid PIN are rejected with `4001: Invalid session PIN`.
3. **Strict Network Isolation:**
   - Probing and listening are strictly bound to either Tailscale or LAN, eliminating split-brain states and duplicate device appearances.

---

## 6. LLM Agent Tools Reference

Agents inside OMP have access to 5 coordination tools:

| Tool | Purpose | Key Parameters |
|---|---|---|
| `link_connect` | **Autonomous self-healing**: inspect status, auto-discover & join sessions, start hosting, switch network, or disconnect. | `{ action: "status" \| "join" \| "start" \| "leave", target?: "...", pin?: "...", network?: "tailscale" \| "lan" }` |
| `link_send` | Send a task/message to another terminal on any machine. Includes auto-reconnect fallback if connection temporarily dropped. | `{ to: "terminal-name", message: "..." }` |
| `link_list` | Inspect all connected terminals, their hostnames, projects, status, context window usage, session ID, and network mode. | `{}` |
| `link_discover` | Scan the active network mode for other sessions and online terminals. | `{}` |
| `link_compact` | Request that another terminal compact its context window before delegating a large task. | `{ to: "terminal-name", customInstructions?: "..." }` |

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

1. **Prevent Conversational Ping-Pong Loops**:
   - Every `link_send` message triggers an LLM turn on the receiving agent (`triggerTurn: true`), which takes 5–15 seconds of LLM inference.
   - **Never** send polite conversational acknowledgments (e.g. "Thanks!", "Got it, standing by!", "You're welcome!").
   - When finishing an assigned task, state your results clearly and conclude with: `[FINAL ANSWER - No reply needed]`.
2. **Pre-flight Status Check**:
   - Run `link_list` before dispatching tasks.
   - Verify the target agent is `idle`. If it is `thinking` or `compacting`, your message will queue in its inbox until its current turn completes.
3. **Context Window Hygiene**:
   - Check peer context utilization via `link_list`.
   - If a peer is above 75% context, call `link_compact` before sending a large code payload.
4. **Targeting by Role or Project**:
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
