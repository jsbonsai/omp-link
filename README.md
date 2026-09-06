# omp-link

> **Multi-Machine & Multi-Codebase Inter-Terminal Coordination Mesh for [Oh-My-Pi (OMP)](https://github.com/can1357/oh-my-pi) and [Pi](https://github.com/badlogic/pi-mono).**  
> Turn multiple terminal windows across your Mac, Linux workstation, Raspberry Pi, or cloud VMs into a unified collaborative swarm over **Tailscale** and **LAN**.

---

## Origin & Credits

`omp-link` is an intelligent network fork of [Alberto Vivar's `pi-link`](https://github.com/alvivar/pi-link).

Alberto designed the foundational localhost protocol: WebSocket-based inter-terminal transport, trailing-edge batched inbox delivery, live status pub/sub, context window metrics, and remote compaction gating.

We took Alberto's great architecture and gave it distributed wings:
- **Session-Centric & Slash-Command Driven**: No external hub/worker launch wrappers. Run `omp` normally; all coordination is driven directly inside OMP via slash commands (`/link`, `/link-start`, `/link-join`, etc.).
- **Strict Either/Or Network Model**: Explicitly choose **Tailscale** (default when active) or **LAN**. Probing and listening are strictly segregated, eliminating duplicate device entries.
- **PIN & WireGuard Authentication**: Dual-tier security model. On Tailscale, peers are auto-verified via WireGuard cryptographic identity. On LAN, remote peers must provide a 4-digit session PIN.
- **Autonomous Agent Self-Healing**: Includes a `link_connect` tool and auto-reconnect fallback in `link_send` so agents can heal drops without human intervention.
- **Cross-Codebase & Host Awareness**: Terminals automatically track and display their host machine name (`os.hostname()`) and active repository/project directory (`path.basename(cwd)`).
- **Turnkey Setup**: One-command `./setup.sh` installation, automatic OMP extension registration, and maintenance tools (`omp-link clean`, `omp-link update`, `omp-link find`).

---

## Security & Authentication Model

`omp-link` uses a strict **either/or network model** with dual-tier authentication:

1. **Tailscale Mode (Default when active):**
   - Connections strictly use the Tailscale network (`100.64.0.0/10`).
   - Authentication is **automatically verified** via WireGuard cryptographic peer identity. No PIN entry is required when linking over Tailscale!
2. **LAN Mode:**
   - Connections use the local subnet.
   - Remote peers **must provide the 4-digit session PIN** to join.
   - Non-Tailscale connection attempts without a valid PIN are rejected with `4001: Invalid session PIN`.
3. **Strict Network Isolation:**
   - Probing and listening are strictly bound to either Tailscale or LAN, eliminating split-brain states and duplicate device appearances.

---

## Quick Start (60 Seconds)

### Step 1: Clone this repo on each machine
```bash
git clone https://github.com/jsbonsai/omp-link.git
cd omp-link
```

### Step 2: Run the turnkey setup
On **every machine**, run:
```bash
./setup.sh
```
*(This installs npm dependencies, symlinks `omp-link` into `~/.local/bin/`, registers the extension with `~/.omp/agent/extensions/`, and cleans up any legacy configs or ports).*

---

### Step 3: Launch OMP Normally
You don't need any special launcher. Simply start `omp` (or `omp-link`):
```bash
omp
```
- On startup, `omp-link` automatically checks for active sessions.
- If a session matching your current directory already exists on your network, it joins automatically!
- Otherwise, it starts hosting the session.

---

### Step 4: Check Status with `/link`
Inside OMP, type:
```
/link
```
You will see a live status card:
```
⚡ OMP LINK: ACTIVE
────────────────────────────────────────────────────
  Session ID : ag-exp
  Network    : TAILSCALE (auto-verified via WireGuard)
  Endpoint   : 100.82.14.92:9900
  LAN PIN    : 4821
  Role       : Host (t-a1b2)
────────────────────────────────────────────────────
  Online Peers (2):
    • t-a1b2 (you) [host: mac-1 · project: ag-exp] (idle)
    • worker-2 [host: mac-2 · project: ag-exp] (idle)
────────────────────────────────────────────────────
  Quick join from another Mac:
    /link-join ag-exp
    (or /link-join 100.82.14.92:9900)
```

---

## Interactive Slash Commands (Inside OMP / Pi)

Type these commands directly inside your OMP prompt:

| Command | Usage | Description |
|---|---|---|
| `/link` | `/link` | Display link status card: session ID, network mode, LAN PIN, and all online peers. |
| `/link-start` | `/link-start [id] [pin]` | Start hosting a session with the given ID and PIN. |
| `/link-join` | `/link-join [id \| ip[:port]] [pin]` | Join an active session. If no argument is given, auto-discovers and joins. |
| `/link-leave` | `/link-leave` | Disconnect / leave the current session. (Alias: `/link-disconnect`). |
| `/link-network` | `/link-network <tailscale \| lan>` | Switch network mode between Tailscale and LAN. |
| `/link-pin` | `/link-pin [pin]` | View current PIN or update to a new 4-digit PIN. |
| `/link-name` | `/link-name [name]` | Rename your terminal on the mesh. |
| `/link-discover` | `/link-discover` | Scan the active network mode and list all discovered sessions. |

---

## LLM Agent Tools

Agents running in OMP have access to 5 coordination tools:

### 1. `link_connect`
Autonomous connection and self-healing tool:
```json
{
  "action": "join",
  "target": "ag-exp"
}
```
*Allows agents to inspect status, join sessions, start hosting, or switch network mode without human intervention.*

### 2. `link_send`
Send a task, prompt, or review to another terminal across the mesh:
```json
{
  "to": "worker-2",
  "message": "Please review src/auth.ts and verify if token expiration is handled."
}
```
*Delivery is batched (~200ms window) and steered directly into the receiver's reasoning cycle. Includes auto-reconnect fallback.*

### 3. `link_list`
Query all online terminals on the mesh, returning:
- Terminal names
- Host machines (`host: mbp-worker`)
- Projects (`project: backend-api`)
- Status (`idle`, `thinking`, `compacting`, `tool:<name>`)
- Context window token consumption (`45K/272K (17%)`)
- Current Session ID and Network Mode

### 4. `link_discover`
Search for active sessions across the selected network mode (Tailscale or LAN).

### 5. `link_compact`
Request that a target terminal compact its context window before dispatching a large task to it.

---

## Maintenance & CLI Commands

Outside OMP, these maintenance commands are available:

| Command | Description |
|---|---|
| `omp-link clean` | Release ports 9900/9901 and reset stale cached configs. |
| `omp-link update` | Pull the latest version from GitHub, refresh dependencies, and update extensions. |
| `omp-link find` | Probe the network for active sessions from the command line. |
| `omp-link --version` | Print current version. |

---

## Configuration File (`~/.omp/link.json` or `~/.pi/link.json`)

You can persist defaults in `~/.omp/link.json`:

```json
{
  "network": "tailscale",
  "sessionId": "team-swarm",
  "pin": "4821",
  "port": 9900,
  "bind": "0.0.0.0"
}
```

---

## Instructions for AI Coding Assistants

If you are an AI assistant setting up this repository for a user, read [`AGENT.md`](./AGENT.md) for automated execution instructions.
