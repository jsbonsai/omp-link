# omp-link

> **Multi-Machine & Multi-Codebase Inter-Terminal Coordination Mesh for [Oh-My-Pi (OMP)](https://github.com/can1357/oh-my-pi) and [Pi](https://github.com/badlogic/pi-mono).**  
> Turn multiple terminal windows across your Mac, Linux workstation, Raspberry Pi, or cloud VMs into a unified collaborative swarm over **Tailscale** and **LAN**.

---

## What It Looks Like When It Works

When `omp-link` is running, type `/link` inside OMP to see your live mesh dashboard:

```text
⚡ OMP LINK: ACTIVE
────────────────────────────────────────────────────────────
  Session ID : team-swarm
  Network    : LAN (PIN: 4821)  [or TAILSCALE: auto-verified via WireGuard]
  Endpoint   : 192.168.1.50:9900
  Role       : Host (macbook-pro)
────────────────────────────────────────────────────────────
  Online Peers (3):
    • macbook-pro       (you) [host: mac-1   · project: web-app] (idle)
    • linux-workstation       [host: linux-2 · project: backend] (idle)
    • cloud-vm                [host: vm-3    · project: ai-models] (idle)
────────────────────────────────────────────────────────────
  Quick join from another machine:
    /link-join team-swarm 4821
    (or /link-join 192.168.1.50:9900 4821)
```

### Live Peer Joining & Message Stream
When another terminal connects or sends a message, OMP displays live status notifications:

```text
⚡ Connected to session "team-swarm" on LAN (2 online)
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
| **`/link`** | `/link` | **The Dashboard**: Instant status card showing your session ID, network mode, PIN, endpoint, and all online peers. |
| **`/link-join`** | `/link-join`<br>`/link-join [id] [pin]` | **Connect**: With no arguments, scans your network and **auto-joins** the active session! Or specify session ID / IP and PIN. |
| **`/link-start`** | `/link-start [id] [pin]` | **Host**: Start or switch to hosting a session with a custom ID or PIN. |
| **`/link-leave`** | `/link-leave` | **Disconnect**: Cleanly leave the session and release the network port. |

### Secondary Slash Commands
- `/link-network <tailscale | lan>`: Switch between Tailscale (WireGuard auto-auth) and LAN mode.
- `/link-discover`: Scan the active network and list all available sessions.
- `/link-pin [pin]`: Inspect or set a new 4-digit PIN for LAN mode.
- `/link-name [name]`: Change your terminal's display name on the mesh.

---

## Agent Tools (Autonomous Swarm Operation)

Agents running inside OMP have access to 5 built-in coordination tools:

### 1. `link_send`
Send a message, code snippet, or task to another terminal across the mesh:
```json
{
  "to": "linux-workstation",
  "message": "Please review src/auth.ts and verify if token expiration is handled."
}
```
*Delivery is batched (50ms window) and injected directly into the recipient's reasoning cycle.*

### 2. `link_list`
Inspect all connected terminals, their hostnames, projects, CPU/agent states (`idle`, `thinking`, `compacting`, `tool:<name>`), context window token usage (`45K/200K (22%)`), session ID, and network mode.

### 3. `link_connect`
Autonomous self-healing tool. If an agent detects a temporary disconnection, it calls:
```json
{ "action": "join" }
```
This automatically scans the active network, discovers the peer session, and reconnects without human intervention.

### 4. `link_compact`
Request that a target terminal compact its context window before dispatching a large task to it.

### 5. `link_discover`
Scan the active network mode for other sessions and online terminals.

---

## Understanding Agent Speed & Latency

### Why does agent-to-agent messaging feel slow?
If you send a message to a remote agent and wait for a reply, you may notice it takes **10 to 30 seconds**. This is completely normal and is caused by **LLM inference**, not the network:

1. **Network Transport (< 5ms)**: The WebSocket message over Tailscale or LAN takes less than 5 milliseconds.
2. **Inbox Flush (50ms)**: The incoming message is batched and injected into OMP within 50ms.
3. **LLM Thinking & Generation (5–15 seconds per turn)**:
   - When the receiving agent receives the message, it loads its full conversation history (often 30,000–80,000 tokens).
   - If using a reasoning model (e.g. Claude 3.7 Sonnet Thinking, o3-mini), the model spends 5–15 seconds generating hidden thinking tokens.
   - The model streams its response and executes any needed tool calls.
4. **Round-Trip Math**:
   - Agent A sends task $\rightarrow$ 5ms network $\rightarrow$ Agent B thinks (10s) $\rightarrow$ Agent B replies $\rightarrow$ 5ms network $\rightarrow$ Agent A reads reply and thinks (10s) $\rightarrow$ **Total elapsed: ~20–25 seconds**.

### Tips for Maximum Swarm Speed:
- **Use Faster / Lighter Models for Workers**: For routine subtasks, use models like Claude 3.5 Haiku, Gemini 2.0 Flash, or GPT-4o-mini on worker terminals. Reserve heavier reasoning models for the orchestrator.
- **Prevent Endless Ping-Pong Loops**: When an agent completes a task, instruct it to conclude with `[FINAL ANSWER - No reply needed]` or state: *"Do not acknowledge; only reply when the task is complete."* Otherwise, agents will spend 15 seconds per turn thanking each other!
- **Watch Context Window Size**: Use `/link` or `link_list` to monitor context token usage. As context grows past 100k tokens, time-to-first-token (TTFT) increases. Run `/compact` when needed.

---

## What to Monitor During Multi-Agent Collaboration

When coordinating multi-terminal swarms, keep an eye on these four indicators:

1. **Agent Status (`idle` vs `thinking` vs `compacting`)**:
   - Check `/link` or `link_list` before sending a task.
   - If a peer is `thinking`, it is busy processing a previous turn. Your message will be held in its inbox and delivered as soon as the current turn settles.
   - If a peer is `compacting`, message delivery is paused until compaction finishes.
2. **Context Window Percentage**:
   - If a worker terminal exceeds 70–80% context utilization, request a compaction (`link_compact` or `/compact`) to restore speed and keep costs low.
3. **Network Mode Consistency**:
   - Ensure all machines are using the same network mode (**Tailscale** or **LAN**). Tailscale is recommended for zero-PIN auto-auth and cross-network flexibility; LAN is ideal for high-speed offline local Wi-Fi.
4. **Active Session ID**:
   - Terminals automatically pair with sessions matching the current folder or project name. Verify with `/link` that all machines share the same Session ID.

---

## Security & Authentication Model

`omp-link` uses a strict **either/or network model** with dual-tier security:

1. **Tailscale Mode (Default when active):**
   - Connections strictly use the Tailscale network (`100.64.0.0/10`).
   - Authentication is **automatically verified** via WireGuard cryptographic peer identity. No PIN entry is required!
2. **LAN Mode:**
   - Connections use the local subnet.
   - Remote peers **must provide the 4-digit session PIN** to join.
   - Connection attempts without a valid PIN are rejected with `4001: Invalid session PIN`.
3. **Strict Network Isolation:**
   - Probing and listening are strictly bound to either Tailscale or LAN, eliminating split-brain states and duplicate device appearances.

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
