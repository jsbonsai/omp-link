# omp-link / pi-link

> **Multi-Machine & Multi-Codebase Inter-Terminal Coordination Mesh for [Oh-My-Pi (OMP)](https://github.com/can1357/oh-my-pi) and [Pi](https://github.com/badlogic/pi-mono).**  
> Turn multiple terminal windows across your Mac, Linux workstation, Raspberry Pi, or cloud VMs into a unified collaborative swarm over **Tailscale** and **LAN**.

---

## Origin & Credits

`omp-link` is an intelligent network fork of [Alberto Vivar's `pi-link`](https://github.com/alvivar/pi-link).

Alberto designed the foundational localhost protocol: WebSocket-based inter-terminal transport, trailing-edge batched inbox delivery, live status pub/sub, context window metrics, and remote compaction gating.

We took Alberto's great architecture and gave it distributed wings:
- **Tailscale WireGuard Mesh Integration**: Connect agents securely across distinct physical machines anywhere in the world.
- **Zero-Config Tailnet Discovery**: Probes online Tailscale peers and LAN UDP broadcast in under 1 second. `omp-link join` with no arguments automatically finds and attaches to your active hub.
- **Cross-Codebase & Host Awareness**: Terminals automatically track and display their host machine name (`os.hostname()`) and active repository/project directory (`path.basename(cwd)`).
- **Turnkey Setup & CLI**: One-command `./setup.sh` installation, automatic OMP extension registration, and dedicated `hub`, `join`, `find`, and `config` CLI commands.

---

## Security & Authentication Model

> [!WARNING]
> **No Application-Level Auth (Yet).**
> `omp-link` currently operates under a **trusted private network model**. There is no user authentication, authorization handshake, or TLS termination built directly into the WebSocket server yet.
> - **Tailscale**: When communicating over Tailscale (`100.64.0.0/10`), all traffic is encrypted end-to-end and authenticated by Tailscale's WireGuard layer.
> - **LAN**: On local subnets, discovery and WebSocket traffic are unauthenticated (an optional shared secret token can be set via `PI_LINK_SECRET` or `link.json`).
> - **Public Internet**: **DO NOT** expose port 9900 directly to the public internet. Dedicated token/mTLS auth is planned for future releases.

---

## Quick Start (60 Seconds)

### Step 1: Clone or Copy this repo to each machine
Copy or extract this folder onto any machine where you want to run OMP agents.

### Step 2: Run the turnkey setup
On **every machine**, run:
```bash
./setup.sh
```
*(This installs npm dependencies, symlinks `omp-link` into `~/.local/bin/`, registers the extension with `~/.omp/agent/extensions/`, and displays your detected Tailscale and LAN IPs).*

---

### Step 3: Start the Main Hub (Machine 1)
Pick one machine to be your primary link hub (e.g. your desktop or main laptop):

```bash
omp-link hub main
```
The hub starts on port `9900` (listening on all interfaces: `0.0.0.0`) and announces its reachable Tailscale IP.

---

### Step 4: Join from other machines (Machine 2, 3, etc.)

#### Option A: Auto-Discovery (Zero Config)
On your other machines, simply type:
```bash
omp-link join
```
It scans your Tailnet and LAN. If it discovers your running hub, it joins and saves the connection automatically!

#### Option B: Direct IP Join
```bash
omp-link join 100.64.0.1 laptop-worker
```
*(Replace `100.64.0.1` with your main machine's Tailscale or LAN IP).*

> [!TIP]
> `omp-link join` connects your current session. If you want to remember this hub permanently for future sessions, pass `--save` (`omp-link join 100.64.0.1 --save`) or run `omp-link config hub <ip>`.

---

## Architecture

```mermaid
graph TD
    subgraph Tailscale WireGuard Mesh / LAN
        subgraph Machine A (Desktop)
            Hub["omp-link hub 'main'<br/>(Port 9900 · 0.0.0.0)"]
            ProjectA["Repo: /dev/backend-api"]
            Hub --- ProjectA
        end

        subgraph Machine B (Laptop)
            ClientB["omp-link join<br/>'reviewer'"]
            ProjectB["Repo: /dev/frontend-ui"]
            ClientB --- ProjectB
        end

        subgraph Machine C (Linux Server / Pi)
            ClientC["omp-link join<br/>'database-worker'"]
            ProjectC["Repo: /dev/db-migrations"]
            ClientC --- ProjectC
        end

        ClientB -->|WebSocket over Tailscale| Hub
        ClientC -->|WebSocket over Tailscale| Hub
    end
```

---

## CLI Reference (`omp-link` / `pi-link`)

Both `omp-link` and `pi-link` commands are installed on your PATH:

| Command | Description |
|---|---|
| `omp-link hub [name]` | Start a session in **hub** mode, binding to `0.0.0.0:9900` for Tailnet/LAN access. |
| `omp-link join [ip] [name]` | Join a hub. If `[ip]` is omitted, automatically probes Tailnet & LAN and joins. |
| `omp-link join lan [name]` | Specifically search local WiFi/LAN via UDP broadcast to find and join a hub. |
| `omp-link find` *(or `search`)* | Scan all online Tailnet peers and LAN for active hubs, active sessions, and projects. |
| `omp-link update` *(or `upgrade`)* | Pull the latest version from git, refresh dependencies, and update extensions. |
| `omp-link clean` *(or `kill`)* | Terminate any lingering hub processes on port 9900 and reset cached hub. |
| `omp-link --status` | Display a real-time table of all terminals, hostnames, projects, and token window usage. |
| `omp-link --list` | List all saved pi-link sessions in the current directory (or everywhere with `-g`). |
| `omp-link config` | Inspect saved hub settings, local Tailscale IP, and LAN IP. |
| `omp-link config hub <ip>` | Save default hub IP to `~/.omp/link.json`. |
| `omp-link config hub clear` | Clear saved hub IP. |

---

## Interactive Slash Commands (Inside OMP / Pi)

Type these commands directly inside your OMP chat prompt:

- **`/link`**: Display status of all connected terminals, their host machines, and active codebases.
- **`/link-discover`** *(or `/link-search`)*: Scan your Tailnet and LAN for other running hubs.
- **`/link-connect [target]`**: Connect or switch to a hub (`/link-connect 100.64.0.1` or `/link-connect local`).
- **`/link-name [name]`**: Rename your terminal on the mesh.
- **`/link-disconnect`**: Disconnect from the mesh.

---

## LLM Agent Tools

Agents running in OMP have access to 4 coordination tools:

### 1. `link_send`
Send a task, prompt, or review to another terminal across the mesh:
```json
{
  "to": "reviewer",
  "content": "Please review src/auth.ts and verify if token expiration is handled."
}
```
*Delivery is batched (~200ms window) and steered directly into the receiver's reasoning cycle.*

### 2. `link_list`
Query all online terminals on the mesh, returning:
- Terminal names
- Host machines (`host: mbp-worker`)
- Projects (`project: backend-api`)
- Status (`idle`, `thinking`, `compacting`, `tool:<name>`)
- Context window token consumption (`45K/272K (17%)`)

### 3. `link_discover`
Search for active pi-link hubs and sessions across the Tailscale network and LAN when seeking to connect to other machines.

### 4. `link_compact`
Request that a target terminal compact its context window before dispatching a large task to it.

---

## Configuration File (`~/.omp/link.json` or `~/.pi/link.json`)

You can persist global defaults in `~/.omp/link.json`:

```json
{
  "hub": "100.64.0.1",
  "port": 9900,
  "bind": "0.0.0.0",
  "tailscaleOnly": false,
  "lanDiscovery": true,
  "secret": "optional-shared-token"
}
```

---

## Instructions for AI Coding Assistants (Handoff)

If you are an LLM being asked to set up this repository, read [`AGENT.md`](./AGENT.md) for concise, autonomous execution instructions.
