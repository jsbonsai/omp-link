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

## 3. Launching & Connecting

Ask the user or determine whether this machine is the **Main Hub** or a **Worker**:

### Option A: This Machine is the MAIN HUB
Run:
```bash
omp-link hub [session-name]
```
- Binds to `0.0.0.0:9900`.
- Acts as the central message router for all machines.
- Prints reachable Tailscale and LAN IPs on startup.

### Option B: This Machine is a WORKER (Joining an Existing Hub)

#### 1. Auto-discovery (No IP needed):
```bash
omp-link join [session-name]
```
*(Scans all online Tailnet peers via Tailscale CLI and LAN UDP 9901 broadcast. If one hub is found, connects automatically).*

#### 2. Manual IP connection:
```bash
omp-link join <HUB_TAILSCALE_OR_LAN_IP> [session-name]
```
*(Connects directly to the specified hub. Add `--save` to persist as the default hub in `~/.omp/link.json`).*

---

## 4. Verification & Status Commands

As an agent, you can run these CLI commands in bash to inspect or debug the link:

- **Update to the latest version:**
  ```bash
  omp-link update
  ```
  *(Fetches latest changes from git, updates dependencies, and refreshes extension links).*
- **Clean up lingering hub processes / release port 9900:**
  ```bash
  omp-link clean
  ```
  *(Terminates any stale background hub processes occupying port 9900 and resets cached hub).*
- **Scan Tailnet & LAN for active hubs:**
  ```bash
  omp-link find
  # or with machine-readable JSON:
  omp-link find --json
  ```
- **Show live connected terminals across all machines:**
  ```bash
  omp-link --status
  # or machine-readable:
  omp-link --status --json
  ```
- **Inspect local network config and saved hub:**
  ```bash
  omp-link config
  ```
- **Clear saved hub target:**
  ```bash
  omp-link config hub clear
  ```

---

## 5. How OMP / Pi Loads This Extension

OMP and Pi automatically discover extensions by inspecting directories in `~/.omp/agent/extensions/` and `~/.pi/agent/extensions/`.
Because `./setup.sh` created a symlink `~/.omp/agent/extensions/omp-link -> <repo-root>`, OMP reads `package.json`:
```json
"pi": {
  "extensions": ["./index.ts"],
  "skills": ["./skills"]
}
```
And loads `index.ts` whenever OMP starts. In addition, the `omp-link` CLI wrapper acts as a fallback by passing `--extension <path-to-index.ts>` if the symlink is ever missing.

---

## 6. In-Session Tools Reference (When Running Inside OMP)

Inside an active session, the LLM has access to these tools:

| Tool | Purpose | Key Parameters |
|---|---|---|
| `link_list` | Inspect all connected terminals, their hostnames, projects, status, and token window usage. | `{}` |
| `link_discover` | Probe Tailnet and LAN for other active hubs and sessions. | `{}` |
| `link_send` | Send a task/message to another terminal on any machine. | `{ to: "terminal-name", content: "..." }` |
| `link_compact` | Request that another terminal compact its context window before delegating a large task. | `{ to: "terminal-name", instructions?: "..." }` |

### In-Session Slash Commands (for Human or Agent interactive prompt):
- `/link` — View current terminal and online peers.
- `/link-discover` — Scan Tailnet and LAN for active hubs.
- `/link-connect [target]` — Connect/reconnect to a remote hub or `local`.
- `/link-name [name]` — Change terminal name on the link.
- `/link-disconnect` — Disconnect from the link.

---

## 7. Important Security Note

There is currently **no application-level authentication** or token verification enforced by default.
- On Tailscale, security and encryption are provided at the network layer by WireGuard.
- On LAN, port 9900 is open to local network peers.
- **Do not expose port 9900 to the public internet without a firewall or reverse proxy.**
