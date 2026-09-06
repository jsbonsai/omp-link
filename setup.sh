#!/usr/bin/env bash
set -e

# Turnkey setup script for omp-link across multiple machines
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "⚡ Setting up omp-link..."

# 1. Cleanup old versions and lingering processes
echo "🧹 Cleaning up legacy versions, stale configs, and orphan processes..."

# Kill any stale hub processes on ports 9900/9901
if command -v lsof >/dev/null 2>&1; then
  STALE_PIDS="$(lsof -ti :9900 -ti :9901 2>/dev/null || true)"
  if [[ -n "$STALE_PIDS" ]]; then
    echo "$STALE_PIDS" | xargs kill -9 2>/dev/null || true
    echo "  ✓ Terminated lingering processes on port 9900/9901"
  fi
fi

# Remove legacy extension symlinks (pi-link) to prevent duplicate loading
rm -rf "$HOME/.omp/agent/extensions/pi-link" 2>/dev/null || true
rm -rf "$HOME/.pi/agent/extensions/pi-link" 2>/dev/null || true

# Reset stale hub addresses from ~/.omp/link.json and ~/.pi/link.json
node -e '
const fs = require("fs");
const path = require("path");
const os = require("os");
for (const p of [
  path.join(os.homedir(), ".omp", "link.json"),
  path.join(os.homedir(), ".pi", "link.json"),
  path.join(os.homedir(), ".config", "pi-link", "link.json"),
  path.join(os.homedir(), ".config", "omp-link", "link.json"),
]) {
  if (fs.existsSync(p)) {
    try {
      const data = JSON.parse(fs.readFileSync(p, "utf8"));
      if (data.hub) {
        delete data.hub;
        fs.writeFileSync(p, JSON.stringify(data, null, 2) + "\n");
        console.log(`  ✓ Cleared stale hub address from ${p}`);
      }
    } catch {}
  }
}
' 2>/dev/null || true

# 2. Check Node.js
if ! command -v node >/dev/null 2>&1; then
  echo "Error: node is required. Please install Node.js (v18+) first."
  exit 1
fi

# 3. Install npm dependencies
echo "📦 Installing npm dependencies..."
cd "$REPO_DIR"
npm install --silent

# 4. Ensure CLI launchers are executable
chmod +x "$REPO_DIR/bin/omp-link.mjs" "$REPO_DIR/bin/pi-link.mjs"

# 5. Link CLI binaries to ~/.local/bin
mkdir -p "$HOME/.local/bin"
ln -sfn "$REPO_DIR/bin/omp-link.mjs" "$HOME/.local/bin/omp-link"
ln -sfn "$REPO_DIR/bin/omp-link.mjs" "$HOME/.local/bin/pi-link"

# Ensure ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  export PATH="$HOME/.local/bin:$PATH"
  SHELL_RC=""
  if [[ -n "$ZSH_VERSION" ]] || [[ "$SHELL" == */zsh ]]; then
    SHELL_RC="$HOME/.zshrc"
  elif [[ -n "$BASH_VERSION" ]] || [[ "$SHELL" == */bash ]]; then
    SHELL_RC="$HOME/.bashrc"
  fi
  if [[ -n "$SHELL_RC" && -f "$SHELL_RC" ]]; then
    if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$SHELL_RC"; then
      echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
    fi
  fi
fi

# 6. Link extension into OMP and Pi agent extensions directories as omp-link
mkdir -p "$HOME/.omp/agent/extensions"
mkdir -p "$HOME/.pi/agent/extensions"
ln -sfn "$REPO_DIR" "$HOME/.omp/agent/extensions/omp-link"
ln -sfn "$REPO_DIR" "$HOME/.pi/agent/extensions/omp-link"

# 7. Detect IP addresses for easy copy-paste
CONFIG_INFO="$("$REPO_DIR/bin/omp-link.mjs" config 2>/dev/null || true)"
TS_IP="$(echo "$CONFIG_INFO" | grep "Tailscale IPv4" | awk -F': ' '{print $2}' | tr -d ' ')"
LAN_IP="$(echo "$CONFIG_INFO" | grep "Local LAN IPv4" | awk -F': ' '{print $2}' | tr -d ' ')"

MAIN_IP="${TS_IP:-$LAN_IP}"
MAIN_IP="${MAIN_IP:-(your-hub-ip)}"

echo ""
echo "======================================================================="
echo "  ✓ Setup complete! omp-link is ready (with pi-link alias)."
echo "======================================================================="
echo ""
echo "  [MAIN MACHINE] (Run on the machine you choose as the main hub):"
echo "    omp-link hub [session-name]"
echo ""
if [[ -n "$TS_IP" && "$TS_IP" != "(not detected)" ]]; then
  echo "    Reachable via Tailscale at: $TS_IP:9900"
fi
if [[ -n "$LAN_IP" && "$LAN_IP" != "(not detected)" ]]; then
  echo "    Reachable via LAN at:       $LAN_IP:9900"
fi
echo ""
echo "  [WORKER / CLIENT MACHINES] (Run on other machines to join):"
echo "    omp-link join $MAIN_IP [session-name]"
echo "    (or simply: omp-link join  to auto-discover on Tailnet/LAN)"
echo ""
echo "  [STATUS & DISCOVERY]"
echo "    omp-link find      (Scan Tailnet & LAN for active hubs)"
echo "    omp-link --status  (Check active terminals and projects)"
echo "    omp-link clean     (Clean lingering processes / ports)"
echo "    omp-link update    (Pull latest version from git)"
echo ""
echo "  [AI ASSISTANTS / LLMS]"
echo "    See AGENT.md for automated agent coordination and tool reference."
echo "======================================================================="
