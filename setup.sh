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
mkdir -p "$HOME/.omp/agent/extensions" "$HOME/.omp/extensions"
mkdir -p "$HOME/.pi/agent/extensions" "$HOME/.pi/extensions"
ln -sfn "$REPO_DIR" "$HOME/.omp/agent/extensions/omp-link"
ln -sfn "$REPO_DIR" "$HOME/.omp/extensions/omp-link"
ln -sfn "$REPO_DIR" "$HOME/.pi/agent/extensions/omp-link"
ln -sfn "$REPO_DIR" "$HOME/.pi/extensions/omp-link"

# Link skills
mkdir -p "$HOME/.omp/agent/skills" "$HOME/.omp/skills"
mkdir -p "$HOME/.pi/agent/skills" "$HOME/.pi/skills"
if [[ -d "$REPO_DIR/skills" ]]; then
  ln -sfn "$REPO_DIR/skills" "$HOME/.omp/agent/skills/omp-link"
  ln -sfn "$REPO_DIR/skills" "$HOME/.pi/agent/skills/omp-link"
fi

echo ""
echo "======================================================================="
echo "  ✓ Setup complete! omp-link is ready (with pi-link alias)."
echo "======================================================================="
echo ""
echo "  Just start your coding session normally:"
echo "    omp"
echo "    (or omp-link)"
echo ""
echo "  All coordination happens via slash commands inside OMP:"
echo "    /link                   View session status, network, PIN, and peers"
echo "    /link-join              Auto-discover & join active session"
echo "    /link-start [id]        Start hosting a session"
echo "    /link-network <ts|lan>  Switch network mode (Tailscale / LAN)"
echo "    /link-pin [pin]         View or change PIN"
echo "    /link-leave             Leave session"
echo ""
echo "  Maintenance commands:"
echo "    omp-link clean          Release ports 9900/9901 & clear stale configs"
echo "    omp-link update         Pull latest version from GitHub"
echo "    omp-link find           Scan network for live link sessions"
echo ""
echo "  [AI ASSISTANTS / AGENTS]"
echo "    See AGENT.md for automated agent coordination and tool reference."
echo "======================================================================="
