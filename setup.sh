#!/usr/bin/env bash
set -e
set -uo pipefail

# Turnkey setup script for omp-link across multiple machines
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${HOME:-}" ]]; then
  echo "Error: \$HOME is not set, so there is nowhere to install to."
  exit 1
fi

# `ln -sfn SRC DST` reads as "replace DST with a link", and it does — unless DST already exists
# as a *real directory*. Then ln creates the link INSIDE it and exits 0, so setup prints "Setup
# complete" while the agent keeps loading the old directory: the install looks fine and every
# change made here does nothing. Refuse that case loudly instead, and name the fix.
link_into_place() {
  local src="$1" dst="$2" what="$3"
  if [[ -d "$dst" && ! -L "$dst" ]]; then
    echo ""
    echo "Error: $dst already exists as a real directory, not a symlink."
    echo "       It is probably an older copy-install of omp-link, an unpacked release, or a"
    echo "       plugin manager's own copy. Linking into it would leave that copy loaded and"
    echo "       this checkout ignored, with no visible error — so setup stops here."
    echo ""
    echo "       Check what is in it, then move it aside and re-run ./setup.sh:"
    echo "         mv \"$dst\" \"$dst.bak\""
    echo ""
    echo "       ($what would have been linked from $src)"
    exit 1
  fi
  if [[ -e "$dst" && ! -L "$dst" ]]; then
    echo "  ! replacing existing file $dst"
  fi
  ln -sfn "$src" "$dst"
}

echo "⚡ Setting up omp-link..."

# 1. Cleanup old versions and stale registrations
echo "🧹 Cleaning up legacy versions and stale configs..."

# Report — never kill — whatever holds 9900/9901. Setup has no way to prove a
# listener is an omp-link hub, and killing by port has taken down live agent
# sessions and unrelated dev servers. Use `omp-link cleanup` for that: it proves
# ownership over /status first and asks before signalling anything.
if command -v lsof >/dev/null 2>&1; then
  PORT_HOLDERS="$(lsof -nP -iTCP:9900 -sTCP:LISTEN -t 2>/dev/null || true)"
  if [[ -n "$PORT_HOLDERS" ]]; then
    echo "  ! Port 9900 is already in use by PID(s): $(echo "$PORT_HOLDERS" | tr '\n' ' ')"
    echo "    Left running. Inspect with: omp-link cleanup"
  fi
fi

# Remove legacy extension symlinks (pi-link) and plugin registrations to prevent duplicate loading
rm -rf "$HOME/.omp/agent/extensions/pi-link" 2>/dev/null || true
rm -rf "$HOME/.omp/extensions/pi-link" 2>/dev/null || true
rm -rf "$HOME/.pi/agent/extensions/pi-link" 2>/dev/null || true
rm -rf "$HOME/.pi/extensions/pi-link" 2>/dev/null || true
rm -rf "$HOME/.omp/plugins/node_modules/pi-link" 2>/dev/null || true
rm -rf "$HOME/.pi/plugins/node_modules/pi-link" 2>/dev/null || true

# Clean legacy pi-link from omp-plugins.lock.json
node -e '
const fs = require("fs");
const path = require("path");
const os = require("os");
for (const lockPath of [
  path.join(os.homedir(), ".omp", "plugins", "omp-plugins.lock.json"),
  path.join(os.homedir(), ".pi", "plugins", "omp-plugins.lock.json"),
]) {
  if (fs.existsSync(lockPath)) {
    try {
      const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
      if (lock.plugins && lock.plugins["pi-link"]) {
        delete lock.plugins["pi-link"];
        fs.writeFileSync(lockPath, JSON.stringify(lock, null, 2) + "\n");
        console.log(`  ✓ Removed legacy pi-link plugin registration from ${lockPath}`);
      }
    } catch {}
  }
}
' 2>/dev/null || true

# Cached hub addresses in link.json are user state, not install state: setup no
# longer edits them. `omp-link cleanup` previews a stale entry and only clears
# it with --apply.

# 2. Check Node.js (>= 18: the code uses ESM, node: specifiers and fetch)
if ! command -v node >/dev/null 2>&1; then
  echo "Error: node is required. Please install Node.js (v18+) first."
  exit 1
fi

NODE_VERSION="$(node -p 'process.versions.node' 2>/dev/null || echo "0.0.0")"
NODE_MAJOR="${NODE_VERSION%%.*}"
if ! [[ "$NODE_MAJOR" =~ ^[0-9]+$ ]] || (( NODE_MAJOR < 18 )); then
  echo "Error: omp-link needs Node.js 18 or newer. Found $NODE_VERSION at $(command -v node)."
  echo "       Install a newer Node (nvm install 22, brew install node, or your distro package) and re-run ./setup.sh."
  exit 1
fi

# 3. Install npm dependencies
echo "📦 Installing npm dependencies..."
cd "$REPO_DIR"
npm install --silent

# 4. Ensure CLI launchers are executable
chmod +x "$REPO_DIR/bin/omp-link.mjs" "$REPO_DIR/bin/pi-link.mjs"
# The MCP stdio server is optional in an older checkout; link it when it is present.
if [[ -f "$REPO_DIR/bin/omp-link-mcp.mjs" ]]; then
  chmod +x "$REPO_DIR/bin/omp-link-mcp.mjs"
fi

# 5. Link CLI binaries to ~/.local/bin
mkdir -p "$HOME/.local/bin"
link_into_place "$REPO_DIR/bin/omp-link.mjs" "$HOME/.local/bin/omp-link" "the omp-link CLI"
link_into_place "$REPO_DIR/bin/omp-link.mjs" "$HOME/.local/bin/pi-link" "the pi-link alias"
if [[ -f "$REPO_DIR/bin/omp-link-mcp.mjs" ]]; then
  link_into_place "$REPO_DIR/bin/omp-link-mcp.mjs" "$HOME/.local/bin/omp-link-mcp" "the MCP stdio server"
fi

# Ensure ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  export PATH="$HOME/.local/bin:$PATH"
  SHELL_RC=""
  if [[ -n "${ZSH_VERSION:-}" ]] || [[ "${SHELL:-}" == */zsh ]]; then
    SHELL_RC="$HOME/.zshrc"
  elif [[ -n "${BASH_VERSION:-}" ]] || [[ "${SHELL:-}" == */bash ]]; then
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
mkdir -p "$HOME/.omp/agent/skills" "$HOME/.omp/skills"
mkdir -p "$HOME/.pi/agent/skills" "$HOME/.pi/skills"

# These roots hold the device private key, the paired-device store and the audit log. Nothing
# outside this user account has any business reading them.
chmod 700 "$HOME/.omp" "$HOME/.pi" 2>/dev/null || true

link_into_place "$REPO_DIR" "$HOME/.omp/agent/extensions/omp-link" "the omp extension"
link_into_place "$REPO_DIR" "$HOME/.omp/extensions/omp-link" "the omp extension"
link_into_place "$REPO_DIR" "$HOME/.pi/agent/extensions/omp-link" "the pi extension"
link_into_place "$REPO_DIR" "$HOME/.pi/extensions/omp-link" "the pi extension"

# Link skills
if [[ -d "$REPO_DIR/skills" ]]; then
  link_into_place "$REPO_DIR/skills" "$HOME/.omp/agent/skills/omp-link" "the coordination skills"
  link_into_place "$REPO_DIR/skills" "$HOME/.pi/agent/skills/omp-link" "the coordination skills"
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
echo "  Coordination happens inside OMP/Pi:"
echo "    /link                   Status card (role, peers, authentication state)"
echo "    /link on | off          Turn the mesh on, or leave from this terminal"
echo "    /link create <name>     Host a new room"
echo "    /link join [endpoint]   Join an existing room"
echo "    /link scan              Look for reachable hubs (unverified until paired)"
echo ""
echo "  From a terminal:"
echo "    omp-link doctor         Measured diagnostics"
echo "    omp-link cleanup        Preview link-owned leftovers (--apply to act)"
echo "    omp-link update         Pull the latest version and re-run setup"
echo ""
echo "  Full command reference (single source of truth): omp-link help"
echo ""
echo "  [AI ASSISTANTS / AGENTS]"
echo "    See AGENT.md for automated agent coordination and tool reference."
echo "======================================================================="
