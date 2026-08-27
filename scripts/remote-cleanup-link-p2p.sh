#!/usr/bin/env bash
# Safely tear down leftover link-p2p test processes on a machine.
#
# Scope (deliberately narrow — do NOT touch Tailscale / system daemons):
#   - tmux session named exactly "link-p2p" (project name)
#   - processes whose cmdline matches target/release/link-p2p or ./link-p2p
#   - leftover test python http.server on the ports we use (18081)
#
# Usage (on the machine, or via ssh):
#   ./scripts/remote-cleanup-link-p2p.sh
set -euo pipefail

echo "=== tmux sessions (before) ==="
tmux ls 2>/dev/null || echo "(no tmux server)"

if tmux has-session -t '=link-p2p' 2>/dev/null; then
    echo "killing tmux session 'link-p2p'"
    tmux kill-session -t '=link-p2p'
else
    echo "no tmux session named 'link-p2p'"
fi

# Exact-ish binary match — avoid matching this script or editors.
# Prefer SIGTERM, then SIGKILL after a short wait.
pkill -f '[t]arget/release/link-p2p' 2>/dev/null || true
pkill -f '[.]/link-p2p ' 2>/dev/null || true
pkill -f '[/]link-p2p (serve|connect|tun|ping)' 2>/dev/null || true
sleep 1
pkill -9 -f '[t]arget/release/link-p2p' 2>/dev/null || true

# Only the ad-hoc http.server used by prior cross-network tests.
pkill -f 'python3 -m http.server 18081' 2>/dev/null || true

echo "=== remaining link-p2p / related ==="
pgrep -af 'link-p2p|http.server 18081' || echo "(none)"
echo "=== tmux sessions (after) ==="
tmux ls 2>/dev/null || echo "(no tmux server)"
echo "done (Tailscale left untouched)"
