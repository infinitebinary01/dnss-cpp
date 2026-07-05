#!/bin/bash
# switch-network.sh — Toggle between work (PdaNet proxy) and home (direct)
#
# Usage:
#   ./scripts/switch-network.sh          # interactive: prompts for mode
#   ./scripts/switch-network.sh work     # switch to work proxy
#   ./scripts/switch-network.sh home     # switch to direct
#
# Updates all four locations at once:
#   1. ~/.lynx-proxy (lynx SIGHUP config)
#   2. /etc/environment (system-wide proxy vars)
#   3. GNOME proxy settings (gsettings)
#   4. ~/.bashrc (terminal proxy vars)

set -euo pipefail

MODE="${1:-}"
LYNX_CONFIG_DIR="${LYNX_CONFIG_DIR:-$HOME/.config/lynx}"
PROXY_FILE="$HOME/.lynx-proxy"

WORK_PROXY="http://<IP ADDRESS>:8000"
WORK_NO_PROXY="localhost,127.0.0.1,::1,192.168.0.0/16,10.0.0.0/8"

die() { echo "$*" >&2; exit 1; }
log() { echo "[$(date '+%H:%M:%S')] $*"; }

detect_current() {
    if [ -f "$PROXY_FILE" ] && [ -s "$PROXY_FILE" ]; then
        echo "work"
    else
        echo "home"
    fi
}

set_work() {
    log "Switching to WORK mode (PdaNet proxy)"

    # 1. ~/.lynx-proxy
    echo "$WORK_PROXY" > "$PROXY_FILE"
    log "Wrote $PROXY_FILE"

    # 2. /etc/environment (needs sudo)
    if [ "$EUID" -ne 0 ]; then
        log "Skipping /etc/environment — re-run with sudo for system-wide proxy"
        log "  sudo $0 work"
    else
        # Remove existing proxy lines and append new ones
        sed -i '/^http_proxy=/d; /^https_proxy=/d; /^HTTP_PROXY=/d; /^HTTPS_PROXY=/d; /^no_proxy=/d; /^NO_PROXY=/d' /etc/environment
        cat >> /etc/environment <<EOF
http_proxy=$WORK_PROXY
https_proxy=$WORK_PROXY
HTTP_PROXY=$WORK_PROXY
HTTPS_PROXY=$WORK_PROXY
no_proxy=$WORK_NO_PROXY
NO_PROXY=$WORK_NO_PROXY
EOF
        log "Updated /etc/environment"
    fi

    # 3. GNOME proxy
    if command -v gsettings &>/dev/null; then
        gsettings set org.gnome.system.proxy mode 'manual' 2>/dev/null || true
        gsettings set org.gnome.system.proxy.http host '<IP ADDRESS>' 2>/dev/null || true
        gsettings set org.gnome.system.proxy.http port 8000 2>/dev/null || true
        gsettings set org.gnome.system.proxy.https host '<IP ADDRESS>' 2>/dev/null || true
        gsettings set org.gnome.system.proxy.https port 8000 2>/dev/null || true
        gsettings set org.gnome.system.proxy ignore-hosts "['localhost', '127.0.0.0/8', '::1']" 2>/dev/null || true
        log "Set GNOME proxy to manual"
    fi

    # 4. Reload this shell
    export http_proxy="$WORK_PROXY"
    export https_proxy="$WORK_PROXY"
    export HTTP_PROXY="$WORK_PROXY"
    export HTTPS_PROXY="$WORK_PROXY"
    export no_proxy="$WORK_NO_PROXY"
    export NO_PROXY="$WORK_NO_PROXY"

    # 5. SIGHUP lynx to pick up new proxy
    pkill -HUP lynx 2>/dev/null || true

    log "Work mode active"
}

set_home() {
    log "Switching to HOME mode (direct)"

    # 1. ~/.lynx-proxy — clear it (lynx uses direct connection)
    > "$PROXY_FILE"
    log "Cleared $PROXY_FILE"

    # 2. /etc/environment (needs sudo)
    if [ "$EUID" -ne 0 ]; then
        log "Skipping /etc/environment — re-run with sudo for system-wide proxy"
        log "  sudo $0 home"
    else
        sed -i '/^http_proxy=/d; /^https_proxy=/d; /^HTTP_PROXY=/d; /^HTTPS_PROXY=/d; /^no_proxy=/d; /^NO_PROXY=/d' /etc/environment
        log "Cleared proxy from /etc/environment"
    fi

    # 3. GNOME proxy
    if command -v gsettings &>/dev/null; then
        gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null || true
        log "Set GNOME proxy to none"
    fi

    # 4. Reload this shell
    unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY

    # 5. SIGHUP lynx to pick up no-proxy
    pkill -HUP lynx 2>/dev/null || true

    log "Home mode active"
}

# --- Main ---

if [ -z "$MODE" ]; then
    CURRENT=$(detect_current)
    echo "Current mode: $CURRENT"
    echo ""
    echo "Switch to:"
    echo "  1) Work  (PdaNet proxy $WORK_PROXY)"
    echo "  2) Home  (direct)"
    echo ""
    read -rp "Choice [1/2]: " choice
    case "$choice" in
        1|work|w) MODE="work" ;;
        2|home|h) MODE="home" ;;
        *) die "Invalid choice" ;;
    esac
fi

case "$MODE" in
    work)   set_work ;;
    home)   set_home ;;
    *)      die "Usage: $0 [work|home]" ;;
esac

echo ""
echo "=== Verify ==="
echo "lynx proxy file: $(cat "$PROXY_FILE" 2>/dev/null || echo 'empty')"
echo "http_proxy: ${http_proxy:-unset}"
echo "GNOME proxy mode: $(gsettings get org.gnome.system.proxy mode 2>/dev/null || echo 'unavailable')"
echo ""
echo "New terminals will inherit the current settings."
echo "To reload this terminal: source $0 <mode>"
