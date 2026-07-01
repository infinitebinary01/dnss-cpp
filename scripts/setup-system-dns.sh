#!/bin/bash
# setup-system-dns.sh — Configure this machine to use lynx as system DNS resolver
#
# Usage:
#   sudo ./setup-system-dns.sh              # Configure system DNS → lynx on port 53
#   sudo ./setup-system-dns.sh --restore    # Restore original DNS settings
#
# This script:
#   1. Grants cap_net_bind_service so lynx can bind to port 53 without root
#   2. Detects your DNS manager (NetworkManager / systemd-resolved / resolvconf)
#   3. Sets the system DNS server to 127.0.0.1
#   4. Saves a backup of /etc/resolv.conf for --restore

set -euo pipefail

BINARY="${BINARY:-$(dirname "$0")/../build/lynx}"
BACKUP_FILE="/etc/resolv.conf.lynx-backup"
RESTORE="${1:-}"

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo (or as root)."
    exit 1
fi

# --- Grant capability ---
if [ -f "$BINARY" ]; then
    setcap cap_net_bind_service=+ep "$BINARY" 2>/dev/null || \
        echo "Warning: could not setcap on $BINARY (not critical if running as root)"
    echo "[OK] cap_net_bind_service set on $(basename "$BINARY")"
else
    echo "Warning: $BINARY not found — build lynx first, or set BINARY= env var"
fi

# --- Detect DNS manager ---
detect_dns_manager() {
    if command -v resolvectl &>/dev/null && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo "systemd-resolved"
    elif command -v nmcli &>/dev/null && systemctl is-active --quiet NetworkManager 2>/dev/null; then
        echo "networkmanager"
    elif command -v resolvconf &>/dev/null; then
        echo "resolvconf"
    else
        echo "static"
    fi
}

get_active_nm_connection() {
    nmcli -t -f NAME con show --active 2>/dev/null | head -1
}

restore_dns() {
    echo "Restoring DNS..."
    if [ -f "$BACKUP_FILE" ]; then
        cp "$BACKUP_FILE" /etc/resolv.conf
        echo "[OK] Restored /etc/resolv.conf from backup"
    else
        echo "No backup found at $BACKUP_FILE — skipping"
    fi
    exit 0
}

if [ "$RESTORE" = "--restore" ]; then
    restore_dns
fi

# --- Backup current resolv.conf ---
cp /etc/resolv.conf "$BACKUP_FILE"
echo "[OK] Backed up /etc/resolv.conf → $BACKUP_FILE"

MANAGER=$(detect_dns_manager)
echo "[INFO] DNS manager: $MANAGER"

case "$MANAGER" in
    networkmanager)
        CONN=$(get_active_nm_connection)
        if [ -z "$CONN" ]; then
            echo "No active NetworkManager connection found."
            exit 1
        fi
        echo "[INFO] Configuring connection: $CONN"
        nmcli con mod "$CONN" ipv4.ignore-auto-dns yes
        nmcli con mod "$CONN" ipv4.dns "127.0.0.1"
        nmcli con down "$CONN" 2>/dev/null || true
        nmcli con up "$CONN"
        echo "[OK] DNS set to 127.0.0.1 via NetworkManager"
        ;;

    systemd-resolved)
        resolvectl dns "" 127.0.0.1
        resolvectl domain "" "~."
        echo "[OK] DNS set to 127.0.0.1 via systemd-resolved"
        ;;

    resolvconf)
        echo "nameserver 127.0.0.1" | resolvconf -a lo.lynx
        echo "[OK] DNS set to 127.0.0.1 via resolvconf"
        ;;

    static)
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        echo "[OK] DNS set to 127.0.0.1 (static /etc/resolv.conf)"
        ;;
esac

# Force-write /etc/resolv.conf if it doesn't already point to 127.0.0.1
# (handles custom managers like dnss-wrapper that bypass NetworkManager)
if ! grep -q "nameserver 127.0.0.1" /etc/resolv.conf 2>/dev/null; then
    echo "[INFO] /etc/resolv.conf not updated by DNS manager — writing directly"
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    echo "[OK] /etc/resolv.conf updated to use 127.0.0.1"
fi

echo ""
echo "=== Verification ==="
echo "System DNS:"
cat /etc/resolv.conf
echo ""
echo "lynx should be running on port 53 — restart if needed:"
echo "  pkill lynx && ./build/lynx --config=config.json"
echo ""
echo "To restore original DNS: sudo ./scripts/setup-system-dns.sh --restore"
