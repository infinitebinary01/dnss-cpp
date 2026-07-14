#!/bin/bash
# lynx-watchdog.sh — Health monitor for lynx
# Checks DNS health every 10s.
# Network/proxy detection is handled by 90-lynx-network NM dispatcher.
set +e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

LOG="/tmp/lynx-watchdog.log"

log() {
    echo "[$(date '+%H:%M:%S')] $*" >> "$LOG"
}

check_health() {
    local result elapsed
    T=$(date +%s%N)
    result=$(dig +short +time=5 google.com @127.0.0.1 -p 5353 2>&1)
    elapsed=$((($(date +%s%N) - T) / 1000000))
    if echo "$result" | grep -qP '^\d+\.\d+\.\d+\.\d+$'; then
        if [ "$elapsed" -lt 10000 ]; then
            return 0
        fi
    fi
    return 1
}

echo "lynx-watchdog started (pid $$)" >> "$LOG"

while true; do
    sleep 10
    if pgrep -x lynx > /dev/null 2>&1; then
        if check_health; then
            : # healthy
        fi
    fi
done
