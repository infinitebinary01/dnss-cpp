#!/bin/bash
# lynx-watchdog.sh — Health monitor + proxy auto-detect
# Every 10s: probes proxy, checks DNS health, updates env files.
# Does NOT restart lynx — lynx-loop handles that.
set +e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEFAULT_CONFIG="$PROJECT_DIR/config.json"
CONFIG="$DEFAULT_CONFIG"
for arg in "$@"; do
    case "$arg" in --config=*) CONFIG="${arg#--config=}";; esac
done

LOG="/tmp/lynx-watchdog.log"
PROXY_FILE="$HOME/.lynx-proxy"
PROXY_ENV="$HOME/.proxy-env"
PROXY_HOST="<IP ADDRESS>"
PROXY_PORT="8000"
PROXY_URL="http://$PROXY_HOST:$PROXY_PORT/"
NO_PROXY="localhost,127.0.0.1,::1,192.168.0.0/16,10.0.0.0/8"

LAST_MODE=""

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

auto_detect() {
    local mode
    if timeout 2 bash -c "echo > /dev/tcp/$PROXY_HOST/$PROXY_PORT" 2>/dev/null; then
        mode="work"
    else
        mode="home"
    fi
    if [ "$mode" = "$LAST_MODE" ]; then
        return
    fi
    LAST_MODE="$mode"
    if [ "$mode" = "work" ]; then
        echo "$PROXY_URL" > "$PROXY_FILE"
        cat > "$PROXY_ENV" <<EOF
export http_proxy=$PROXY_URL
export https_proxy=$PROXY_URL
export HTTP_PROXY=$PROXY_URL
export HTTPS_PROXY=$PROXY_URL
export no_proxy=$NO_PROXY
export NO_PROXY=$NO_PROXY
EOF
        log "Auto-detect: WORK proxy $PROXY_URL"
    else
        > "$PROXY_FILE"
        cat > "$PROXY_ENV" <<EOF
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
unset no_proxy NO_PROXY
EOF
        log "Auto-detect: HOME (direct)"
    fi
    pkill -HUP lynx 2>/dev/null || true
}

echo "lynx-watchdog started (pid $$)" >> "$LOG"

while true; do
    sleep 10
    auto_detect
    if pgrep -x lynx > /dev/null 2>&1; then
        if check_health; then
            : # healthy
        fi
    fi
done
