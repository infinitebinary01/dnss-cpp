#!/bin/bash
# lynx-loop.sh — Persistent launcher for lynx + watchdog
# Started by start.sh; restarts both lynx and watchdog if they die.
set +e
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$PROJECT_DIR/build-rel2/lynx"
CFG="$PROJECT_DIR/config.json"
LOG="/tmp/lynx-loop.log"
WATCHDOG="$PROJECT_DIR/scripts/lynx-watchdog.sh"

WATCHDOG_PID="/tmp/lynx-watchdog.pid"

log() { echo "[$(date '+%H:%M:%S')] $*" >> "$LOG"; }

# Start watchdog in background if not running (pid file prevents duplicates)
ensure_watchdog() {
    if [ -f "$WATCHDOG_PID" ] && kill -0 $(cat "$WATCHDOG_PID") 2>/dev/null; then
        return
    fi
    rm -f "$WATCHDOG_PID"
    nohup "$WATCHDOG" --config="$CFG" > /dev/null 2>&1 &
    echo $! > "$WATCHDOG_PID"
    log "watchdog started (pid $!)"
}

log "lynx-loop started (pid $$)"
ensure_watchdog

while true; do
    log "starting lynx..."
    # Source cached proxy env so lynx gets the right proxy immediately
    [ -f "$HOME/.proxy-env" ] && . "$HOME/.proxy-env"

    # Probe proxy before starting — if unreachable, clear it so lynx starts direct.
    # This avoids a startup race where ~/.proxy-env has stale proxy from last session
    # but the NM dispatcher hasn't run yet to clear it on this network.
    PROXY_URL_FILE="$HOME/.lynx-proxy-url"
    if [ -f "$PROXY_URL_FILE" ]; then
        PURL=$(head -1 "$PROXY_URL_FILE" | tr -d '\n\r')
        if [ -n "$PURL" ]; then
            PHOST=$(echo "$PURL" | sed -E 's|https?://([^:/]+).*|\1|')
            PPORT=$(echo "$PURL" | sed -E 's|.*:([0-9]+)/?$|\1|')
            if timeout 2 bash -c "echo > /dev/tcp/$PHOST/$PPORT" 2>/dev/null; then
                echo "$PURL" > "$HOME/.lynx-proxy"
                export http_proxy="$PURL" https_proxy="$PURL" HTTP_PROXY="$PURL" HTTPS_PROXY="$PURL"
                export no_proxy="localhost,127.0.0.1,::1" NO_PROXY="localhost,127.0.0.1,::1"
                log "proxy $PURL reachable"
            else
                unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY
                > "$HOME/.lynx-proxy"
                log "proxy $PURL unreachable — starting direct"
            fi
        fi
    fi

    "$BIN" --config="$CFG" --log_level=info >> "$LOG" 2>&1 < /dev/null
    RC=$?
    log "lynx exited with code $RC, restarting in 2s..."
    ensure_watchdog
    sleep 0.5
done
