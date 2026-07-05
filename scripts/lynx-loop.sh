#!/bin/bash
# lynx-loop.sh — Persistent launcher for lynx + watchdog
# Started by start.sh; restarts both lynx and watchdog if they die.
set +e
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$PROJECT_DIR/build/lynx"
CFG="$PROJECT_DIR/config.json"
LOG="/tmp/lynx-loop.log"
WATCHDOG="$PROJECT_DIR/scripts/lynx-watchdog.sh"

log() { echo "[$(date '+%H:%M:%S')] $*" >> "$LOG"; }

# Start watchdog in background if not running
ensure_watchdog() {
    if ! pgrep -f "lynx-watchdog.sh" > /dev/null 2>&1; then
        nohup "$WATCHDOG" --config="$CFG" > /dev/null 2>&1 &
        log "watchdog started (pid $!)"
    fi
}

log "lynx-loop started (pid $$)"
ensure_watchdog

while true; do
    log "starting lynx..."
    "$BIN" --config="$CFG" --log_level=info >> "$LOG" 2>&1 < /dev/null
    RC=$?
    log "lynx exited with code $RC, restarting in 2s..."
    ensure_watchdog
    sleep 0.5
done
