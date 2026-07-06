#!/bin/bash
# lynx-loop.sh — Persistent launcher for lynx + watchdog
# Started by start.sh; restarts both lynx and watchdog if they die.
set +e
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$PROJECT_DIR/build/lynx"
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
    "$BIN" --config="$CFG" --log_level=info >> "$LOG" 2>&1 < /dev/null
    RC=$?
    log "lynx exited with code $RC, restarting in 2s..."
    ensure_watchdog
    sleep 0.5
done
