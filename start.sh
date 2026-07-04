#!/bin/bash
# start.sh — Start the full lynx DNS stack
#   - lynx-loop.sh (keep-alive loop for lynx + watchdog)
#   - lynx-watchdog.sh (proxy detection, health checks)
#
# Usage: ./start.sh            # start everything
#        ./start.sh stop       # stop everything
#        ./start.sh status     # check status
#        ./start.sh logs       # tail logs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOOP_LOG="/tmp/lynx-loop.log"
WATCHDOG_LOG="/tmp/lynx-watchdog.log"
LYNX_PID_FILE="/tmp/lynx-stack.pid"

start_stack() {
    if [ -f "$LYNX_PID_FILE" ] && kill -0 "$(cat "$LYNX_PID_FILE")" 2>/dev/null; then
        echo "lynx stack is already running (pid $(cat "$LYNX_PID_FILE"))"
        return
    fi

    nohup "$SCRIPT_DIR/scripts/lynx-loop.sh" > /dev/null 2>&1 &
    echo "$!" > "$LYNX_PID_FILE"
    sleep 2

    if kill -0 "$(cat "$LYNX_PID_FILE")" 2>/dev/null; then
        echo "lynx stack started (pid $(cat "$LYNX_PID_FILE"))"
        echo "  lynx-loop:  $(cat $LYNX_PID_FILE)"
        echo "  watchdog:   $(pgrep -f lynx-watchdog.sh 2>/dev/null || echo 'starting...')"
    else
        echo "FAILED to start lynx stack"
        rm -f "$LYNX_PID_FILE"
        return 1
    fi
}

stop_stack() {
    echo "Stopping lynx stack..."

    # Stop watchdog first
    local watchdog_pid
    watchdog_pid=$(pgrep -f lynx-watchdog.sh 2>/dev/null || true)
    if [ -n "$watchdog_pid" ]; then
        kill "$watchdog_pid" 2>/dev/null || true
        echo "  watchdog stopped"
    fi

    # Stop lynx politely (TERM, then KILL if needed)
    if pgrep -x lynx > /dev/null; then
        pkill -TERM lynx 2>/dev/null || true
        sleep 3
        pkill -9 lynx 2>/dev/null || true
        echo "  lynx stopped"
    fi

    # Stop lynx-loop
    local loop_pid
    if [ -f "$LYNX_PID_FILE" ]; then
        loop_pid=$(cat "$LYNX_PID_FILE")
        kill "$loop_pid" 2>/dev/null || true
        rm -f "$LYNX_PID_FILE"
        echo "  lynx-loop stopped"
    fi

    echo "lynx stack stopped"
}

status_stack() {
    echo "=== lynx stack status ==="
    if [ -f "$LYNX_PID_FILE" ] && kill -0 "$(cat "$LYNX_PID_FILE")" 2>/dev/null; then
        echo "  lynx-loop:  RUNNING (pid $(cat "$LYNX_PID_FILE"))"
    else
        echo "  lynx-loop:  NOT RUNNING"
    fi

    local lynx_pid
    lynx_pid=$(pgrep -x lynx 2>/dev/null || true)
    if [ -n "$lynx_pid" ]; then
        echo "  lynx:       RUNNING (pid $lynx_pid)"
    else
        echo "  lynx:       NOT RUNNING"
    fi

    local watchdog_pid
    watchdog_pid=$(pgrep -f lynx-watchdog.sh 2>/dev/null || true)
    if [ -n "$watchdog_pid" ]; then
        echo "  watchdog:   RUNNING (pid $watchdog_pid)"
    else
        echo "  watchdog:   NOT RUNNING"
    fi

    if ss -tlnp 2>/dev/null | grep -q :5353; then
        echo "  port 5353:  LISTENING"
    else
        echo "  port 5353:  NOT LISTENING"
    fi
    if ss -tlnp 2>/dev/null | grep -q :8085; then
        echo "  port 8085:  LISTENING"
    else
        echo "  port 8085:  NOT LISTENING"
    fi
}

case "${1:-start}" in
    start)
        start_stack
        ;;
    stop)
        stop_stack
        ;;
    restart)
        stop_stack
        sleep 1
        start_stack
        ;;
    status)
        status_stack
        ;;
    logs)
        tail -f /tmp/lynx-loop.log /tmp/lynx-watchdog.log 2>/dev/null || echo "No log files found"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
