#!/bin/bash
# Lynx DNS Test Suite — runs all test suites, generates HTML report
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
JSON_REPORT="$SCRIPT_DIR/test-report.json"
HTML_REPORT="$SCRIPT_DIR/test-report.html"

SERVER="127.0.0.1"
PORT="5353"
MONITOR_PORT="8085"

PASS=0
FAIL=0
TOTAL=0

red()   { tput setaf 1; cat; tput sgr0; }
green() { tput setaf 2; cat; tput sgr0; }
bold()  { tput bold; cat; tput sgr0; }

banner() {
    echo ""
    echo "================================================"
    echo "  Lynx DNS Test Suite"
    echo "================================================"
    echo "  Server: $SERVER:$PORT"
    echo "  Monitor: http://$SERVER:$MONITOR_PORT"
    echo "  Time: $(date)"
    echo "================================================"
    echo ""
}

check_lynx() {
    if ! pgrep -x lynx > /dev/null 2>&1; then
        echo "✗ lynx is NOT running" | red
        echo "  Start it with: $PROJECT_DIR/build-rel2/lynx --config=$PROJECT_DIR/config.json"
        exit 1
    fi
    echo "✓ lynx is running (pid $(pgrep -x lynx))" | green
    if curl -sf "http://$SERVER:$MONITOR_PORT/api/stats" > /dev/null 2>&1; then
        echo "✓ Monitoring API is responding" | green
    else
        echo "✗ Monitoring API is not responding" | red
        exit 1
    fi
    echo ""
}

run_suite() {
    local name="$1"
    local script="$2"
    TOTAL=$((TOTAL + 1))
    echo "────────────────────────────────────────────────"
    echo "  Suite: $name" | bold
    echo "────────────────────────────────────────────────"
    if python3 "$script"; then
        PASS=$((PASS + 1))
        echo "  Suite passed" | green
    else
        FAIL=$((FAIL + 1))
        echo "  Suite FAILED" | red
    fi
    echo ""
}

html_report() {
    python3 "$SCRIPT_DIR/report.py"
    echo "  HTML Report: $HTML_REPORT" | green
}

summary() {
    local status="PASS"
    local color=green
    if [ "$FAIL" -gt 0 ]; then
        status="FAIL"
        color=red
    fi
    # JSON summary
    cat > "$JSON_REPORT" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "suites_total": $TOTAL,
  "suites_passed": $PASS,
  "suites_failed": $FAIL,
  "status": "$status",
  "server": "$SERVER:$PORT"
}
EOF
    echo ""
    echo "================================================"
    echo "  Test Summary" | bold
    echo "================================================"
    echo "  Total:  $TOTAL"
    echo "  Passed: $PASS"  | green
    echo "  Failed: $FAIL"  | red
    echo "  Status: $status" | $color
    echo "  JSON:   $JSON_REPORT"
    echo "  HTML:   $HTML_REPORT"
    echo "================================================"
    echo ""
}

# ── Main ──────────────────────────────────────────────

banner
check_lynx

run_suite "Functional"     "$SCRIPT_DIR/functional.py"
run_suite "Performance"    "$SCRIPT_DIR/performance.py"
run_suite "Resilience"     "$SCRIPT_DIR/resilience.py"

html_report
summary

exit $FAIL
