#!/bin/bash
# dnss-monitor — start C++ dnss and monitor for N minutes
# Usage: sudo bash dnss-monitor.sh [minutes]

MINUTES=${1:-5}
BINARY=./build/dnss
LOG=/tmp/dnss-mon.log
CPP_LOG=/tmp/dnss-cpp.log

echo "=== dnss-monitor ==="
date

# Kill everything
systemctl stop dnss.service 2>/dev/null
for p in $(pgrep -f "build/dnss" 2>/dev/null); do kill $p 2>/dev/null; done
for p in $(pgrep -x dnss 2>/dev/null); do kill $p 2>/dev/null; done
sleep 2
while ss -tuln | grep -q ":53 "; do sleep 1; done
echo "Port 53 free"

# Start C++ dnss
export https_proxy=http://PROXY_IP:PROXY_PORT/
rm -f "$CPP_LOG"
setsid "$BINARY" \
  --dns_listen_addr=":53" \
  --enable_dns_to_https \
  --https_upstream="https://1.1.1.1/dns-query" \
  --log_level=info \
  >> "$CPP_LOG" 2>&1 < /dev/null &
sleep 2
PID=$(pgrep -f "build/dnss" 2>/dev/null | head -1)
BOUND=$(ss -tuln | grep ":53 ")
if [ -z "$PID" ] || [ -z "$BOUND" ]; then
  echo "FAILED to start"; cat "$CPP_LOG"; exit 1
fi
echo "C++ dnss PID $PID"
echo "$BOUND"

# Monitoring loop
echo "=== Monitoring for ${MINUTES}min ($((MINUTES * 4)) queries, 15s apart) ==="
> "$LOG"
INTERVAL=15
MAX=$(( MINUTES * 60 / INTERVAL ))
FAIL=0
for i in $(seq 1 $MAX); do
  T=$(date +%H:%M:%S)
  R=$(dig @127.0.0.1 +timeout=5 google.com A +short 2>&1)
  if [ -z "$R" ] || echo "$R" | grep -qi "timeout\|fail\|no server"; then
    echo "[$T] Q$i: FAIL ($R)" | tee -a "$LOG"
    FAIL=$((FAIL + 1))
  else
    echo "[$T] Q$i: OK ($R)" | tee -a "$LOG"
  fi
  kill -0 $PID 2>/dev/null || {
    echo "[$T] PROCESS DIED!" | tee -a "$LOG"
    break
  }
  sleep $INTERVAL
done

echo "=== Done ===" | tee -a "$LOG"
echo "$((i-1)) queries, $FAIL failures" | tee -a "$LOG"
kill -0 $PID 2>/dev/null && echo "Process: ALIVE" | tee -a "$LOG" || echo "Process: DEAD" | tee -a "$LOG"
echo "=== C++ dnss log (last 20 lines) ==="
tail -20 "$CPP_LOG"
echo "=== Port 53 ==="
ss -tuln | grep ":53 "
