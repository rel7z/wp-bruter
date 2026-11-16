#!/bin/bash
# Monitor the worker fleet's diagnostic log and results.
# Workers only accept password auth; set WORKER_PASS to override.
set -u

WORKER_PASS="${WORKER_PASS:-fahrel}"
WORKERS=(
    "68.183.184.203"
    "139.59.114.182"
    "159.65.138.79"
    "206.189.90.210"
    "188.166.252.160"
)
SSH_OPTS=(-o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=10)

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  WORDPRESS BRUTER - DIAGNOSTIC MONITOR                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

for WORKER in "${WORKERS[@]}"; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Worker: $WORKER"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    sshpass -p "$WORKER_PASS" ssh "${SSH_OPTS[@]}" "root@$WORKER" "
        echo '📊 SUMMARY:'
        echo ''
        echo -n '  progress: '; wc -l < /opt/wp-bruter/progress.txt 2>/dev/null
        echo -n "  shard:    "; cat /root/wordpress.s* 2>/dev/null | wc -l
        echo -n '  creds:    '; wc -l < /opt/wp-bruter/creds.txt 2>/dev/null
        echo -n '  results:  '; wc -l < /opt/wp-bruter/results.txt 2>/dev/null
        echo ''
        echo '  last outcomes:'
        awk -F'\t' 'NF>1 && $2 != "verified_success"' /opt/wp-bruter/progress.txt 2>/dev/null | tail -20 | cut -f2 | sort | uniq -c | sed 's/^/    /'
        echo ''
        echo '📈 Recent activity (debug.log):'
        tail -10 /opt/wp-bruter/debug.log 2>/dev/null | sed 's/^/  /'
        echo ''
        echo '⚠️  Common issues (whole log):'
        echo -n '  BLOCKED: '; grep -c '\] BLOCKED |' /opt/wp-bruter/debug.log 2>/dev/null
        echo -n '  WAF:     '; grep -c '\] WAF |' /opt/wp-bruter/debug.log 2>/dev/null
        echo -n '  NET_ERR: '; grep -c '\] NET_ERR |' /opt/wp-bruter/debug.log 2>/dev/null
        echo -n '  dropped: '; grep -c "\[DIAG\] dropped" /opt/wp-bruter/debug.log 2>/dev/null
        echo ''
        echo '  log size (MB):'; echo \$(( \$(stat -c%s /opt/wp-bruter/debug.log 2>/dev/null || echo 0) / 1048576 ))
        echo ''
        echo 'Process status:'
        pgrep -a wp-bruter | head -1 | sed 's/^/  /' || echo '  (not running)'
    " 2>/dev/null

    echo ""
done

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  END OF REPORT                                             ║"
echo "╚════════════════════════════════════════════════════════════╝"
