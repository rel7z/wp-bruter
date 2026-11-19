#!/bin/bash
# Stop wp-bruter and watchdog across the fleet.
#
# 1. Removes /etc/cron.d/wp-bruter so watchdog doesn't revive.
# 2. Sends SIGTERM for graceful shutdown (saves in-flight to progress.txt).
# 3. Falls back to SIGKILL (-9) if processes don't exit cleanly within 5 seconds.
#
# Usage:
#   ./stop.sh            # graceful stop (SIGTERM then SIGKILL if needed)
#   ./stop.sh --force    # immediate SIGKILL (-9)
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
FLEET_FILE="${FLEET_FILE:-$HERE/fleet.txt}"
WORKER_PASS="${WORKER_PASS:-fahrel}"
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

if [ ! -f "$FLEET_FILE" ]; then
    echo "[-] Fleet file not found: $FLEET_FILE" >&2
    exit 1
fi

SSH_OPTS=(-o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=10 -o NumberOfPasswordPrompts=1 -o ControlMaster=auto -o ControlPath="/tmp/wpbruter-%r@%h:%p" -o ControlPersist=60)

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  STOPPING WP-BRUTER FLEET & WATCHDOG                       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo "[*] Fleet file: $FLEET_FILE"
echo "[*] Mode: $( [ $FORCE -eq 1 ] && echo 'FORCE (SIGKILL -9)' || echo 'GRACEFUL (SIGTERM -> 5s -> SIGKILL)' )"
echo "[*] Stopping all workers in parallel..."
echo ""

stop_worker() {
    local host="$1"
    local res
    res=$(sshpass -p "$WORKER_PASS" ssh "${SSH_OPTS[@]}" "root@$host" "
        # 1. Remove watchdog cron first
        rm -f /etc/cron.d/wp-bruter

        # 2. Terminate runner & binary
        pkill -f '^/bin/bash ./run[.]sh' 2>/dev/null
        if [ $FORCE -eq 1 ]; then
            pkill -9 -x wp-bruter 2>/dev/null
        else
            pkill -TERM -x wp-bruter 2>/dev/null
            for _ in \$(seq 1 5); do
                pgrep -x wp-bruter >/dev/null || break
                sleep 1
            done
            pkill -9 -x wp-bruter 2>/dev/null
        fi

        # 3. Report status
        cnt=\$(pgrep -cx wp-bruter 2>/dev/null || echo 0)
        if [ \"\$cnt\" -eq 0 ]; then
            echo 'watchdog removed, process stopped (0 running)'
        else
            echo \"WARNING: \$cnt process(es) still alive\"
        fi
    " 2>&1)
    local rc=$?
    if [ $rc -eq 0 ]; then
        printf "[%-16s] %s\n" "$host" "$res"
    else
        printf "[%-16s] SSH FAILED (timeout/auth error)\n" "$host"
    fi
}

for WORKER in $(grep -Ev '^[[:space:]]*(#|$)' "$FLEET_FILE"); do
    stop_worker "$WORKER" &
done
wait

echo ""
echo "[*] Fleet shutdown routine complete."
