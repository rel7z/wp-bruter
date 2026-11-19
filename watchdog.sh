#!/bin/bash
# Install a 3-minute cron on every box that restarts run.sh if it died.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
WORKER_PASS="${WORKER_PASS:-fahrel}"
SSH_OPTS=(-o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=15 -o NumberOfPasswordPrompts=1 -o ControlMaster=auto -o ControlPath="/tmp/wpbruter-%r@%h:%p" -o ControlPersist=120)
for W in $(grep -Ev '^[[:space:]]*(#|$)' "${FLEET_FILE:-$HERE/fleet.txt}"); do
    printf '[%s] ' "$W"
    sshpass -p "$WORKER_PASS" ssh "${SSH_OPTS[@]}" "root@$W" '
        cd /opt/wp-bruter || exit 1
        printf "%s\n" "*/3 * * * * root cd /opt/wp-bruter && pgrep -f \"^/bin/bash ./run[.]sh\" >/dev/null || [ -f done ] || nohup ./run.sh \$(cat shard.idx 2>/dev/null || echo 0) >> attack.log 2>&1" > /etc/cron.d/wp-bruter
        chmod 644 /etc/cron.d/wp-bruter
        if pgrep -f "^/bin/bash ./run[.]sh" >/dev/null; then echo "watchdog ok (running)"; elif [ -f done ]; then echo "watchdog ok (finished, cron idle)"; else echo "watchdog ok (run.sh absent — cron will start it)"; fi
    ' 2>/dev/null || echo "watchdog failed"
done
