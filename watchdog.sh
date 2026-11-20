#!/bin/bash
# Install a 3-minute cron on every box that restarts run.sh if it died.
#
# Auth: SSH_KEY=~/.ssh/id_ed25519 for key auth, otherwise WORKER_PASS.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
FLEET_FILE="${FLEET_FILE:-$HERE/fleet.txt}"
. "$HERE/ssh_common.sh"

for W in $(fleet_hosts); do
    printf '[%s] ' "$W"
    ssh_cmd "$W" '
        cd /opt/wp-bruter || exit 1
        printf "%s\n" "*/3 * * * * root cd /opt/wp-bruter && pgrep -f \"^/bin/bash ./run[.]sh\" >/dev/null || [ -f done ] || nohup ./run.sh \$(cat shard.idx 2>/dev/null || echo 0) >> attack.log 2>&1" > /etc/cron.d/wp-bruter
        chmod 644 /etc/cron.d/wp-bruter
        if pgrep -f "^/bin/bash ./run[.]sh" >/dev/null; then echo "watchdog ok (running)"; elif [ -f done ]; then echo "watchdog ok (finished, cron idle)"; else echo "watchdog ok (run.sh absent — cron will start it)"; fi
    ' 2>/dev/null || echo "watchdog failed"
done
