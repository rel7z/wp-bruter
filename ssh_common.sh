#!/bin/bash
# Shared SSH plumbing for the fleet scripts. Source it, do not run it.
#
# Two auth modes, chosen by SSH_KEY:
#   SSH_KEY=/path/key   key auth (root@, port 22)
#   SSH_KEY= (unset)    sshpass password auth with WORKER_PASS, default fahrel
#
# SSH_USER / SSH_PORT override the defaults root / 22.
set -u

SSH_USER="${SSH_USER:-root}"
SSH_PORT="${SSH_PORT:-22}"
WORKER_PASS="${WORKER_PASS:-fahrel}"
SSH_KEY="${SSH_KEY:-}"

SSH_OPTS=(
    -o StrictHostKeyChecking=no
    -o ConnectTimeout=15
    -o ServerAliveInterval=5
    -o ServerAliveCountMax=6
    -o IPQoS=throughput
    -o NumberOfPasswordPrompts=1
    -o ControlMaster=auto
    -o ControlPath="/tmp/wpbruter-%r@%h:%p"
    -o ControlPersist=120
    -p "$SSH_PORT"
)
if [ -n "$SSH_KEY" ]; then
    SSH_OPTS+=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o BatchMode=yes)
else
    SSH_OPTS+=(-o PreferredAuthentications=password -o PubkeyAuthentication=no)
fi

# ssh_cmd <host> <command...>. One muxed connection per host plus retries: a
# busy box throttles bursts of auth and would otherwise fail the call.
ssh_cmd() {
    local host="$1" try
    shift
    for try in 1 2 3; do
        if [ -n "$SSH_KEY" ]; then
            ssh "${SSH_OPTS[@]}" "$SSH_USER@$host" "$@" && return 0
        else
            sshpass -p "$WORKER_PASS" ssh "${SSH_OPTS[@]}" "$SSH_USER@$host" "$@" && return 0
        fi
        sleep 2
    done
    return 1
}

scp_cmd() {
    local src="$1" host="$2" dest="$3" try
    for try in 1 2 3; do
        if [ -n "$SSH_KEY" ]; then
            scp -O "${SSH_OPTS[@]}" "$src" "$SSH_USER@$host:$dest" && return 0
        else
            sshpass -p "$WORKER_PASS" scp -O "${SSH_OPTS[@]}" "$src" "$SSH_USER@$host:$dest" && return 0
        fi
        sleep 2
    done
    return 1
}

# fleet_hosts prints the fleet file without comments or blank lines.
fleet_hosts() {
    grep -Ev '^[[:space:]]*(#|$)' "${FLEET_FILE:-$(dirname "$0")/fleet.txt}"
}
