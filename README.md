# wp-bruter fleet

## Fleet

`fleet.txt` — one host per line, `root` password `fahrel` (or `WORKER_PASS`).
Every script reads it. Shard index is tied to the line position, so a host that
is down keeps its shard for the next deploy instead of renumbering the fleet
(a renumber would invalidate every box's `progress.txt`).

## Spread a Drive list

```
./spread.sh <drive-link-or-id>          # download, cache, shard, deploy
./spread.sh <drive-link-or-id> --fetch  # download only
./spread.sh --local lists/foo.txt       # deploy an already-downloaded file
```

List is cached under `lists/<drive-id>.txt`, CR-stripped, trimmed,
deduplicated and checked for non-URL lines before any host is touched.

## Deploy / monitor / verify

```
./deploy.sh                 # same as spread.sh --local <LOCAL_SITES>
./monitor.sh                # per-box progress, outcome histogram, process state
python3 tools/verify_creds.py --collect --ssh-pass fahrel
```

## Tuning

`WORKERS_PER_BOX` (3000), `ACTIVE_PER_BOX` (2500), `PREP_PER_BOX` (768),
`TIMEOUT` seconds (12), `PHASES` (`150 500 0`), `LOCAL_PASS` (`pass.txt`).
Measured on 4 vCPU/8 GB boxes: ~450 attempts/s at load ~3. A 5s timeout marked
43% of attempts as dead sites although they answered in 2.5-6.5s.

Progress survives redeploys while the shard is unchanged; it is wiped when the
shard content changes. `run.sh` retries a phase up to 5 times (fasthttp can
still panic), raises `RLIMIT_NOFILE` to 262144 and rotates `attack.log` at
100 MB. Results land in `/opt/wp-bruter/creds.txt` on each box.
