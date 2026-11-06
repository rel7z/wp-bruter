# WP-Bruter

A conservative WordPress credential assessment CLI for systems you own or have explicit permission to test. It discovers public author candidates, expands your password templates, and preserves only verified authentication results.

## Build and run

Requires Go 1.25 or newer.

```sh
go build -o wp-bruter .
./wp-bruter
```

There are **no runtime arguments**. Old options are rejected before any files are opened or network requests are sent. The scanner reads these files from its working directory:

| File | Purpose |
|---|---|
| `wordpress.txt` | HTTP(S) WordPress site roots, one per line |
| `pass.txt` | Explicit passwords and placeholder templates, one per line |
| `results.txt` | Appended verified credentials, owner-only permissions |
| `run-report.jsonl` | Appended per-site JSON reports, owner-only permissions |

Blank lines and lines whose first non-space character is `#` are ignored. Password whitespace is otherwise preserved. Sites without a scheme get `https://`; duplicate normalized URLs are tested once. Targets cannot contain embedded credentials, query parameters, or fragments. Include the installation path for WordPress sites hosted in subdirectories.

Results retain `site | username | password` format. Backslashes, pipes, and line breaks inside fields are escaped. Existing results are preserved, including between runs. Writes and flushes are checked; a save failure cancels the scan and exits with an error. Results and candidate previews contain passwords; ordinary diagnostics and run reports do not.

## Fixed behavior

| Setting | Default |
|---|---|
| Concurrent site workers | 10 |
| Authentication concurrency per site | 1 |
| Minimum interval between authentication attempts | 1 second |
| Request timeout | 5 seconds |
| Slow-response cutoff, including response body | 3 seconds |
| Maximum candidates attempted per user | 50 |
| Transient read-only discovery retries | 1 |
| Authentication submission retries | 0 |
| REST discovery budget | Two pages of ten users per route |
| Author redirect discovery | IDs 1–10 |
| Redirect limit | Three same-origin hops |
| Maximum response body | 2 MiB |

Separate sites run concurrently and reuse HTTP connections. Password attempts within a site are sequential so there are no queued authentication submissions after blocking is detected. XML-RPC multicall is not used: multicall batches attempts against one server, not separate sites, and prevents stopping between the individual attempts in a batch.

The scanner deliberately skips any recognizable WAF presence, including normal pages with Cloudflare or Sucuri headers. It also skips known Wordfence, Imunify, ModSecurity, CAPTCHA, and challenge signatures. HTTP 403/406 stop as protection signals; 429 stops as a rate limit. HTTP 503 stops as unavailable without claiming a WAF. Timeouts and responses beyond the cutoff stop as slow. No challenges are solved and no protection bypass is attempted. Known signatures cannot identify every invisible WAF.

Only public WordPress REST user slugs and author redirects are used for discovery. The alternate REST route is attempted if the first yields no usable candidates. Redirects are parsed as URLs, and sources are deduplicated. Discovered slugs are reported as `unconfirmed_slug` until a matching login is verified: a public author slug is not proof of a login name. No discoverable users means the site is skipped.

## Password candidates

Expanded `pass.txt` entries and generated variations are combined and deduplicated, then ranked together. Neither source nor position in `pass.txt` receives priority. Duplicate candidates retain `passlist+generated` provenance when they occur in both sources. Ranking favors exact username/site matches, simple contextual variations, current-year variations ahead of previous-year ones, and the existing common-word vocabulary. Short length is a small secondary signal; whitespace, control characters, and unexpanded placeholders reduce priority. The strongest contextual match wins without double-counting identical username/site labels. Equal scores sort lexically for reproducibility. Scores describe heuristic priority, not measured probabilities. Automatic generation retains the existing bounded username/site/year variations; it does not claim statistical success probabilities. Site names use a public suffix list, including domains such as `example.co.id`. Unicode transformations preserve valid characters.

The bundled `pass.txt` contains 4,828 unique entries, including 3,712 supported templates. Its synthetic expansion covers contextual prefixes/suffixes, username/site combinations, role and login vocabulary, and numeric/keyboard patterns. All 389 original entries are preserved; `pass.before-expansion.txt` keeps the original file. `wordlist-metadata.json` records category counts and file hashes. This is broader coverage, not an empirically measured "best" wordlist; only the top 50 expanded, ranked candidates are attempted per user.

Uppercase and lowercase spellings of these placeholders are supported:

| Placeholder | Value |
|---|---|
| `[WPADMIN]` | Candidate username |
| `[SITENAME]`, `[DOMAINNAME]` | Registrable domain's label |
| `[YEAR]`, `[YEAR2]` | Current four-digit/two-digit year |
| `[WPADMIN_LEET]`, `[SITENAME_LEET]`, `[DOMAINNAME_LEET]` | Existing leet substitutions |
| `[WPADMIN_CAP]`, `[SITENAME_CAP]`, `[DOMAINNAME_CAP]` | First character capitalized |

An IP-address target has no domain label. Only the first 50 unique candidates are tried per user; the limit is applied after ranking the entire combined pool, so a long wordlist cannot automatically crowd out generated candidates. An empty `pass.txt` permits automatic candidates. A missing file is an input error.

## Offline preview

Create `preview-context.json` with an explicit site and username:

```json
{"site":"https://example.com","username":"admin"}
```

```sh
go run ./cmd/preview
```

This separate program has no runtime arguments and makes **no network requests**, even when the context names a public site. It reads `pass.txt` and writes `candidate-preview.jsonl` with position, password, source, heuristic score, scoring reasons, and whether the candidate is within the 50-attempt limit. The preview uses the same ranking function as the scanner. The preview file is replaced atomically with owner-only permissions.

## Authentication and reporting

Login redirects and cookie names are preliminary evidence. Each candidate gets an isolated cookie jar containing only the initial anonymous cookies, including WordPress's test cookie. Multiple `Set-Cookie` headers and expiration are handled by the HTTP cookie jar.

A result is saved only when a live WordPress logged-in cookie accompanies an authenticated profile page with the expected login identity, a positive user ID, a profile nonce, and a nonce-bearing logout link. HTML pages explicitly request HTML: WordPress suppresses its admin bar on JSON requests ([WordPress source](https://github.com/WordPress/WordPress/blob/master/wp-includes/admin-bar.php)). The anonymous profile baseline must not already expose those identity markers. Generic dashboard text, larger cookies, expired cookies, or redirects alone never verify a password. Customized login/profile flows, different login identities, and unrecognized responses stop as inconclusive rather than generating a success or rejection guess.

Each JSONL report records the outcome, evidence, discovered candidate usernames and their sources, HTTP request count, attempted/available/generated candidate counts, start time, and duration. Available candidate counts cover users whose password loop was reached. No passwords, cookie values, response bodies, or raw transport errors enter the report.

Outcomes: `not_wordpress`, `waf_present`, `rate_limited`, `slow`, `network_error`, `no_users`, `verified_success`, `candidates_exhausted`, `attempt_limit`, `inconclusive`, and `cancelled`. A completed run can have skipped or inconclusive sites; inspect the report rather than interpreting an empty result file as proof that all passwords failed.

## Validation

```sh
go test ./...
go test -race ./...
go vet ./...
```

Tests use local mock servers and cover block detection, cancellation, false successes, cookie handling, candidate budgets, pacing, Unicode, discovery parsing, file permissions, and persistence failures. The real WordPress integration test is opt-in:

```sh
bash lab/setup.sh
WP_BRUTER_LAB=1 go test -run TestWordPressLab -v .
```

The dedicated Docker project binds only to loopback. Port 18080 hosts WordPress; 18081 is a normal page carrying a Cloudflare header; 18082 simulates Wordfence; 18083 returns 429; 18084 deliberately slows WordPress responses. The script initializes the dedicated lab's `admin` user with a known fixture password and publishes its sample author post. It does not edit the scanner's target or password files or modify the separate `dvwp` environment. External WordPress HTTP calls and background updates are disabled in this dedicated fixture to make verification deterministic. Images must be available locally or downloadable by Docker.

The integration test checks rejected ranked candidates followed by the verified fixture password, and confirms that protected fixtures receive no authentication attempts. No public sites are probed by the test suite. Public accessibility or a bug-bounty listing alone does not authorize credential guessing.

Stop the dedicated lab when finished:

```sh
docker compose -f lab/docker-compose.yml down
```

Database and WordPress volumes are retained. Keep this intentionally weak-credential lab on loopback.
