#!/usr/bin/env python3
"""Assert that PUBLISHED compliance evidence is fresh — the check that was missing.

The policy has always been that published reporting is less than 24 hours old.
Nothing enforced it. `check_f_freshness` in scripts/reconcile.py verifies that the
*staged* signal carries the current commit and has an `emitted_at` at all; it has
no staleness threshold and never looks at the live edge. So when the nightly
deploy started failing, the served artifacts simply stopped moving and every gate
stayed green — twelve days of rot, silently.

This reads the artifact a third party would read, over the public URL, and fails
loudly if its `emitted_at` is older than the threshold. It is deliberately
AWS-free and dependency-free: it proves the *published* claim, not the build's
opinion of it.

It doubles as the post-publish edge check. `--expect-sha256` asserts the bytes
being served are the bytes just built, and `--retries` rides out CDN invalidation
propagation, so one invocation answers both "did my publish reach the edge" and
"is what the edge serves inside the freshness policy".

Exit codes: 0 fresh (and matching, if --expect-sha256), 1 stale/mismatched,
2 the artifact could not be fetched or parsed.
"""

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_URL = "https://samaydlette.com/.well-known/vdr-report.json"
DEFAULT_MAX_AGE_HOURS = 24.0


def fetch(url, timeout=30):
    """Return the raw bytes at url. Cache-busting is the caller's problem: we
    want to see exactly what a third party would get."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "samaydlette-evidence-freshness/1",
        # Ask intermediaries not to hand us a cached copy; a stale intermediary
        # would make this check answer a question nobody asked.
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https/file scheme, operator-supplied
        return resp.read()


def parse_emitted_at(raw):
    """Pull `emitted_at` out of the artifact and return it as an aware datetime."""
    doc = json.loads(raw)
    value = doc.get("emitted_at")
    if not value:
        raise ValueError("artifact carries no emitted_at")
    # Both forms occur in the published set: '...Z' (KSI signal) and an
    # explicit +00:00 offset (VDR). fromisoformat only learned 'Z' in 3.11.
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    emitted = datetime.fromisoformat(value)
    if emitted.tzinfo is None:
        emitted = emitted.replace(tzinfo=timezone.utc)
    return emitted


def check_once(url, max_age_hours, expect_sha256, now):
    """One attempt. Returns (ok, message, age_hours_or_None)."""
    try:
        raw = fetch(url)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        return None, f"could not fetch {url}: {exc}", None

    if expect_sha256:
        got = hashlib.sha256(raw).hexdigest()
        if got != expect_sha256:
            return False, (f"served bytes do not match the build "
                           f"(built {expect_sha256[:12]}…, served {got[:12]}…)"), None

    try:
        emitted = parse_emitted_at(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        return None, f"could not read emitted_at from {url}: {exc}", None

    age_hours = (now() - emitted).total_seconds() / 3600.0
    if age_hours > max_age_hours:
        return False, (f"published evidence is {age_hours:.1f}h old "
                       f"(policy: under {max_age_hours:g}h) — emitted_at {emitted.isoformat()}"), age_hours
    return True, (f"published evidence is {age_hours:.1f}h old "
                  f"(policy: under {max_age_hours:g}h) — emitted_at {emitted.isoformat()}"), age_hours


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=DEFAULT_URL,
                    help=f"published artifact to check (default: {DEFAULT_URL})")
    ap.add_argument("--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS,
                    help="fail if emitted_at is older than this (default: 24)")
    ap.add_argument("--expect-sha256", default=None,
                    help="also assert the served bytes hash to this (post-publish edge check)")
    ap.add_argument("--retries", type=int, default=0,
                    help="retry this many times before failing (rides out CDN propagation)")
    ap.add_argument("--retry-delay", type=float, default=20.0,
                    help="seconds between retries (default: 20)")
    args = ap.parse_args(argv)

    def now():
        return datetime.now(timezone.utc)

    attempts = args.retries + 1
    ok, message, _age = None, "no attempt made", None
    for attempt in range(1, attempts + 1):
        ok, message, _age = check_once(args.url, args.max_age_hours,
                                       args.expect_sha256, now)
        if ok:
            print(f"OK: {message}")
            return 0
        if attempt < attempts:
            print(f"attempt {attempt}/{attempts}: {message}; retrying in "
                  f"{args.retry_delay:g}s", file=sys.stderr)
            time.sleep(args.retry_delay)

    # ok is False for a real staleness/mismatch verdict, None for a fetch or
    # parse failure. Both are failures — an unreadable published artifact is not
    # evidence of freshness — but they get different exit codes so a transient
    # network fault is distinguishable from a genuine policy breach.
    print(f"::error::{message}", file=sys.stderr)
    return 1 if ok is False else 2


if __name__ == "__main__":
    sys.exit(main())
