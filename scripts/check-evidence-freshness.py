#!/usr/bin/env python3
"""Assert that PUBLISHED compliance evidence is fresh — the check that was missing.

The policy has always been that published reporting is less than 24 hours old.
Nothing enforced it. `check_f_freshness` in scripts/reconcile.py verifies that the
*staged* signal carries the current commit and has an `emitted_at` at all; it has
no staleness threshold and never looks at the live edge. So when the nightly
deploy started failing, the served artifacts simply stopped moving and every gate
stayed green — twelve days of rot, silently.

This reads the artifact a third party would read, over the public URL, and fails
loudly if its timestamp is older than the governed freshness window for that
artifact (infrastructure/schemas/freshness-config.json, REQ-PUB-2). The window
and the timestamp field come from that config, never from a flag: an artifact
the config does not list cannot be checked, and a missing or invalid config is a
failure. `--all` checks every listed artifact under a site's /.well-known/. It is deliberately
AWS-free and dependency-free: it proves the *published* claim, not the build's
opinion of it.

It doubles as the post-publish edge check. `--expect-sha256` asserts the bytes
being served are the bytes just built, and `--retries` rides out CDN invalidation
propagation, so one invocation answers both "did my publish reach the edge" and
"is what the edge serves inside the freshness policy".

Exit codes: 0 fresh (and matching, if --expect-sha256), 1 stale/mismatched,
2 the artifact could not be fetched or parsed, is not listed, or the config is
missing or invalid.
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _freshness import artifact_for, load_freshness_config, timestamp_of  # noqa: E402

DEFAULT_URL = "https://samaydlette.com/.well-known/vdr-report.json"


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
        return resp.read(), resp.headers.get("Last-Modified")


def http_date_to_iso(value):
    """An HTTP Last-Modified date as ISO 8601, or None."""
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None


def parse_timestamp(value):
    """An ISO timestamp as an aware datetime."""
    if not value:
        raise ValueError("artifact carries no timestamp")
    # Both forms occur in the published set: '...Z' (KSI signal) and an
    # explicit +00:00 offset (VDR). fromisoformat only learned 'Z' in 3.11.
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    emitted = datetime.fromisoformat(value)
    if emitted.tzinfo is None:
        emitted = emitted.replace(tzinfo=timezone.utc)
    return emitted


def check_once(url, artifact, expect_sha256, now):
    """One attempt against the governed window for `artifact`.
    Returns (ok, message, age_hours_or_None)."""
    max_age_hours = artifact["max_age_hours"]
    try:
        raw, last_modified = fetch(url)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        return None, f"could not fetch {url}: {exc}", None

    if expect_sha256:
        got = hashlib.sha256(raw).hexdigest()
        if got != expect_sha256:
            return False, (f"served bytes do not match the build "
                           f"(built {expect_sha256[:12]}…, served {got[:12]}…)"), None

    try:
        emitted = parse_timestamp(timestamp_of(artifact, raw, http_date_to_iso(last_modified)))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, AttributeError) as exc:
        return None, f"could not read the timestamp of {url}: {exc}", None

    age_hours = (now() - emitted).total_seconds() / 3600.0
    verdict = (f"{artifact['path']} is {age_hours:.1f}h old "
               f"(governed window: under {max_age_hours:g}h) — as of {emitted.isoformat()}")
    if age_hours > max_age_hours:
        return False, verdict, age_hours
    return True, verdict, age_hours


def check_all(site, cfg, now):
    """Every listed artifact under `site`, once each. Returns an exit code."""
    stale, unreadable = [], []
    for artifact in cfg["artifacts"]:
        ok, message, _age = check_once(f"{site.rstrip('/')}/{artifact['path']}", artifact, None, now)
        print(("OK: " if ok else "::error::") + message, file=sys.stdout if ok else sys.stderr)
        if ok is False:
            stale.append(artifact["path"])
        elif ok is None:
            unreadable.append(artifact["path"])
    if stale or unreadable:
        print(f"::error::{len(stale)} stale, {len(unreadable)} unreadable of {len(cfg['artifacts'])} "
              f"published artifacts (config {cfg['version']})", file=sys.stderr)
        return 2 if unreadable else 1
    print(f"OK: all {len(cfg['artifacts'])} published artifacts inside their governed windows (config {cfg['version']})")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=DEFAULT_URL,
                    help=f"published artifact to check (default: {DEFAULT_URL})")
    ap.add_argument("--config", default=None,
                    help="governed freshness config (default: infrastructure/schemas/freshness-config.json)")
    ap.add_argument("--all", metavar="SITE", default=None,
                    help="check every listed artifact under SITE (e.g. https://samaydlette.com) instead of --url")
    ap.add_argument("--expect-sha256", default=None,
                    help="also assert the served bytes hash to this (post-publish edge check)")
    ap.add_argument("--retries", type=int, default=0,
                    help="retry this many times before failing (rides out CDN propagation)")
    ap.add_argument("--retry-delay", type=float, default=20.0,
                    help="seconds between retries (default: 20)")
    args = ap.parse_args(argv)

    def now():
        return datetime.now(timezone.utc)

    try:
        cfg = load_freshness_config(args.config)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 2
    if args.all:
        return check_all(args.all, cfg, now)
    artifact = artifact_for(cfg, args.url)
    if artifact is None:
        print(f"::error::{args.url} is not listed in the governed freshness config; "
              f"it has no window to check against", file=sys.stderr)
        return 2

    attempts = args.retries + 1
    ok, message, _age = None, "no attempt made", None
    for attempt in range(1, attempts + 1):
        ok, message, _age = check_once(args.url, artifact, args.expect_sha256, now)
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
