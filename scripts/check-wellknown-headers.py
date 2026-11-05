#!/usr/bin/env python3
"""The public JSON under /.well-known/ is servable to any program (FRC-CSO-JSN).

Fetches each named artifact over HTTPS from the live site, as a browser on
another origin would (an Origin header), and fails unless the response carries:

  * Access-Control-Allow-Origin: *     (CORS: a page on any origin can read it)
  * a JSON Content-Type                (application/json or application/*+json)
  * X-Content-Type-Options: nosniff    (the browser keeps that type)

The headers come from the CloudFront response-headers policy for /.well-known/*
(infrastructure/bootstrap/cloudfront.tf), which the operator applies; this step
is what makes the deploy fail when that apply is missing. Read-only; stdlib only.

    check-wellknown-headers.py --site https://samaydlette.com ksi-signal.json ...
    check-wellknown-headers.py --fixture headers.json   (tests: {name: {header: value}})
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

ORIGIN = "https://example.org"
DEFAULT_ARTIFACTS = ("ksi-signal.json", "security-decision-record.json", "trust-center.json",
                     "vdr-report.json", "certification-package-overview.json")


def problems(headers):
    """[reason, ...] for one response's headers (names case-insensitive)."""
    h = {k.lower(): (v or "").strip() for k, v in headers.items()}
    out = []
    if h.get("access-control-allow-origin") != "*":
        out.append(f"Access-Control-Allow-Origin is {h.get('access-control-allow-origin')!r}, not '*'")
    ctype = h.get("content-type", "").split(";")[0].strip().lower()
    if not (ctype == "application/json" or (ctype.startswith("application/") and ctype.endswith("+json"))):
        out.append(f"Content-Type is {ctype or 'absent'!r}, not JSON")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append("X-Content-Type-Options: nosniff is absent")
    return out


def fetch(url, timeout=20):
    req = urllib.request.Request(url, method="GET", headers={"Origin": ORIGIN, "User-Agent": "samaydlette-header-check"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310: fixed https URL
        return dict(resp.headers.items())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--site", default="https://samaydlette.com")
    ap.add_argument("--fixture", default=None, help="JSON {artifact: {header: value}} instead of the network")
    ap.add_argument("artifacts", nargs="*", default=None)
    a = ap.parse_args(argv)
    if not a.site.startswith("https://"):
        print("::error::--site must be an https:// URL", file=sys.stderr)
        return 2
    fixture = json.loads(open(a.fixture).read()) if a.fixture else None
    names = a.artifacts or (sorted(fixture) if fixture is not None else list(DEFAULT_ARTIFACTS))
    failed = 0
    for name in names:
        url = f"{a.site.rstrip('/')}/.well-known/{name}"
        try:
            headers = fixture[name] if fixture is not None else fetch(url)
        except (urllib.error.URLError, OSError, KeyError) as exc:
            print(f"::error::{url}: could not be read ({type(exc).__name__})", file=sys.stderr)
            failed += 1
            continue
        why = problems(headers)
        for w in why:
            print(f"::error::{url}: {w}", file=sys.stderr)
        failed += bool(why)
        if not why:
            print(f"ok: {url} (CORS *, JSON, nosniff)")
    if failed:
        print(f"{failed} artifact(s) under /.well-known/ lack the required headers; the deploy does not proceed.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
