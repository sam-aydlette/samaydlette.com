#!/usr/bin/env python3
"""Fetch the previously published copy of an append-only history, fail-closed.

Several published files are append-only: each build carries over what the
previous published copy holds (the access summary's months, the certification
report index's first-publication dates, the package submission log's
entries). If the fetch of the previous copy fails and the build starts over
from nothing, the history is silently reset. So, like the Significant Change
Notification step:

  200  the body must be a complete JSON document; it is written to OUT.
  404  nothing has been published yet; OUT is removed and the build starts
       the history.
  anything else (a 5xx, a 403, a redirect loop, a network error, a timeout,
       or a 200 whose body is truncated or not JSON) fails the deploy.

Only HTTPS on the provider's own site is fetched.

  fetch-published-history.py NAME OUT [--site https://samaydlette.com]
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SITE = "https://samaydlette.com"
ALLOWED_HOST = "samaydlette.com"
TIMEOUT = 30


def _fail(msg):
    raise SystemExit(f"::error::published history: {msg} (fail-closed: refusing to restart the history)")


def http_get(url):
    """(status, body). An HTTP error status is a status, not an exception; a
    network failure raises."""
    req = urllib.request.Request(url, headers={"User-Agent": "samaydlette-deploy/1 (history fetch)"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # nosec B310: https on the allowed host only
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


def fetch(name, out, site=SITE, get=http_get):
    """Write the published `name` to `out` and return True, or remove `out` and
    return False when it has never been published (404). Fails otherwise."""
    if not name or "/" in name or name.startswith(".") or not name.endswith(".json"):
        _fail(f"{name!r} is not a .json file name under /.well-known/")
    url = f"{site.rstrip('/')}/.well-known/{name}"
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname != ALLOWED_HOST:
        _fail(f"refusing to fetch {url!r} (only https://{ALLOWED_HOST})")
    out = Path(out)
    try:
        status, body = get(url)
    except (OSError, ValueError) as exc:
        _fail(f"cannot fetch the published {name} ({type(exc).__name__})")
    if status == 404:
        out.unlink(missing_ok=True)
        print(f"{name} not published yet; starting its history")
        return False
    if status != 200:
        _fail(f"fetching the published {name} returned HTTP {status}")
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        _fail(f"the published {name} is truncated or not JSON")
    if not isinstance(doc, dict) or not doc:
        _fail(f"the published {name} is not a JSON object")
    out.write_bytes(body)
    print(f"{name}: previous published copy read ({len(body)} bytes)")
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name")
    ap.add_argument("out")
    ap.add_argument("--site", default=SITE)
    a = ap.parse_args(argv)
    fetch(a.name, a.out, a.site)
    return 0


if __name__ == "__main__":
    sys.exit(main())
