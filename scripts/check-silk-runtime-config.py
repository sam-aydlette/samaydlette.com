#!/usr/bin/env python3
"""Fail the deploy when the running Silk Reeling app disagrees with Terraform.

POAM-038: from 2026-06 the app Lambda kept running with an old environment
while every apply reported it updated, and nothing noticed for four months.
Neither CI role can decrypt the CMK-encrypted environment to compare it, so
this asks the app instead: its public /auth-config endpoint reports the Cognito
settings the process actually sees. Those must equal what Terraform declared
(the `silk_reeling_auth_config_json` output) or the deploy stops before any
evidence is published.

Usage: check-silk-runtime-config.py EXPECTED_JSON [--url URL]
An empty EXPECTED_JSON means the app is not deployed; the check passes.

Exit codes: 0 match (or app not deployed), 1 mismatch, 2 the endpoint could
not be fetched or parsed.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

DEFAULT_URL = "https://samaydlette.com/silk-reeling/auth-config"


def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={
        "User-Agent": "samaydlette-silk-runtime-config/1",
        "Cache-Control": "no-cache",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
        return json.loads(resp.read())


def mismatches(expected, actual):
    """Names of the declared settings the running app does not report as declared."""
    return sorted(k for k, v in expected.items() if actual.get(k) != v)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("expected", help="the silk_reeling_auth_config_json Terraform output")
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--attempts", type=int, default=3)
    args = ap.parse_args(argv)

    if not args.expected.strip():
        print("Silk Reeling not deployed; nothing to compare.")
        return 0
    expected = json.loads(args.expected)

    # A just-replaced function cold-starts in a few seconds; retry briefly.
    last_err = None
    for attempt in range(args.attempts):
        try:
            actual = fetch(args.url)
            break
        except (urllib.error.URLError, OSError, ValueError) as err:
            last_err = err
            time.sleep(10 * (attempt + 1))
    else:
        print(f"::error::could not read {args.url}: {last_err}")
        return 2

    bad = mismatches(expected, actual)
    if bad:
        print(f"::error::the running Silk Reeling app does not match Terraform: {', '.join(bad)} "
              "(see POAM-038: the function's environment did not take the apply)")
        return 1
    print(f"Silk Reeling runtime config matches Terraform ({', '.join(sorted(expected))}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
