#!/usr/bin/env python3
"""Fail the deploy when the running Silk Reeling app disagrees with Terraform,
or when its gateway answers without a token.

POAM-038: from 2026-06 the app Lambda kept running with an old environment
while every apply reported it updated, and nothing noticed for four months.
Neither CI role can decrypt the CMK-encrypted environment to compare it, so
this asks the app instead: its /auth-config route reports the Cognito settings
the process actually sees. Those must equal what Terraform declared (the
`silk_reeling_auth_config_json` output) or the deploy stops before any evidence
is published. The API Gateway has no unauthenticated route to reach that route
through, so the check invokes the function directly (the deploy role may invoke
this one function and nothing else).

It then checks the gateway from outside, without a token: the root must have no
route (404), and an API route must be refused by the authorizer (401). Any other
answer means a route is open that should not be.

Usage: check-silk-runtime-config.py EXPECTED_JSON --function NAME --gateway URL
An empty EXPECTED_JSON means the app is not deployed; the check passes.

Exit codes: 0 match (or app not deployed), 1 mismatch or an open route, 2 the
function or the gateway could not be reached or parsed.
"""

import argparse
import json
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

USER_AGENT = "samaydlette-silk-runtime-config/1"

# A minimal API Gateway HTTP API (payload 2.0) request for GET /auth-config,
# which is what the function's ASGI adapter expects.
AUTH_CONFIG_EVENT = {
    "version": "2.0", "routeKey": "$default", "rawPath": "/auth-config", "rawQueryString": "",
    "headers": {"host": "runtime-check.invalid", "user-agent": USER_AGENT},
    "requestContext": {
        "accountId": "anonymous", "apiId": "runtime-check", "domainName": "runtime-check.invalid",
        "domainPrefix": "runtime-check", "requestId": "runtime-check", "routeKey": "$default",
        "stage": "$default", "time": "01/Jan/2026:00:00:00 +0000", "timeEpoch": 0,
        "http": {"method": "GET", "path": "/auth-config", "protocol": "HTTP/1.1",
                 "sourceIp": "127.0.0.1", "userAgent": USER_AGENT},
    },
    "isBase64Encoded": False,
}

# What the gateway must answer to a request without a token.
GATEWAY_PROBES = (("/", 404), ("/api/healthz", 401))


def invoke(function, timeout=60):
    """The JSON body the function returns for GET /auth-config."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "response.json"
        r = subprocess.run(
            ["aws", "lambda", "invoke", "--function-name", function,
             "--cli-binary-format", "raw-in-base64-out",
             "--payload", json.dumps(AUTH_CONFIG_EVENT), str(out)],
            capture_output=True, text=True, timeout=timeout, check=False)
        if r.returncode != 0:
            raise OSError(f"aws lambda invoke exited {r.returncode}")
        if "FunctionError" in r.stdout:
            raise ValueError("the function returned an error")
        resp = json.loads(out.read_text())
    if resp.get("statusCode") != 200:
        raise ValueError(f"/auth-config answered {resp.get('statusCode')}")
    return json.loads(resp["body"])


def status(url, timeout=30):
    """The HTTP status a request without a token gets."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https URL from the Terraform output
            return resp.status
    except urllib.error.HTTPError as err:
        return err.code


def mismatches(expected, actual):
    """Names of the declared settings the running app does not report as declared."""
    return sorted(k for k, v in expected.items() if actual.get(k) != v)


def open_routes(gateway):
    """(path, status, expected) for each probe the gateway answers differently."""
    base = gateway.rstrip("/")
    return [(path, got, want) for path, want in GATEWAY_PROBES
            if (got := status(base + path)) != want]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("expected", help="the silk_reeling_auth_config_json Terraform output")
    ap.add_argument("--function", help="the silk_reeling_function_name Terraform output")
    ap.add_argument("--gateway", help="the silk_reeling_api_endpoint Terraform output")
    ap.add_argument("--attempts", type=int, default=3)
    args = ap.parse_args(argv)

    if not args.expected.strip():
        print("Silk Reeling not deployed; nothing to compare.")
        return 0
    if not args.function or not args.gateway or not args.gateway.startswith("https://"):
        print("::error::--function and an https --gateway are required when the app is deployed")
        return 2
    expected = json.loads(args.expected)

    # A just-replaced function cold-starts in a few seconds; retry briefly.
    last_err = None
    for attempt in range(args.attempts):
        try:
            actual = invoke(args.function)
            break
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as err:
            last_err = err
            time.sleep(10 * (attempt + 1))
    else:
        print(f"::error::could not read /auth-config from {args.function}: {last_err}")
        return 2

    bad = mismatches(expected, actual)
    if bad:
        print(f"::error::the running Silk Reeling app does not match Terraform: {', '.join(bad)} "
              "(see POAM-038: the function's environment did not take the apply)")
        return 1
    print(f"Silk Reeling runtime config matches Terraform ({', '.join(sorted(expected))}).")

    try:
        opened = open_routes(args.gateway)
    except (urllib.error.URLError, OSError) as err:
        print(f"::error::could not reach the Silk Reeling gateway: {err}")
        return 2
    if opened:
        for path, got, want in opened:
            print(f"::error::the Silk Reeling gateway answers {path} without a token with {got}, not {want}")
        return 1
    print("Silk Reeling gateway: no route answers without a token "
          f"({', '.join(f'{p} {w}' for p, w in GATEWAY_PROBES)}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
