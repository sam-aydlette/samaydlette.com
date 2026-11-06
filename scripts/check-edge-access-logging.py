#!/usr/bin/env python3
"""Access to the certification data is logged, within the privacy limits (CDS-TRC-ACL).

Reads the CloudFront standard-logging (v2) configuration the deploy role can see
and fails unless:

  * a delivery from the source named for this site exists;
  * that source is the CloudFront distribution's ACCESS_LOGS;
  * the delivery goes to S3; and
  * its record fields are exactly within ALLOWED_FIELDS and include REQUIRED_FIELDS.

ALLOWED_FIELDS is the operator's privacy condition: no client IP, forwarded-for,
port, cookies, query string, user agent or referrer is ever logged. It must equal
the delivery's record_fields in infrastructure/bootstrap/trust-access-logs.tf
(tests/test_edge_access_logging.py holds them equal). The configuration is
operator-applied (bootstrap), so this check is what fails the deploy when it is
missing, before the trust center or the SDR say access is logged.

Inputs are the AWS CLI's JSON (aws logs describe-deliveries, aws logs
get-delivery-source), so the check runs the same on fixtures. Prints no ARN.
"""
import argparse
import json
import sys
from pathlib import Path

ALLOWED_FIELDS = ("date", "time", "x-edge-location", "c-country", "cs-method", "cs-uri-stem",
                  "sc-status", "sc-bytes", "x-edge-result-type")
REQUIRED_FIELDS = ("date", "time", "cs-uri-stem", "sc-status")
# Named so the failure message says what was found; any field outside
# ALLOWED_FIELDS fails, whether or not it is listed here.
IDENTIFYING = ("c-ip", "x-forwarded-for", "c-port", "cs(Cookie)", "cs-uri-query", "cs(User-Agent)",
               "cs(Referer)")


def problems(deliveries, source, name):
    out = []
    mine = [d for d in (deliveries or {}).get("deliveries", []) if d.get("deliverySourceName") == name]
    if not mine:
        return [f"no CloudFront access-log delivery from source {name!r} (bootstrap not applied?)"]
    if len(mine) > 1:
        out.append(f"{len(mine)} deliveries from {name!r}; expected one")
    src = (source or {}).get("deliverySource") or {}
    if src.get("name") != name:
        out.append(f"delivery source {name!r} could not be read")
    if src.get("logType") != "ACCESS_LOGS":
        out.append(f"delivery source log type is {src.get('logType')!r}, not ACCESS_LOGS")
    if not any(":distribution/" in a and a.startswith("arn:aws:cloudfront::") for a in src.get("resourceArns") or []):
        out.append("delivery source is not a CloudFront distribution")
    for d in mine:
        if d.get("deliveryDestinationType") != "S3":
            out.append(f"delivery destination type is {d.get('deliveryDestinationType')!r}, not S3")
        fields = d.get("recordFields") or []
        extra = sorted(set(fields) - set(ALLOWED_FIELDS))
        bad = sorted(f for f in extra if f in IDENTIFYING)
        if bad:
            out.append(f"delivery logs identifying field(s) {bad}")
        if sorted(set(extra) - set(bad)):
            out.append(f"delivery logs field(s) outside the privacy allowlist: {sorted(set(extra) - set(bad))}")
        missing = sorted(set(REQUIRED_FIELDS) - set(fields))
        if missing:
            out.append(f"delivery omits required field(s) {missing}")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--deliveries", required=True, help="aws logs describe-deliveries output")
    ap.add_argument("--source", required=True, help="aws logs get-delivery-source output (may be empty)")
    ap.add_argument("--name", required=True, help="the delivery source's name")
    a = ap.parse_args(argv)

    def read(p):
        t = Path(p).read_text() if Path(p).exists() else ""
        try:
            return json.loads(t) if t.strip() else {}
        except json.JSONDecodeError:
            return {}
    why = problems(read(a.deliveries), read(a.source), a.name)
    for w in why:
        print(f"::error::edge access logging: {w}", file=sys.stderr)
    if why:
        print("Access to the certification data is not logged as the trust center states; "
              "the deploy does not proceed.", file=sys.stderr)
        return 1
    print(f"ok: CloudFront access logging to S3, fields {', '.join(ALLOWED_FIELDS)} "
          "(no IP, cookies, query string or user agent)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
