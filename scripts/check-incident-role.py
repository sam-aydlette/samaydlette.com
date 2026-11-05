#!/usr/bin/env python3
"""Deploy gate: the incident report publisher's role can actually be assumed.

The IEC records describe a system whose unattended publisher
(.github/workflows/incident-reports.yml) assumes the role
infrastructure/bootstrap/incident-reports.tf creates. The deploy job runs this
before it builds the SDR, so a deploy whose publisher role does not work stops
before any record claiming it is published:

  1. request the job's GitHub OIDC token (audience sts.amazonaws.com);
  2. call STS AssumeRoleWithWebIdentity for AWS_INCIDENT_REPORTS_ROLE_ARN;
  3. require success, and that the assumed role is
     github-actions-incident-reports-oidc.

The temporary credentials STS returns are discarded unused. Prints no token,
credential, ARN or account ID. Stdlib only. Exit 0 pass, 1 fail.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

EXPECTED_ROLE_NAME = "github-actions-incident-reports-oidc"
SESSION = "deploy-proves-incident-publisher"
STS_URL = "https://sts.{region}.amazonaws.com/"
REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]$")
ASSUMED_RE = re.compile(r"^arn:aws(-[a-z]+)*:sts::[0-9]{12}:assumed-role/([\w+=,.@-]+)/[\w+=,.@-]+$")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_sts(status: int, body: str) -> list[str]:
    """Problems with an AssumeRoleWithWebIdentity response, or []."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return [f"STS returned HTTP {status} with a body that is not XML"]
    found = {_local(e.tag): (e.text or "").strip() for e in root.iter()}
    if status != 200 or "Error" in found:
        code = re.sub(r"[^A-Za-z.]", "", found.get("Code", "unknown"))[:64]
        return [f"STS refused the incident publisher role ({code}, HTTP {status}): the role or its trust for the "
                f"deploy environment is missing; apply infrastructure/bootstrap/incident-reports.tf"]
    m = ASSUMED_RE.match(found.get("Arn", ""))
    if not m:
        return ["STS answered without an assumed-role identity"]
    if m.group(2) != EXPECTED_ROLE_NAME:
        return [f"the assumed role is not {EXPECTED_ROLE_NAME}"]
    return []


def oidc_token(env=os.environ, opener=urllib.request.urlopen) -> str:
    url, bearer = env.get("ACTIONS_ID_TOKEN_REQUEST_URL"), env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise RuntimeError("no GitHub OIDC token available (the job needs permissions: id-token: write)")
    sep = "&" if "?" in url else "?"
    req = urllib.request.Request(url + sep + "audience=sts.amazonaws.com", headers={"Authorization": f"bearer {bearer}"})
    with opener(req, timeout=30) as r:
        return json.loads(r.read())["value"]


def assume(role_arn: str, token: str, region: str, opener=urllib.request.urlopen) -> tuple[int, str]:
    data = urllib.parse.urlencode({"Action": "AssumeRoleWithWebIdentity", "Version": "2011-06-15",
                                   "RoleArn": role_arn, "RoleSessionName": SESSION, "DurationSeconds": "900",
                                   "WebIdentityToken": token}).encode()
    req = urllib.request.Request(STS_URL.format(region=region), data=data, method="POST")
    try:
        with opener(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main(argv=None, env=os.environ, opener=urllib.request.urlopen) -> int:
    role_arn = (env.get("INCIDENT_REPORTS_ROLE_ARN") or "").strip()
    region = env.get("AWS_REGION") or "us-east-2"
    if not REGION_RE.match(region):
        # The region becomes part of the STS host name; never let it pick the host.
        problems = ["AWS_REGION is not an AWS region name"]
    elif not role_arn:
        problems = ["AWS_INCIDENT_REPORTS_ROLE_ARN is not set"]
    else:
        try:
            status, body = assume(role_arn, oidc_token(env, opener), region, opener)
            problems = parse_sts(status, body)
        except (RuntimeError, urllib.error.URLError, KeyError, ValueError) as e:
            problems = [f"could not ask STS: {type(e).__name__}"]
    for p in problems:
        print(f"::error::incident publisher role: {p}")
    if not problems:
        print(f"incident publisher role: assumed {EXPECTED_ROLE_NAME} from the deploy job; credentials discarded")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
