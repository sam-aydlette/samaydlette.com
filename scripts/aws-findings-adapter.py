#!/usr/bin/env python3
"""The AWS adapter: AWS-native findings to normalized findings.

The VDR build (scripts/build-vdr-report.py) reads AWS findings only in the
normalized form (infrastructure/schemas/findings.schema.json), through
--findings, the same input any other platform's adapter would use. This file is
the only place that knows the shape of an AWS service's findings; everything
downstream (deduplication, scoring, decisions, the gates) is platform-neutral.

  scripts/fetch-aws-feeds.sh      fetches the raw feeds (needs AWS credentials)
  scripts/aws-findings-adapter.py turns them into one findings document (offline)

A stack on another platform writes its own pair and passes the result to the
VDR build with --findings; it needs nothing in this file.

Feeds:
  --inspector        Amazon Inspector (Lambda standard scanning), as fetched
  --access-analyzer  IAM Access Analyzer (external access), as fetched

Each published field has the AWS account ID masked (scripts/_redact.py). The
`source` of each finding is the name the decision register and the gates know it
by (VULN_SOURCES in build-vdr-report.py and vuln-gate.py).

Usage: aws-findings-adapter.py [--inspector F] [--access-analyzer F] --output F
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _redact  # noqa: E402

SCHEMA_VERSION = "findings/v1"


def _cvss_vector(cvss):
    """A CVSS vector from Inspector's cvss list of {version, scoringVector}:
    a 3.x vector first, then any vector (the rule build-vdr-report.py applies to
    the other scanners)."""
    vectors = [(str(c.get("version") or ""), c.get("scoringVector"))
               for c in cvss or [] if isinstance(c, dict) and c.get("scoringVector")]
    for ver, vec in vectors:
        if ver.startswith("3"):
            return vec
    return vectors[0][1] if vectors else None


def _aws_feed(path, key):
    """The findings list from a wrapped AWS feed (scripts/fetch-detection-feeds.sh).
    Absent or unreadable gives [], as for every scanner the VDR build reads:
    whether the feed was present and the service on is the detection gate's job
    (G7), which runs first."""
    if not path or not Path(path).exists():
        return []
    try:
        doc = json.loads(Path(path).read_text())
    except json.JSONDecodeError:
        return []
    items = doc.get(key) if isinstance(doc, dict) else None
    return items if isinstance(items, list) else []


# Inspector severities onto the vocabulary SEVERITY_TO_PAIN understands, as Grype's are.
INSPECTOR_SEVERITY = {"INFORMATIONAL": "LOW", "UNTRIAGED": "MEDIUM"}
INSPECTOR_FIX_STATE = {"YES": "fixed", "NO": "not-fixed", "PARTIAL": "fixed"}


def ingest_inspector(path):
    """Amazon Inspector findings for the deployed Lambda functions: a second,
    AWS-run scan of what is deployed, beside Grype's scan of the build. Each
    finding is one CVE in one package of one function; the resource is the
    function's ARN without its version, so it resolves to the inventoried
    function. Suppressed findings are kept: the decision lives in the register."""
    findings = []
    for f in _aws_feed(path, "findings"):
        if f.get("type") != "PACKAGE_VULNERABILITY":
            continue
        det = f.get("packageVulnerabilityDetails") or {}
        vid = det.get("vulnerabilityId") or "inspector"
        res = (f.get("resources") or [{}])[0]
        # Published, so the account ID is masked as the inventory masks it
        # (scripts/_redact.py); resolve_component matches the masked form.
        arn = _redact.redact_text(re.sub(r":(\$LATEST|\d+)$", "", str(res.get("id") or "")))
        function = ((res.get("details") or {}).get("awsLambdaFunction") or {}).get("functionName") \
            or arn.rsplit(":", 1)[-1]
        pkgs = det.get("vulnerablePackages") or [{}]
        pkg = pkgs[0]
        sev = (f.get("severity") or "MEDIUM").upper()
        findings.append({
            "source": "inspector",
            "tool_id": vid,
            "tracking_id": f"inspector-{vid}-{function}-{pkg.get('name', '')}",
            "title": f"{vid} in {pkg.get('name', '')} ({function})",
            "description": det.get("source", ""),
            "severity": INSPECTOR_SEVERITY.get(sev, sev),
            "resource": arn,
            "cve": vid if str(vid).upper().startswith("CVE-") else None,
            "detected_at": f.get("firstObservedAt"),
            "cvss_vector": _cvss_vector(det.get("cvss")),
            "fix_state": INSPECTOR_FIX_STATE.get(f.get("fixAvailable"), "unknown"),
            "fix_versions": [p.get("fixedInVersion") for p in pkgs if p.get("fixedInVersion")],
        })
    return findings


def ingest_access_analyzer(path):
    """IAM Access Analyzer external-access findings: a resource a principal
    outside the account can reach. Public access is HIGH; access granted to a
    named outside principal (a federated identity provider, another account, a
    service) is MEDIUM. Each is decided by a record naming its tracking_id, which
    is stable for one resource, principal and access: a change to any of them is
    a new finding, decided anew. Archived findings are kept: the decision lives
    in the register, never in an archive rule."""
    findings = []
    for f in _aws_feed(path, "findings"):
        if f.get("status") == "RESOLVED":
            continue
        arn = _redact.redact_text(str(f.get("resource") or ""))
        rtype = f.get("resourceType") or "resource"
        name = arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]
        principal = f.get("principal") or {}
        who = ", ".join(f"{k}: {v}" for k, v in sorted(principal.items())) or "unknown principal"
        actions = ", ".join(f.get("action") or []) or "unknown actions"
        public = f.get("isPublic") is True
        findings.append({
            "source": "access-analyzer",
            "tool_id": f"external-access:{rtype}",
            "tracking_id": f"access-analyzer-{f.get('id', 'x')}",
            "title": f"{'Public' if public else 'External'} access to {rtype} {name}",
            "description": _redact.redact_text(
                f"{who} can {actions}"
                + (f" when {json.dumps(f['condition'], sort_keys=True)}" if f.get("condition") else "")
                + f" (status {f.get('status', 'ACTIVE')})."),
            "severity": "HIGH" if public else "MEDIUM",
            "resource": arn,
            "detected_at": f.get("createdAt"),
        })
    return findings


def build(inspector=None, access_analyzer=None):
    """One normalized findings document from the AWS feeds given."""
    findings = ingest_inspector(inspector) + ingest_access_analyzer(access_analyzer)
    return {"schema_version": SCHEMA_VERSION, "platform": "aws",
            "adapter": "scripts/aws-findings-adapter.py", "findings": findings}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--inspector", help="Amazon Inspector status, coverage and findings (scripts/fetch-aws-feeds.sh)")
    ap.add_argument("--access-analyzer", help="IAM Access Analyzer analyzer and findings (scripts/fetch-aws-feeds.sh)")
    ap.add_argument("--output", required=True, help="the normalized findings document to write")
    args = ap.parse_args(argv)
    doc = build(args.inspector, args.access_analyzer)
    Path(args.output).write_text(json.dumps(doc, indent=2) + "\n")
    print(f"AWS adapter: {len(doc['findings'])} normalized finding(s) -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
