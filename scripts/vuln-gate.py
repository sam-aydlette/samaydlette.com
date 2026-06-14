#!/usr/bin/env python3
# =============================================================================
# VULNERABILITY GATE  (fail closed on any uncategorized vulnerability)
# =============================================================================
# The rule, by operator decision: a scanner-reported vulnerability of ANY
# severity (Critical/High/Medium/Low) fails the build unless it is handled.
# A vulnerability is handled only if it is:
#   - remediated  (no longer reported by the scanner — it simply isn't here), or
#   - dispositioned in data/vuln-dispositions.json as one of:
#       false-positive          (no real risk / not applicable), or
#       operational-requirement (real risk, deliberately accepted).
#
# A risk-adjusted vulnerability still has a severity, so it does NOT pass — fix
# it. There is no SLA-with-a-future-date pass state for vulnerabilities: you
# either fix it, prove it is a false positive, or accept it as an operational
# requirement. The gate forces that choice on every build.
#
# Config-scanner suppressions (Checkov) are governed separately (.checkov.yaml +
# the VDR maps + the reconciliation gate); this gate is for vulnerabilities only.
#
# Usage:
#   vuln-gate.py --vdr infrastructure/vdr-report.json        # read VDR CVEs
#   vuln-gate.py --findings findings.json                    # raw list (tests)
#   [--register data/vuln-dispositions.json]
#
# Exit 0 if every vulnerability is handled; exit 1 (with a remediate-or-
# categorize report) if any is not.
# =============================================================================

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The only two dispositions that let a vulnerability pass the build.
PASS_DISPOSITIONS = {"false-positive", "operational-requirement"}

# Sources that produce vulnerabilities (gated here). Config scanners
# (opa/checkov/tfsec) are governed separately via .checkov.yaml + the VDR maps.
VULN_SOURCES = {"grype", "zap", "dependabot"}


def load_register(path):
    doc = json.loads(Path(path).read_text())
    return doc.get("dispositions", {})


def vulns_from_vdr(vdr):
    """Extract every vulnerability from a VDR report — from the raw findings
    (so ZAP DAST alerts, which carry no CVE, are included) and the consolidated
    CVE list. Keyed by CVE when present, else the scanner tracking id. Config
    findings are excluded (governed separately)."""
    out = {}
    for f in vdr.get("findings", []) or []:
        if f.get("source") not in VULN_SOURCES:
            continue
        vid = f.get("cve") or f.get("tracking_id") or f.get("tool_id")
        if vid:
            out[vid] = {"id": vid, "severity": (f.get("severity") or "").upper(),
                        "source": f.get("source", "vdr")}
    for c in vdr.get("cve_findings", []) or []:
        vid = c.get("cve") or c.get("id") or c.get("tracking_id")
        if vid and vid not in out:
            out[vid] = {"id": vid, "severity": (c.get("severity") or c.get("max_severity") or "").upper(),
                        "source": c.get("source", "vdr")}
    return list(out.values())


def disposition_of(vuln_id, register):
    entry = register.get(vuln_id) or {}
    return entry.get("disposition")


def find_unhandled(vulns, register):
    """Return the vulnerabilities that are neither false-positive nor
    operational-requirement in the register."""
    unhandled = []
    for v in vulns:
        if disposition_of(v["id"], register) not in PASS_DISPOSITIONS:
            unhandled.append(v)
    return unhandled


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--vdr", help="VDR report JSON; vulnerabilities read from cve_findings")
    src.add_argument("--findings", help="JSON array of {id, severity, source} (tests/manual)")
    ap.add_argument("--register", default=str(REPO / "data" / "vuln-dispositions.json"))
    args = ap.parse_args()

    register = load_register(args.register)

    if args.vdr:
        vdr = json.loads(Path(args.vdr).read_text())
        vulns = vulns_from_vdr(vdr)
    else:
        vulns = json.loads(Path(args.findings).read_text())

    unhandled = find_unhandled(vulns, register)

    if not unhandled:
        print(f"vulnerability gate: OK — {len(vulns)} scanned, all remediated or dispositioned (FP/OR)")
        return 0

    print(f"VULNERABILITY GATE FAILED — {len(unhandled)} uncategorized vulnerability(ies):", file=sys.stderr)
    for v in unhandled:
        sev = v.get("severity") or "?"
        print(f"  ✗ {v['id']} [{sev}] (source: {v.get('source','?')})", file=sys.stderr)
    print("", file=sys.stderr)
    print("Each must be either fixed (so the scanner stops reporting it) or added to", file=sys.stderr)
    print(f"  {Path(args.register).name}  with a disposition of 'false-positive' or", file=sys.stderr)
    print("  'operational-requirement' and a justification. Risk-adjustment does NOT pass.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
