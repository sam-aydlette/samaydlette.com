#!/usr/bin/env python3
# =============================================================================
# VULNERABILITY GATE  (fail closed on any uncategorized vulnerability)
# =============================================================================
# The rule, by operator decision: a scanner-reported vulnerability of ANY
# severity (Critical/High/Medium/Low) fails the build unless it is handled.
# A vulnerability is handled only if it is:
#   - remediated  (no longer reported by the scanner — it simply isn't here), or
#   - dispositioned in data/vuln-dispositions.json, in force (review_by not
#     passed), as one of:
#       false-positive          (the reason lives in the scanned artifact; a
#                                false positive naming a control does not pass)
#       operational-requirement (Rev5 term: real risk, deliberately accepted)
#       accepted                (will not fix, with the acceptance explanation)
#       mitigated               (only with a mitigation the VDR shows in force)
#       vendor-dependency       (only while the VDR shows fix state not-fixed;
#                                an unknown fix state counts as fixable)
#
# under-investigation and remediate are recorded but do not pass. Passing this
# gate never stops a deadline: the VDR's deadline gate still blocks an overdue
# vendor dependency or partly mitigated finding.
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
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The only dispositions that let a vulnerability pass the build; mitigated and
# vendor-dependency also need their evidence (see handled()).
PASS_DISPOSITIONS = {"false-positive", "operational-requirement", "accepted",
                     "mitigated", "vendor-dependency"}

# Sources that produce vulnerabilities (gated here). Config scanners
# (opa/checkov/tfsec) are governed separately via .checkov.yaml + the VDR maps.
VULN_SOURCES = {"grype", "zap", "dependabot"}

# The scanner fix state a vendor dependency needs: no fix yet. "wont-fix" (none
# coming) is not a vendor dependency. Mirrors policies/triage.rego.
NO_FIX_STATES = {"not-fixed"}


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
            # Evidence the builder evaluated: a mitigation in force, and the
            # scanner's fix state. One ID can cover several findings (one CVE in
            # several packages); the evidence must hold on every one of them.
            mit = (f.get("mitigation") or {}).get("valid") is True
            fix = f.get("fix_state")
            prev = out.get(vid)
            if prev:
                mit = mit and prev["mitigation_valid"]
                if prev["fix_state"] not in NO_FIX_STATES:
                    fix = prev["fix_state"]
            out[vid] = {"id": vid, "severity": (f.get("severity") or "").upper(),
                        "source": f.get("source", "vdr"),
                        "mitigation_valid": mit, "fix_state": fix}
    for c in vdr.get("cve_findings", []) or []:
        vid = c.get("cve") or c.get("id") or c.get("tracking_id")
        if vid and vid not in out:
            out[vid] = {"id": vid, "severity": (c.get("severity") or c.get("max_severity") or "").upper(),
                        "source": c.get("source", "vdr")}
    return list(out.values())


def disposition_of(vuln_id, register):
    entry = register.get(vuln_id) or {}
    return entry.get("disposition")


def handled(v, entry, today):
    """True when the register entry is in force and its disposition passes with
    the evidence it needs. A record past review_by is absent."""
    disp = (entry or {}).get("disposition")
    if disp not in PASS_DISPOSITIONS:
        return False
    review_by = entry.get("review_by")
    if review_by:
        try:
            if date.fromisoformat(str(review_by)) < today:
                return False
        except ValueError:
            return False
    if disp == "false-positive" and entry.get("mitigation"):
        return False
    if disp == "mitigated" and v.get("mitigation_valid") is not True:
        return False
    if disp == "vendor-dependency" and v.get("fix_state") not in NO_FIX_STATES:
        return False
    return True


def find_unhandled(vulns, register, today=None):
    """Return the vulnerabilities the register does not handle."""
    today = today or date.today()
    return [v for v in vulns if not handled(v, register.get(v["id"]), today)]


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
        print(f"vulnerability gate: OK — {len(vulns)} scanned, all remediated or dispositioned in force")
        return 0

    print(f"VULNERABILITY GATE FAILED — {len(unhandled)} uncategorized vulnerability(ies):", file=sys.stderr)
    for v in unhandled:
        sev = v.get("severity") or "?"
        print(f"  ✗ {v['id']} [{sev}] (source: {v.get('source','?')})", file=sys.stderr)
    print("", file=sys.stderr)
    print("Each must be either fixed (so the scanner stops reporting it) or added to", file=sys.stderr)
    print(f"  {Path(args.register).name}  with a passing disposition in force (review_by not", file=sys.stderr)
    print("  passed): false-positive, accepted, operational-requirement, mitigated (with a", file=sys.stderr)
    print("  mitigation in force) or vendor-dependency (only while no fix exists).", file=sys.stderr)
    print("  Risk-adjustment, under-investigation and remediate do NOT pass.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
