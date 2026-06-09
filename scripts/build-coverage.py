#!/usr/bin/env python3
# =============================================================================
# COVERAGE STACK  (Phase 2 / A2 — spoke output contract)
# =============================================================================
# Rolls up an OSCAL SSP's authored per-control responsibility classification into
# a coverage stack + inheritable fraction. Coverage is NOT a derived score: it is
# the histogram of the control-origination/implementation-status that each
# control already carries in the SSP. The responsibility classes use FedRAMP's
# authoritative control-origination vocabulary under plain-language labels.
#
# Deliberately does NOT report an "automation depth" / machine-evidence metric —
# that conflates evidence quality with coverage and was dropped by design.
#
#   coverage % = determined (every control has a class) = 100% by construction
#   inheritable fraction = fully-inherited + partially-inherited (the ~53/110
#     analog for CMMC)
#
# Usage: build-coverage.py <oscal-ssp.json> [--framework NAME] [--output PATH]
# =============================================================================

import argparse
import json
import sys
from collections import Counter

# FedRAMP control-origination + implementation-status -> responsibility class
CLASSES = ["implemented", "partially-inherited", "fully-inherited",
           "customer-responsibility", "planned", "not-applicable"]


def classify(status, origination):
    if status == "not-applicable":
        return "not-applicable"
    if status == "planned":
        return "planned"
    # implemented / partial / alternative
    if origination == "inherited":
        return "fully-inherited"
    if origination == "shared":
        return "partially-inherited"      # shared (system + AWS) == partially inherited
    if origination in ("customer-configured", "customer-provided"):
        return "customer-responsibility"
    return "implemented"                  # sp-system / sp-corporate (provider implements)


def _prop(ir, name):
    for p in ir.get("props", []) or []:
        if p.get("name") == name:
            return p.get("value")
    return None


def build_coverage(ssp, framework):
    irs = ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]
    hist = Counter()
    for ir in irs:
        hist[classify(_prop(ir, "implementation-status"),
                      _prop(ir, "control-origination"))] += 1
    total = len(irs)
    inherit_full = hist["fully-inherited"]
    inherit_part = hist["partially-inherited"]
    return {
        "framework": framework,
        "in_scope_controls": total,
        "coverage": {
            "determined": total,
            "determined_pct": round(100.0 * total / total, 1) if total else 0.0,
        },
        "responsibility_stack": {c: hist[c] for c in CLASSES},
        "inheritable": {
            "fully_inherited": inherit_full,
            "partially_inherited": inherit_part,
            "inheritance_touched": inherit_full + inherit_part,
            "fraction_of_baseline": round((inherit_full + inherit_part) / total, 3) if total else 0.0,
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ssp")
    ap.add_argument("--framework", default="FedRAMP Rev5 Moderate")
    ap.add_argument("--output", default=None)
    a = ap.parse_args()
    cov = build_coverage(json.loads(open(a.ssp).read()), a.framework)
    out = json.dumps(cov, indent=2)
    if a.output:
        open(a.output, "w").write(out + "\n")
    # human-readable summary to stderr
    print(f"=== coverage: {cov['framework']} ({cov['in_scope_controls']} in-scope) ===", file=sys.stderr)
    print(f"  coverage (determined): {cov['coverage']['determined_pct']}%", file=sys.stderr)
    for c in CLASSES:
        n = cov["responsibility_stack"][c]
        if n:
            print(f"    {n:4}  {c}", file=sys.stderr)
    inh = cov["inheritable"]
    print(f"  inheritable: {inh['inheritance_touched']} controls "
          f"({inh['fully_inherited']} full + {inh['partially_inherited']} partial) "
          f"= {inh['fraction_of_baseline']*100:.1f}% of baseline", file=sys.stderr)
    if not a.output:
        print(out)


if __name__ == "__main__":
    main()
