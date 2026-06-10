#!/usr/bin/env python3
# =============================================================================
# CMMC PROJECTION  (Phase 2 / CMMC)
# =============================================================================
# Projects the 800-53 Rev5 hub through the composed mapping
#   CMMC req (171 Rev2)  ->(171->53r4)->  53 Rev4  ->(Rev4->Rev5)->  Rev5 hub
# to a CMMC Level 2 coverage view: per-requirement responsibility, the coverage
# stack, the inheritable fraction (the ~53/110 sensor), and residue.
#
# Aggregation is CONSERVATIVE MERGE: a requirement is "fully-inherited" only if
# EVERY mapped hub control is inherited; any provider/shared part downgrades it
# to partially-inherited. Never overclaim inheritance.
#
# Usage: build-cmmc.py --ssp REV5_SSP [--output COVERAGE.json]
# =============================================================================

import argparse
import json
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def classify(status, origination):
    if status == "not-applicable":
        return "not-applicable"
    if status == "planned":
        return "planned"
    if origination == "inherited":
        return "fully-inherited"
    if origination == "shared":
        return "partially-inherited"
    if origination in ("customer-configured", "customer-provided"):
        return "customer-responsibility"
    return "implemented"


def load_171_53():
    doc = json.loads((REPO / "data/mappings/SP800-171r2-to-SP800-53r4.mapping.json").read_text())["mapping-collection"]
    out = {}
    for m in doc["mappings"][0]["maps"]:
        out.setdefault(m["sources"][0]["id-ref"], []).append(m["targets"][0]["id-ref"])
    return out


def load_rev4_rev5():
    doc = json.loads((REPO / "data/mappings/SP800-53_rev4-to-rev5.mapping.json").read_text())["mapping-collection"]
    return {m["sources"][0]["id-ref"]: m["targets"][0]["id-ref"] for m in doc["mappings"][0]["maps"]}


def load_catalog_reqs():
    cat = json.loads((REPO / "data/catalogs/NIST_SP-800-171_rev2_catalog.json").read_text())["catalog"]
    return [c["id"] for g in cat["groups"] for c in g["controls"]]


def load_hub(ssp_path):
    irs = json.loads(Path(ssp_path).read_text())["system-security-plan"]["control-implementation"]["implemented-requirements"]
    def p(ir, n):
        for x in ir.get("props", []) or []:
            if x["name"] == n:
                return x["value"]
    return {ir["control-id"]: (p(ir, "implementation-status"), p(ir, "control-origination")) for ir in irs}


def aggregate(classes):
    """Conservative merge of the mapped hub controls' responsibility classes."""
    non_na = classes - {"not-applicable"}
    if not non_na:
        return "not-applicable"
    if non_na == {"fully-inherited"}:
        return "fully-inherited"
    if non_na & {"fully-inherited", "partially-inherited"}:
        return "partially-inherited"   # some inheritance but not all -> partial (conservative)
    return "implemented"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssp", required=True)
    ap.add_argument("--output", default=None)
    a = ap.parse_args()

    reqs = load_catalog_reqs()
    m171 = load_171_53()
    r45 = load_rev4_rev5()
    hub = load_hub(a.ssp)

    stack = Counter()
    residue = []
    per_req = {}
    for req in reqs:
        r4 = m171.get(req, [])
        if not r4:
            residue.append((req, "no 800-53 mapping (CMMC-specific control)"))
            continue
        r5 = sorted({r45.get(c, c) for c in r4})      # compose r4 -> r5 (default same-id)
        impls = [hub[c] for c in r5 if c in hub]
        if not impls:
            residue.append((req, f"hub does not address {r5}"))
            continue
        cls = aggregate({classify(s, o) for (s, o) in impls})
        stack[cls] += 1
        per_req[req] = {"class": cls, "hub_controls": r5}

    total = len(reqs)
    inh_full = stack["fully-inherited"]
    inh_part = stack["partially-inherited"]
    cov = {
        "framework": "CMMC Level 2 (NIST SP 800-171 Rev2, 110 requirements)",
        "in_scope_requirements": total,
        "coverage": {"determined": total - len(residue), "residue": len(residue),
                     "determined_pct": round(100.0 * (total - len(residue)) / total, 1)},
        "responsibility_stack": dict(stack),
        "inheritable": {"fully_inherited": inh_full, "partially_inherited": inh_part,
                        "inheritance_touched": inh_full + inh_part,
                        "fraction": f"{inh_full + inh_part}/110"},
        "residue": [{"req": r, "reason": why} for r, why in residue],
        "per_requirement": per_req,
    }
    if a.output:
        Path(a.output).write_text(json.dumps(cov, indent=2) + "\n")

    import sys
    print("=== CMMC Level 2 coverage (projected from the 800-53 Rev5 hub) ===", file=sys.stderr)
    print(f"  in-scope requirements: {total}", file=sys.stderr)
    print(f"  determined: {cov['coverage']['determined']}/{total} "
          f"({cov['coverage']['determined_pct']}%) | residue: {len(residue)}", file=sys.stderr)
    for k in ["implemented", "partially-inherited", "fully-inherited", "customer-responsibility", "planned", "not-applicable"]:
        if stack[k]:
            print(f"    {stack[k]:4}  {k}", file=sys.stderr)
    print(f"  INHERITABLE from this CSO: {inh_full + inh_part}/110 "
          f"({inh_full} full + {inh_part} partial)  <- the ~53/110 sensor", file=sys.stderr)
    if residue:
        print(f"  residue ({len(residue)}): {[r for r,_ in residue]}", file=sys.stderr)


if __name__ == "__main__":
    main()
