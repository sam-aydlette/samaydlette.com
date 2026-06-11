#!/usr/bin/env python3
# =============================================================================
# BASELINE SPOKES — GovRAMP Moderate+CJIS, TX-RAMP L1/L2  (Phase 2)
# =============================================================================
# These frameworks are 800-53 control SELECTIONS, so each spoke is an OSCAL
# profile over the hub + a coverage projection — no new catalog, no new mapping:
#   - GovRAMP Moderate (+CJIS): Rev5-native -> control ids match the hub directly.
#   - TX-RAMP Level 1 / Level 2: still the 2021 Rev4 baseline (current per TX DIR)
#     -> ids project through the Rev4->Rev5 mapping (the existing bridge), then
#     match the hub.
#
# Reads the checked-in selections (data/baselines/...selections.json), emits an
# OSCAL profile per baseline (data/profiles/), and reports coverage + residue.
# =============================================================================

import json
import uuid
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SEL = REPO / "data/baselines/govramp-txramp-cjis.selections.json"
NS = uuid.UUID("ba5e1100-0000-5000-8000-000000000005")
CATALOG = {"rev5": "../catalogs/NIST_SP-800-53_rev5_catalog.json",
           "rev4": "../catalogs/NIST_SP-800-53_rev4_catalog.json"}


def sid(*p):
    return str(uuid.uuid5(NS, ":".join(p)))


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


def load_hub(ssp_path):
    irs = json.loads(Path(ssp_path).read_text())["system-security-plan"]["control-implementation"]["implemented-requirements"]
    def p(ir, n):
        for x in ir.get("props", []) or []:
            if x["name"] == n:
                return x["value"]
    return {ir["control-id"]: (p(ir, "implementation-status"), p(ir, "control-origination")) for ir in irs}


def load_r4_r5():
    m = json.loads((REPO / "data/mappings/SP800-53_rev4-to-rev5.mapping.json").read_text())["mapping-collection"]
    return {x["sources"][0]["id-ref"]: x["targets"][0]["id-ref"] for x in m["mappings"][0]["maps"]}


def build_profile(key, title, revision, controls):
    doc = {"profile": {
        "uuid": sid("profile", key),
        "metadata": {"title": title, "last-modified": "2026-06-10T00:00:00Z",
                     "version": "1.0.0", "oscal-version": "1.2.2"},
        "imports": [{"href": CATALOG[revision],
                     "include-controls": [{"with-ids": controls}]}],
        "merge": {"as-is": True},
    }}
    out = REPO / "data/profiles" / f"{key}_profile.json"
    out.write_text(json.dumps(doc, indent=2) + "\n")
    return out


def coverage(revision, controls, hub, r4_r5, spoke_na):
    stack = Counter()
    residue = []
    for c in controls:
        rev5 = c if revision == "rev5" else r4_r5.get(c, c)
        if rev5 in hub:
            stack[classify(*hub[rev5])] += 1
        elif c in spoke_na or rev5 in spoke_na:
            stack["not-applicable"] += 1            # CJIS-specific / no Rev5 successor, dispositioned N/A
        else:
            residue.append(c)
    return stack, residue


def main():
    import argparse, sys
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssp", required=True)
    a = ap.parse_args()

    data = json.loads(SEL.read_text())
    hub = load_hub(a.ssp)
    disp = json.loads((REPO / "data/dispositions/beyond-moderate.json").read_text())
    for c, d in disp["controls"].items():          # beyond-Moderate dispositions extend the hub
        hub[c] = (d["status"], d["origination"])
    spoke_na = set(disp["spoke_not_applicable"])
    r4_r5 = load_r4_r5()
    titles = {"govramp_moderate_cjis": "GovRAMP Moderate (Rev5) + CJIS overlay",
              "txramp_level1": "TX-RAMP Level 1 (Rev4 baseline)",
              "txramp_level2": "TX-RAMP Level 2 (Rev4 baseline)"}

    for key, bl in data["baselines"].items():
        controls, rev = bl["controls"], bl["revision"]
        build_profile(key, titles[key], rev, controls)
        stack, residue = coverage(rev, controls, hub, r4_r5, spoke_na)
        covered = sum(stack.values())
        print(f"\n=== {titles[key]} ===", file=sys.stderr)
        print(f"  baseline controls: {len(controls)} ({rev})  |  covered by hub: {covered}  "
              f"|  residue: {len(residue)} ({round(100*covered/len(controls))}% covered)", file=sys.stderr)
        for k in ["implemented", "partially-inherited", "fully-inherited", "customer-responsibility", "planned", "not-applicable"]:
            if stack[k]:
                print(f"    {stack[k]:4}  {k}", file=sys.stderr)
        if residue:
            print(f"  residue ({len(residue)}): {residue[:18]}{' ...' if len(residue) > 18 else ''}", file=sys.stderr)


if __name__ == "__main__":
    main()
