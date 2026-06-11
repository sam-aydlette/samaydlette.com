#!/usr/bin/env python3
# =============================================================================
# SPOKE PROJECTION GENERATOR  (Phase 2 / D — the reusable spoke)
# =============================================================================
# Projects a hub-derived source SSP (e.g. the 800-53 Rev5 SSP) THROUGH an OSCAL
# control mapping into a target framework's SSP, then computes the coverage stack
# and the projection residue. This is the additive thesis in one script: the
# evidence is never re-collected, only re-projected — one mapping per framework.
#
# In-scope target controls = those whose mapped source control is actually in the
# source SSP (i.e. the target view of what the system implements). Each projected
# requirement carries the source implementation + a note naming the mapping
# relationship; `subset-of` maps are flagged (target control covered by a broader
# source control).
#
# Usage: build-spoke.py --mapping M --source-ssp S --framework NAME [--output O]
# =============================================================================

import argparse
import importlib.util
import json
import uuid
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
NS = uuid.UUID("a1b2c3d4-e5f6-5a7b-8c9d-0e1f2a3b4c5d")


def _load(p):
    return json.loads(Path(p).read_text())


def load_mapping(path):
    doc = _load(path)["mapping-collection"]
    out = {}
    residue = doc["mappings"][0].get("uuid")  # placeholder; residue is in remarks
    for mp in doc["mappings"]:
        for e in mp["maps"]:
            out[e["sources"][0]["id-ref"]] = (e["targets"][0]["id-ref"], e["relationship"])
    return out


def _coverage_module():
    spec = importlib.util.spec_from_file_location("bc", str(REPO / "scripts/build-coverage.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mapping", required=True)
    ap.add_argument("--source-ssp", required=True)
    ap.add_argument("--framework", required=True)
    ap.add_argument("--target-profile-href", default="800-53 Rev 4")
    ap.add_argument("--output", default=None)
    a = ap.parse_args()

    mapping = load_mapping(a.mapping)
    src = _load(a.source_ssp)["system-security-plan"]["control-implementation"]["implemented-requirements"]
    src_irs = {ir["control-id"]: ir for ir in src}

    projected = []
    rel_counts = Counter()
    for tgt_cid, (src_cid, rel) in sorted(mapping.items()):
        s = src_irs.get(src_cid)
        if s is None:
            continue  # source control not in system scope -> target control out of scope
        rel_counts[rel] += 1
        props = [p for p in s.get("props", []) or []
                 if p["name"] in ("implementation-status", "control-origination")]
        note = f"Projected from NIST 800-53 Rev 5 {src_cid} via control-mapping relationship '{rel}'."
        if rel == "subset-of":
            note += (" The target (Rev4) control is a subset of the broader Rev5 control; "
                     "covered by that control's implementation.")
        projected.append({
            "uuid": str(uuid.uuid5(NS, "req:" + tgt_cid)),
            "control-id": tgt_cid,
            "props": props,
            "statements": [{
                "statement-id": f"{tgt_cid}_smt",
                "uuid": str(uuid.uuid5(NS, "stmt:" + tgt_cid)),
                "remarks": note,
            }],
        })

    ssp = {
        "system-security-plan": {
            "uuid": str(uuid.uuid5(NS, "ssp:" + a.framework)),
            "metadata": {"title": f"{a.framework} — projected from the 800-53 Rev5 hub",
                         "last-modified": "2026-06-09T00:00:00Z", "version": "1.0.0",
                         "oscal-version": "1.2.2"},
            "import-profile": {"href": a.target_profile_href},
            "control-implementation": {
                "description": (f"Projected from the 800-53 Rev5 SSP through "
                                f"data/mappings (additive: evidence re-projected, not re-collected)."),
                "implemented-requirements": projected,
            },
        }
    }

    bc = _coverage_module()
    cov = bc.build_coverage(ssp, a.framework)

    if a.output:
        Path(a.output).write_text(json.dumps(ssp, indent=2) + "\n")

    import sys
    print(f"=== spoke projection: {a.framework} ===", file=sys.stderr)
    print(f"  projected in-scope controls: {len(projected)}", file=sys.stderr)
    print(f"  via mapping relationship: {dict(rel_counts)}", file=sys.stderr)
    print(f"  coverage (determined): {cov['coverage']['determined_pct']}%", file=sys.stderr)
    for c in bc.CLASSES:
        n = cov["responsibility_stack"][c]
        if n:
            print(f"    {n:4}  {c}", file=sys.stderr)
    inh = cov["inheritable"]
    print(f"  inheritable: {inh['inheritance_touched']} "
          f"({inh['fraction_of_baseline']*100:.1f}% of projected baseline)", file=sys.stderr)
    print(f"  projection-quality residue: {rel_counts['subset-of']} controls covered via a "
          f"broader Rev5 control (subset-of); plus the 3 mapping-residue controls with no "
          f"Rev5 successor (recorded in the mapping doc).", file=sys.stderr)


if __name__ == "__main__":
    main()
