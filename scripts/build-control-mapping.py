#!/usr/bin/env python3
# =============================================================================
# CONTROL MAPPING  800-53 Rev4 -> Rev5   (Phase 2 / D — the Rev4 bridge)
# =============================================================================
# Emits an OSCAL Control Mapping Model (v1.2.x) document mapping every NIST
# 800-53 Rev4 control to its Rev5 counterpart, derived AUTHORITATIVELY from the
# two vendored NIST OSCAL catalogs — no hand-keyed crosswalk:
#
#   - same id, Rev5 entry active        -> relationship "equivalent"
#   - same id, Rev5 entry withdrawn:
#       rel "incorporated-into" target  -> "subset-of"  (Rev4 control ⊆ target)
#       rel "moved-to"        target  -> "equivalent" (relocated)
#
# The withdrawal disposition (target) is taken from the Rev5 catalog control's
# own links (rel incorporated-into / moved-to) — i.e., from NIST, not us.
#
# This is the bridge the CMMC spoke rides: 800-171 Rev2 -> 800-53 Rev4 -> (here)
# -> Rev5 hub.  Source = Rev4 control, Target = Rev5 control.
# =============================================================================

import json
import uuid
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
R4 = REPO / "data/catalogs/NIST_SP-800-53_rev4_catalog.json"
R5 = REPO / "data/catalogs/NIST_SP-800-53_rev5_catalog.json"
OUT = REPO / "data/mappings/SP800-53_rev4-to-rev5.mapping.json"
NS = uuid.UUID("9c2b6d1a-4e5f-5a7b-8c0d-1e2f3a4b5c6d")
LAST_MODIFIED = "2026-06-09T00:00:00Z"


def index(path):
    cat = json.loads(path.read_text())["catalog"]
    out = {}
    def walk(n):
        for c in n.get("controls", []) or []:
            out[c["id"]] = c
            walk(c)
        for g in n.get("groups", []) or []:
            walk(g)
    walk(cat)
    return out


def sid(*p):
    return str(uuid.uuid5(NS, ":".join(p)))


def withdrawal_target(ctrl):
    """(target_control_id, rel) from a withdrawn control's links, or None."""
    for link in ctrl.get("links", []) or []:
        rel = link.get("rel")
        if rel in ("incorporated-into", "moved-to"):
            tgt = link.get("href", "").lstrip("#").split("_")[0]  # statement -> owning control
            return tgt, rel
    return None


def is_withdrawn(c):
    return any(p.get("name") == "status" and p.get("value") == "withdrawn"
               for p in c.get("props", []) or [])


def main():
    r4 = index(R4)
    r5 = index(R5)
    maps = []
    rels = Counter()
    unresolved = []
    for cid in sorted(r4):
        r5c = r5.get(cid)
        if r5c is None:
            unresolved.append((cid, "no same-id control in Rev5 catalog"))
            continue
        if is_withdrawn(r5c):
            wt = withdrawal_target(r5c)
            if not wt:
                unresolved.append((cid, "withdrawn in Rev5 with no successor (NIST: addressed generally / N-A)"))
                continue
            if wt[0] not in r5:
                unresolved.append((cid, f"withdrawn; incorporated into '{wt[0]}' (family-level, not a single control)"))
                continue
            tgt, rel = wt
            relationship = "subset-of" if rel == "incorporated-into" else "equivalent"
            remark = f"Rev4 {cid} withdrawn in Rev5; NIST disposition: {rel} {tgt}."
        else:
            tgt = cid
            relationship = "equivalent"
            remark = None
        rels[relationship] += 1
        m = {
            "uuid": sid("map", cid),
            "relationship": relationship,
            "sources": [{"type": "control", "id-ref": cid}],
            "targets": [{"type": "control", "id-ref": tgt}],
        }
        if remark:
            m["remarks"] = remark
        maps.append(m)

    doc = {
        "mapping-collection": {
            "uuid": sid("mapping-collection", "rev4-to-rev5"),
            "metadata": {
                "title": "NIST SP 800-53 Rev 4 → Rev 5 control mapping",
                "last-modified": LAST_MODIFIED,
                "version": "1.0.0",
                "oscal-version": "1.2.2",
                "remarks": (
                    "Derived deterministically from the vendored NIST OSCAL Rev4 and "
                    "Rev5 catalogs (data/catalogs/, see data/PROVENANCE.md). Same-id "
                    "active controls are mapped equivalent; controls withdrawn in Rev5 "
                    "follow the Rev5 catalog's own incorporated-into / moved-to link. "
                    "Note: 'equivalent' is catalog-level id equivalence; a subset of "
                    "same-id controls have substantive text changes between revisions "
                    "(FedRAMP's Rev4→Rev5 comparison flags these) and could be "
                    "refined to intersects-with."
                ),
            },
            "provenance": {
                "method": "automation",
                "matching-rationale": "syntactic",
                "status": "complete",
                "mapping-description": (
                    "NIST SP 800-53 Rev 4 to Rev 5 control mapping, derived "
                    "deterministically (automation) from the two vendored NIST OSCAL "
                    "catalogs: same-id active controls map equivalent; controls "
                    "withdrawn in Rev5 follow the Rev5 catalog's own incorporated-into "
                    "/ moved-to link. No hand-keyed crosswalk."
                ),
            },
            "mappings": [{
                "uuid": sid("mapping", "rev4-rev5"),
                "source-resource": {"type": "resource", "href": "#resource-rev4-catalog"},
                "target-resource": {"type": "resource", "href": "#resource-rev5-catalog"},
                "maps": maps,
            }],
            "back-matter": {
                "resources": [
                    {"uuid": sid("resource", "rev4"), "title": "NIST SP 800-53 Rev 4 catalog (OSCAL)",
                     "props": [{"name": "id", "value": "resource-rev4-catalog"}],
                     "rlinks": [{"href": "../catalogs/NIST_SP-800-53_rev4_catalog.json"}]},
                    {"uuid": sid("resource", "rev5"), "title": "NIST SP 800-53 Rev 5 catalog (OSCAL)",
                     "props": [{"name": "id", "value": "resource-rev5-catalog"}],
                     "rlinks": [{"href": "../catalogs/NIST_SP-800-53_rev5_catalog.json"}]},
                ]
            },
        }
    }
    doc["mapping-collection"]["metadata"]["remarks"] += (
        f" RESIDUE — {len(unresolved)} Rev4 control(s) with no clean single Rev5 "
        f"successor (recorded, not silently dropped): "
        + "; ".join(f"{c} ({r})" for c, r in unresolved) + "."
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=2) + "\n")

    print(f"Rev4 controls mapped: {len(maps)} / {len(r4)}")
    print(f"  relationships: {dict(rels)}")
    print(f"  residue (no clean successor, recorded in doc): {len(unresolved)}")
    for c, r in unresolved:
        print(f"    {c}: {r}")
    # spot-checks against what we know
    by_src = {m['sources'][0]['id-ref']: m for m in maps}
    for cid in ["ac-1", "ac-2.10", "si-3.1", "ca-3.3"]:
        m = by_src.get(cid)
        if m:
            print(f"  {cid:8} -> {m['targets'][0]['id-ref']:8} [{m['relationship']}]")
    print(f"wrote: {OUT.relative_to(REPO)}")


if __name__ == "__main__":
    main()
