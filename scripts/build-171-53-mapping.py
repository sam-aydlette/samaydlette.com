#!/usr/bin/env python3
# =============================================================================
# 171 Rev2 -> 800-53 Rev4 OSCAL Control Mapping  (Phase 2 / CMMC)
# =============================================================================
# Emits the OSCAL Control Mapping from the checked-in source data
# (data/mappings/SP800-171r2-to-SP800-53r4.source.json), which was extracted
# from NIST SP 800-171 Rev2 Appendix D Table D-1 via pdfplumber word-geometry +
# manual verification of spanning cells. The 171 requirement is a tailored
# SUBSET of the relevant 800-53 control (per the publication), so relationship
# = subset-of. This is the CMMC projection rail: 171 req -> 53 Rev4 -> (Rev4->Rev5
# mapping) -> Rev5 hub.
# =============================================================================

import json
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "data/mappings/SP800-171r2-to-SP800-53r4.source.json"
OUT = REPO / "data/mappings/SP800-171r2-to-SP800-53r4.mapping.json"
NS = uuid.UUID("171b5300-0000-5000-8000-000000000043")


def sid(*p):
    return str(uuid.uuid5(NS, ":".join(p)))


def main():
    src = json.loads(SRC.read_text())
    mp = src["mapping"]
    none = src.get("no_800_53_mapping", [])
    residue = src.get("residue_unconfirmed", [])
    maps = []
    for req in sorted(mp):
        for ctl in sorted(mp[req]):
            maps.append({"uuid": sid("map", req, ctl), "relationship": "subset-of",
                         "sources": [{"type": "control", "id-ref": req}],
                         "targets": [{"type": "control", "id-ref": ctl}]})
    doc = {"mapping-collection": {
        "uuid": sid("mc", "171r2-53r4"),
        "metadata": {
            "title": "NIST SP 800-171 Rev2 -> 800-53 Rev4 control mapping (Appendix D, Table D-1)",
            "last-modified": "2026-06-10T00:00:00Z", "version": "1.0.0", "oscal-version": "1.2.2",
            "remarks": (f"From 800-171 Rev2 Appendix D Table D-1 (a 171 requirement is a tailored "
                        f"subset of the relevant 800-53 control). {len([k for k in mp if mp[k]])} "
                        f"requirements mapped; {len(none)} explicit no-800-53-mapping ({none}); "
                        f"RESIDUE pending verification: {residue}."),
        },
        "provenance": {"method": "hybrid", "matching-rationale": "functional", "status": "not-complete",
                       "mapping-description": ("NIST's authoritative 171->53 tailoring mapping (Table D-1); "
                                               "171 requirements are tailored subsets of the 800-53 controls.")},
        "mappings": [{"uuid": sid("m", "171-53"),
                      "source-resource": {"type": "resource", "href": "#res-171r2"},
                      "target-resource": {"type": "resource", "href": "#res-53r4"},
                      "maps": maps}],
        "back-matter": {"resources": [
            {"uuid": sid("r", "171"), "title": "NIST SP 800-171 Rev2 catalog",
             "props": [{"name": "id", "value": "res-171r2"}],
             "rlinks": [{"href": "../catalogs/NIST_SP-800-171_rev2_catalog.json"}]},
            {"uuid": sid("r", "53"), "title": "NIST SP 800-53 Rev4 catalog",
             "props": [{"name": "id", "value": "res-53r4"}],
             "rlinks": [{"href": "../catalogs/NIST_SP-800-53_rev4_catalog.json"}]}]},
    }}
    OUT.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"171->53 mapping: {len([k for k in mp if mp[k]])}/110 mapped, {len(maps)} links, "
          f"{len(none)} no-mapping, {len(residue)} residue")


if __name__ == "__main__":
    main()
