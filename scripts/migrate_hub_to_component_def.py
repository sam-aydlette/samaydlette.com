#!/usr/bin/env python3
# =============================================================================
# HUB MIGRATION — CONTROL_OVERRIDES  ->  OSCAL Component Definition
# =============================================================================
# Phase 2 / A1. Lifts the per-control implementation data that currently lives
# inside build-oscal-ssp.py (the CONTROL_OVERRIDES dict) into a standalone OSCAL
# Component Definition — the implementation hub that every framework spoke reads.
#
# This is a deterministic, lossless re-expression: CONTROL_OVERRIDES is the
# source of truth, and the emitted Component Definition round-trips back to it
# exactly (asserted at the end). Origination decides which component satisfies a
# control; the origination value is also preserved as a prop so the regenerated
# SSP reproduces today's control-origination exactly.
#
# FAMILY_DEFAULTS is NOT migrated here — per the agreed design it becomes a
# generator projection rule ("controls in the resolved profile not covered by
# the hub are N/A-with-family-rationale"), not hub data.
#
# Output: data/component-definitions/samaydlette-com-component-definition.json
# =============================================================================

import importlib.util
import json
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SSP_GEN = REPO / "scripts" / "build-oscal-ssp.py"
OUT = REPO / "data" / "component-definitions" / "samaydlette-com-component-definition.json"
CATALOG_SOURCE = "../catalogs/NIST_SP-800-53_rev5_catalog.json"

# Fixed namespace + last-modified so the artifact is deterministic (it changes
# only when the hub content changes, not on every run).
NS = uuid.UUID("7b0c2a4e-1f3d-5a6b-8c9d-0e1f2a3b4c5d")
LAST_MODIFIED = "2026-06-09T00:00:00Z"
OSCAL_VERSION = "1.2.2"

# origination value -> (component key, component type, component title)
COMPONENTS = {
    "sp-system":    ("this-system",    "service", "samaydlette.com — cloud service offering (system-implemented controls)"),
    "shared":       ("this-system",    "service", "samaydlette.com — cloud service offering (system-implemented controls)"),
    "sp-corporate": ("operator-policy", "policy", "Operator policies and procedures"),
    "inherited":    ("aws-leveraged",  "service", "AWS (leveraged authorization)"),
}


def load_hub():
    spec = importlib.util.spec_from_file_location("bssp", str(SSP_GEN))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return dict(m.CONTROL_OVERRIDES)


def sid(*parts):
    return str(uuid.uuid5(NS, ":".join(parts)))


def build_component_definition(overrides):
    # Group implemented-requirements by component (per origination).
    comp_irs = {}  # comp_key -> list of implemented-requirement dicts
    comp_meta = {}  # comp_key -> (type, title)
    for cid, o in sorted(overrides.items()):
        orig = o["origination"]
        if orig not in COMPONENTS:
            raise SystemExit(f"unknown origination {orig!r} for control {cid}")
        ckey, ctype, ctitle = COMPONENTS[orig]
        comp_meta[ckey] = (ctype, ctitle)
        comp_irs.setdefault(ckey, []).append({
            "uuid": sid("ir", ckey, cid),
            "control-id": cid,
            "description": o["statement"],
            "props": [
                {"name": "implementation-status", "value": o["status"]},
                {"name": "control-origination", "value": orig},
            ],
        })

    components = []
    for ckey in sorted(comp_irs):
        ctype, ctitle = comp_meta[ckey]
        components.append({
            "uuid": sid("component", ckey),
            "type": ctype,
            "title": ctitle,
            "description": ctitle,
            "control-implementations": [{
                "uuid": sid("control-impl", ckey),
                "source": CATALOG_SOURCE,
                "description": (
                    f"Control implementations satisfied by the {ckey} component, "
                    "expressed once against the NIST 800-53 Rev 5 catalog (the hub). "
                    "Projected into each framework SSP via the spoke generators."
                ),
                "implemented-requirements": comp_irs[ckey],
            }],
        })

    return {
        "component-definition": {
            "uuid": sid("component-definition", "samaydlette-com"),
            "metadata": {
                "title": "samaydlette.com — control implementation hub (Component Definition)",
                "last-modified": LAST_MODIFIED,
                "version": "1.0.0",
                "oscal-version": OSCAL_VERSION,
                "remarks": (
                    "The implementation hub: per-control implementations expressed once "
                    "against 800-53 Rev 5, migrated losslessly from CONTROL_OVERRIDES. "
                    "Origination determines which component satisfies each control."
                ),
            },
            "components": components,
        }
    }


def roundtrip(cd):
    """Reconstruct {control_id: {status, origination, statement}} from the CD."""
    out = {}
    for comp in cd["component-definition"]["components"]:
        for ci in comp["control-implementations"]:
            for ir in ci["implemented-requirements"]:
                props = {p["name"]: p["value"] for p in ir["props"]}
                out[ir["control-id"]] = {
                    "status": props["implementation-status"],
                    "origination": props["control-origination"],
                    "statement": ir["description"],
                }
    return out


def main():
    overrides = load_hub()
    cd = build_component_definition(overrides)

    # Lossless round-trip assertion: the CD reproduces CONTROL_OVERRIDES exactly.
    rt = roundtrip(cd)
    assert rt == overrides, "ROUND-TRIP MISMATCH — migration is lossy"

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(cd, indent=2) + "\n")

    # Report
    from collections import Counter
    by_orig = Counter(o["origination"] for o in overrides.values())
    by_comp = Counter()
    for comp in cd["component-definition"]["components"]:
        n = sum(len(ci["implemented-requirements"]) for ci in comp["control-implementations"])
        by_comp[comp["type"] + ":" + comp["title"][:30]] = n
    print(f"hub controls migrated: {len(overrides)}  (round-trip: EXACT)")
    print(f"by origination: {dict(by_orig)}")
    print(f"components ({len(cd['component-definition']['components'])}):")
    for k, v in by_comp.items():
        print(f"  {v:4}  {k}")
    print(f"wrote: {OUT.relative_to(REPO)}")


if __name__ == "__main__":
    main()
