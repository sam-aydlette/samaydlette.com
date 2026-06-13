#!/usr/bin/env python3
# =============================================================================
# OSCAL SCHEMA VALIDATION GATE  (Phase 2)
# =============================================================================
# Validates the authored OSCAL artifacts against the vendored NIST OSCAL v1.2.2
# JSON schemas (data/schemas/oscal/, from the usnistgov/OSCAL v1.2.2 release).
#
# OSCAL's JSON schemas use ECMA-262 regex (\p{...} Unicode property escapes) that
# Python's `re` cannot compile. Only those incompatible patterns are dropped;
# patterns that DO compile (notably the string type's ^\S(.*\S)?$) are kept and
# enforced, so an embedded newline in a parameter value is caught, not silently
# passed. Structure, required fields, types, and ENUMS are enforced throughout.
#
# Full Metaschema *constraint* validation (beyond JSON Schema) is the CI gold
# standard via NIST's `oscal-cli` (Java); wire it in CI. This gate is the fast
# local equivalent and has already caught field-name and enum errors.
#
# Usage: validate-oscal.py [--ssp PATH ...]   (extra generated SSPs to validate)
# Exit non-zero if any artifact fails.
# =============================================================================

import argparse
import re
import json
import sys
from pathlib import Path

from jsonschema import validators

REPO = Path(__file__).resolve().parent.parent
SCHEMAS = REPO / "data" / "schemas" / "oscal"

# Checked-in OSCAL artifacts -> their model schema.
ARTIFACTS = [
    ("Component Definition", REPO / "data/component-definitions/samaydlette-com-component-definition.json", "oscal_component_schema.json"),
    ("Rev4->Rev5 Mapping",   REPO / "data/mappings/SP800-53_rev4-to-rev5.mapping.json",                     "oscal_mapping_schema.json"),
    ("800-171r2 Catalog",    REPO / "data/catalogs/NIST_SP-800-171_rev2_catalog.json",                      "oscal_catalog_schema.json"),
    ("171r2->53r4 Mapping",  REPO / "data/mappings/SP800-171r2-to-SP800-53r4.mapping.json",                 "oscal_mapping_schema.json"),
    ("GovRAMP Mod+CJIS Prof",REPO / "data/profiles/govramp_moderate_cjis_profile.json",                     "oscal_profile_schema.json"),
    ("TX-RAMP L1 Profile",   REPO / "data/profiles/txramp_level1_profile.json",                             "oscal_profile_schema.json"),
    ("TX-RAMP L2 Profile",   REPO / "data/profiles/txramp_level2_profile.json",                             "oscal_profile_schema.json"),
]


def strip_patterns(o):
    # Strip ONLY the regex patterns Python's re cannot compile (OSCAL uses
    # ECMA-262 \p{...} Unicode property escapes). Patterns that DO compile —
    # notably the string type's ^\S(.*\S)?$ — are kept, so genuine violations
    # (e.g. an embedded newline in a parameter value) are actually caught rather
    # than silently passed.
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            if k == "pattern" and isinstance(v, str):
                try:
                    re.compile(v)
                    out[k] = v
                except re.error:
                    continue  # drop the incompatible pattern only
            else:
                out[k] = strip_patterns(v)
        return out
    if isinstance(o, list):
        return [strip_patterns(x) for x in o]
    return o


def validate(label, artifact_path, schema_name):
    schema = strip_patterns(json.loads((SCHEMAS / schema_name).read_text()))
    inst = json.loads(Path(artifact_path).read_text())
    errs = sorted(validators.validator_for(schema)(schema).iter_errors(inst),
                  key=lambda e: list(e.path))
    if not errs:
        print(f"  {label:24} VALID")
        return True
    print(f"  {label:24} {len(errs)} ERROR(S)")
    seen = set()
    for e in errs:
        k = (tuple(str(p) for p in list(e.path)[-3:]), e.message[:50])
        if k in seen:
            continue
        seen.add(k)
        print("       at", ".".join(str(p) for p in list(e.path)[-4:]), "->", e.message[:140])
        if len(seen) >= 8:
            break
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssp", action="append", default=[], help="generated SSP(s) to validate")
    a = ap.parse_args()

    print("=== OSCAL schema validation (NIST v1.2.2, patterns stripped) ===")
    ok = True
    for label, path, schema in ARTIFACTS:
        ok &= validate(label, path, schema)
    for sp in a.ssp:
        ok &= validate(f"SSP {Path(sp).name}", sp, "oscal_ssp_schema.json")

    print(f"\n{'ALL VALID' if ok else 'VALIDATION FAILED'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
