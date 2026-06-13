#!/usr/bin/env python3
# =============================================================================
# KSI SIGNAL INVENTORY GATE  (external review Task 6)
# =============================================================================
# Blocks the deploy if the emitted canonical inventory (ksi-signal.json) is
# malformed. The inventory is the join layer the whole architecture rests on, so
# a malformed identifier is a correctness defect, not a cosmetic one. This gate
# runs AFTER the signal is built and BEFORE it is signed/published, and exits
# non-zero on any violation.
#
# Checks:
#   - PURL spec-validity: every global_id.purl is a valid 'pkg:<type>/<name>@<ver>';
#     scoped npm namespaces are %40-encoded (a literal '@' right after pkg:npm/
#     is rejected); a version is present.
#   - native_id uniqueness: no two components share a native_id (Task 1).
#   - ecosystem-faithful typing: a component's PURL ecosystem matches its type
#     (pypi <-> pypi_package, npm <-> npm_package) (Task 2).
#
# Usage: validate-ksi-signal.py [ksi-signal.json]   (default: ./ksi-signal.json)
# =============================================================================

import json
import sys
from pathlib import Path

ECOSYSTEM_TYPE = {"pypi": "pypi_package", "npm": "npm_package"}


def purl_errors(purl):
    """Return a list of spec violations for one PURL ('' parts are fine)."""
    errs = []
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return [f"not a pkg: PURL: {purl!r}"]
    rest = purl[len("pkg:"):]
    if "/" not in rest:
        return [f"PURL has no type/name separator: {purl}"]
    ptype, body = rest.split("/", 1)
    if not ptype:
        errs.append(f"PURL has empty type: {purl}")
    # strip qualifiers (?...) and subpath (#...) before checking the version
    name_ver = body.split("#", 1)[0].split("?", 1)[0]
    if "@" not in name_ver or name_ver.rsplit("@", 1)[1] == "":
        errs.append(f"PURL has no @version: {purl}")
    # scoped npm namespace must be percent-encoded, not a literal '@'
    if ptype == "npm" and body.startswith("@"):
        errs.append(f"npm scope not %40-encoded (literal '@'): {purl}")
    return errs


def ecosystem_of(purl):
    if isinstance(purl, str) and purl.startswith("pkg:") and "/" in purl:
        return purl[len("pkg:"):].split("/", 1)[0]
    return None


def validate(signal):
    errors = []
    seen_native = {}
    components = signal.get("components") or []
    for c in components:
        purl = (c.get("global_id") or {}).get("purl")
        if purl:
            errors.extend(purl_errors(purl))
            eco = ecosystem_of(purl)
            expected = ECOSYSTEM_TYPE.get(eco)
            if expected and c.get("type") != expected:
                errors.append(f"type {c.get('type')!r} inconsistent with PURL ecosystem "
                              f"{eco!r} (expected {expected!r}): {purl}")
        nid = c.get("native_id")
        if nid:
            if nid in seen_native:
                errors.append(f"duplicate native_id: {nid}")
            seen_native[nid] = True
    return errors, len(components)


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("ksi-signal.json")
    signal = json.loads(path.read_text())
    errors, n = validate(signal)
    if errors:
        print(f"INVENTORY GATE FAILED: {len(errors)} violation(s) in {path}:", file=sys.stderr)
        for e in errors[:40]:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)
    print(f"INVENTORY GATE OK: {n} components (PURLs valid, native_id unique, typing consistent)")


if __name__ == "__main__":
    main()
