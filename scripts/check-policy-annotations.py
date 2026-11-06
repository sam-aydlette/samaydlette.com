#!/usr/bin/env python3
"""Diff the policy rules' control annotations against the KSI catalog.

Every violation rule in infrastructure/policy/ carries a METADATA block with
`custom.nist_controls` and `custom.ksi_ids`. The FedRAMP KSI catalog
(infrastructure/schemas/ksi-catalog.json) is the single source of truth for
which NIST 800-53 controls a KSI carries; this script fails CI when a rule's
annotation drifts from the catalog:

  1. every declared ksi_id must exist in the catalog;
  2. every declared nist_control must be carried by at least one of the
     rule's declared KSIs (subset-of-union check);
  3. a rule declaring nist_controls must declare at least one ksi_id (no
     orphan control claims) — rules tracing to another framework entirely
     (e.g. Section 508) declare `framework:` and leave both lists empty;
  4. every rule-scoped annotation on a `violations` rule must carry the
     required custom fields (id, category, severity);
  5. every such rule states the Terraform resource types it evaluates in
     `custom.resource_types` (FRC-CSX-VVK: a rule counts as a method for a KSI
     only when it evaluated a resource of one of these types): a list of type
     names, each of which the rule's own file (or the policy's config data,
     config/*.json, which the rule reads) names as a string, or ["*"] for a
     rule that evaluates every resource, or [] for one that evaluates none (the
     gate's own input checks); `custom.runtime_only`, when present, is a
     boolean;
  6. `custom.credit`, when present, is "applies_to", and the rule's file
     exports that rule's id in an `applies_to` set ({"rule": "<id>", ...}):
     the rule earns a KSI method only for the resources its condition applied
     to (build-sdr.py rule_methods), never for mere type presence.

Usage: python3 scripts/check-policy-annotations.py [--policy-dir DIR]
Requires `opa` on PATH (the pinned version from the workflow).
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CATALOG = REPO / "infrastructure" / "schemas" / "ksi-catalog.json"
REQUIRED_CUSTOM_FIELDS = ("id", "category", "severity")


def load_catalog_controls():
    """ksi_id -> set of 800-53 control ids it carries."""
    catalog = json.loads(CATALOG.read_text())
    controls_by_ksi = {}
    for family in (catalog.get("KSI") or {}).values():
        for indicator in family.get("indicators", []) or []:
            controls_by_ksi[indicator["id"]] = {
                c["control_id"] for c in indicator.get("controls", []) or []
            }
    return controls_by_ksi


def load_rule_annotations(policy_dir):
    out = subprocess.run(
        ["opa", "inspect", "-a", str(policy_dir), "--format", "json"],
        capture_output=True, text=True, check=True,
    )
    doc = json.loads(out.stdout)
    rules = []
    for entry in doc.get("annotations", []) or []:
        ann = entry.get("annotations") or {}
        if ann.get("scope") != "rule":
            continue
        path = ".".join(
            str(p.get("value")) for p in entry.get("path", [])[1:]
        )
        if not path.endswith(".violations"):
            continue
        rules.append({
            "path": path,
            "file": (entry.get("location") or {}).get("file", "?"),
            "row": (entry.get("location") or {}).get("row", 0),
            "title": ann.get("title", ""),
            "custom": ann.get("custom") or {},
        })
    return rules


def resource_type_errors(custom, file_text):
    """Why a rule's resource_types / runtime_only annotation is malformed ([] if not)."""
    errs = []
    rts = custom.get("resource_types")
    if not isinstance(rts, list) or not all(isinstance(t, str) and t for t in rts):
        return ["custom.resource_types must be a list of Terraform resource types ([] when the rule evaluates "
                "no resource, [\"*\"] when it evaluates every one)"]
    if "*" in rts and rts != ["*"]:
        errs.append('custom.resource_types: "*" stands alone')
    elif len(set(rts)) != len(rts):
        errs.append("custom.resource_types lists a type twice")
    else:
        unnamed = [t for t in rts if t != "*" and f'"{t}"' not in file_text]
        if unnamed:
            errs.append(f"custom.resource_types {unnamed} are not named in the rule's file or the policy's config "
                        "data, so the rule cannot be evaluating them")
    if "runtime_only" in custom and not isinstance(custom["runtime_only"], bool):
        errs.append("custom.runtime_only must be true or false")
    return errs


def credit_errors(custom, file_text):
    """Why a rule's custom.credit annotation is malformed ([] if not)."""
    if "credit" not in custom:
        return []
    if custom["credit"] != "applies_to":
        return ['custom.credit must be "applies_to" (or absent for credit by resource type)']
    if f'"rule": "{custom.get("id")}"' not in file_text or "applies_to contains" not in file_text:
        return [f"custom.credit is applies_to but the rule's file exports no applies_to entry for {custom.get('id')}"]
    return []


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy-dir", default=str(REPO / "infrastructure" / "policy"))
    args = parser.parse_args(argv)

    controls_by_ksi = load_catalog_controls()
    rules = load_rule_annotations(args.policy_dir)
    config_text = "".join(f.read_text() for f in sorted(Path(args.policy_dir).glob("config/*.json")))

    if not rules:
        print("ERROR: no annotated violations rules found — the policy tree "
              "moved or annotations were stripped.", file=sys.stderr)
        return 1

    errors = []
    for rule in rules:
        where = f"{rule['file']}:{rule['row']} ({rule['custom'].get('id', rule['title'])})"
        custom = rule["custom"]

        for field in REQUIRED_CUSTOM_FIELDS:
            if not custom.get(field):
                errors.append(f"{where}: missing required custom field '{field}'")

        src = Path(rule["file"])
        text = (src.read_text() if src.is_file() else "") + config_text
        errors += [f"{where}: {e}" for e in resource_type_errors(custom, text)]
        errors += [f"{where}: {e}" for e in credit_errors(custom, src.read_text() if src.is_file() else "")]

        ksi_ids = custom.get("ksi_ids")
        nist_controls = custom.get("nist_controls")
        if ksi_ids is None or nist_controls is None:
            errors.append(f"{where}: custom.ksi_ids / custom.nist_controls must "
                          "be present (empty lists are allowed only with a "
                          "'framework' field naming the non-NIST framework)")
            continue

        if not ksi_ids and not nist_controls:
            if not custom.get("framework"):
                errors.append(f"{where}: no KSI/control lineage and no "
                              "'framework' declaring an alternative framework")
            continue

        if nist_controls and not ksi_ids:
            errors.append(f"{where}: declares nist_controls without any ksi_ids "
                          "— control claims must trace through a KSI")
            continue

        unknown = [k for k in ksi_ids if k not in controls_by_ksi]
        if unknown:
            errors.append(f"{where}: ksi_ids not in the catalog: {unknown}")
            continue

        allowed = set().union(*(controls_by_ksi[k] for k in ksi_ids))
        stray = [c for c in nist_controls if c not in allowed]
        if stray:
            errors.append(
                f"{where}: nist_controls {stray} are not carried by the "
                f"declared KSIs {ksi_ids} in the catalog"
            )

    if errors:
        print("Policy annotation / KSI catalog mismatches:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"OK: {len(rules)} annotated violation rules consistent with the KSI catalog")
    return 0


if __name__ == "__main__":
    sys.exit(main())
