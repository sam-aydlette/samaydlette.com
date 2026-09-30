#!/usr/bin/env python3
# =============================================================================
# OSCAL POA&M GENERATOR (NIST SP 800-53 Rev 5 / OSCAL 1.1.2)
# =============================================================================
# Emits a NIST OSCAL Plan of Action and Milestones document conforming to the
# OSCAL POA&M model (oscal_poam_schema.json). The POA&M imports the SSP at
# /.well-known/oscal-ssp.json so the same canonical inventory backs both
# documents and an OSCAL-aware consumer can navigate from a POA&M item to
# the system component it concerns.
#
# Field structure aligns with FedRAMP Rev 5 Appendix O: Plan of Action and
# Milestones template. FedRAMP-specific fields (POA&M ID, Controls, Asset
# Identifier, Original Risk Rating, etc.) are emitted as props in the
# https://fedramp.gov/ns/oscal namespace alongside OSCAL-native fields.
#
# Inputs (read from CWD by default):
#   ksi-signal.json      For system-id, ownership, and component cross-refs
#   ../docs/poam.md      Source of truth for human-readable POA&M; hardcoded
#                        data below mirrors the entries.
#
# Output: oscal-poam.json
# =============================================================================

import argparse
import json
import os
import sys
import uuid as uuid_module
from datetime import datetime, timezone
from pathlib import Path

# Shared generator helpers. The insert is __file__-relative, so this script stays
# runnable standalone from any working directory (see scripts/_common.py).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import FEDRAMP_NS, OSCAL_VERSION  # noqa: E402


SSP_HREF = "https://samaydlette.com/.well-known/oscal-ssp.json"
SYSTEM_ID = "urn:samaydlette:website-prod"
SYSTEM_NAME_ORG = "samaydlette.com"


# =============================================================================
# POA&M ITEMS: data/poam-items.json (mirrored by docs/poam.md; reconciliation
# invariant (g) holds the two in parity)
# =============================================================================
# The items are data, kept out of this generator so each human risk decision is
# a reviewable record: an open risk-accepted, false-positive or
# operational-requirement item carries decided_by, decided_on and review_by.
# The script below converts each entry into an OSCAL poam-item.
# =============================================================================

POAM_ITEMS_PATH = Path(__file__).resolve().parent.parent / "data" / "poam-items.json"
POAM_ITEMS = json.loads(POAM_ITEMS_PATH.read_text())["items"]
# This system's own props (not FedRAMP-defined) use its namespace.
SITE_NS = "https://samaydlette.com/ns/oscal"


# Common defaults applied to every entry below the above (configuration findings)
CONFIG_FINDING_DEFAULTS = {
    "point_of_contact": "Sam Aydlette (operator)",
    "resources_required": "None at present (risk-accepted). If reactivated, cost and operator time per item.",
    "remediation_plan": "Reactivate the corresponding Checkov check by removing the inline #checkov:skip= annotation in infrastructure/main.tf, then implement the missing control. Cost varies per item.",
    "original_detection_date": "2026-05-06",
    "scheduled_completion_date": None,
    "status_date": "2026-05-08",
    "vendor_dependency": False,
}


def _bool_str(value):
    return "yes" if value is True else "no" if value is False else ""


# A POA&M item's `category` fully determines its lifecycle status and its
# disposition. Per the disposition model (assessment Task 1 follow-up): every
# tracked weakness — risk-accepted AND false-positive — stays OPEN so it is
# never silently dropped and every scanner finding has a live, referenceable
# home (each carries a poam_ref in the VDR). Only remediated items are closed.
#   status      ∈ {open, closed}                       — lifecycle
#   disposition ∈ {risk-accepted, false-positive,
#                  operational-requirement, remediated} — how it is handled
_CATEGORY_TO_STATE = {
    "closed":                  ("closed", "remediated"),
    "false-positive":          ("open",   "false-positive"),
    "configuration":           ("open",   "risk-accepted"),
    "interconnection":         ("open",   "risk-accepted"),
    "operational-requirement": ("open",   "operational-requirement"),
}


def _status_disposition(item):
    """Derive (status, disposition) from the item's category, falling back to
    any explicit status the item carries."""
    cat = item.get("category")
    if cat in _CATEGORY_TO_STATE:
        return _CATEGORY_TO_STATE[cat]
    # Unknown category: preserve whatever status the row declares; no disposition.
    return (item.get("status") or "open", item.get("disposition"))


def _prop(name, value, ns=FEDRAMP_NS):
    """Build an OSCAL prop dict, omitting empty values per OSCAL conventions."""
    if value is None or value == "":
        return None
    return {"name": name, "ns": ns, "value": str(value)}


def _build_props_for_item(item, defaults):
    """Produce the full FedRAMP-namespaced props list for a poam-item."""
    status, disposition = _status_disposition(item)
    pairs = [
        ("poam-id", item.get("id")),
        ("controls", ", ".join(item.get("controls", []))),
        ("weakness-detector-source", item.get("weakness_detector_source")),
        ("weakness-source-identifier", item.get("weakness_source_identifier")),
        ("asset-identifier", "; ".join(item.get("asset_identifiers", []))),
        ("point-of-contact", item.get("point_of_contact") or defaults.get("point_of_contact")),
        ("resources-required", item.get("resources_required") or defaults.get("resources_required")),
        ("remediation-plan-summary", item.get("remediation_plan") or defaults.get("remediation_plan")),
        ("original-detection-date", item.get("original_detection_date") or defaults.get("original_detection_date")),
        ("scheduled-completion-date", item.get("scheduled_completion_date") or defaults.get("scheduled_completion_date") or "n/a (risk-accepted)"),
        ("status-date", item.get("status_date") or defaults.get("status_date")),
        ("vendor-dependency", _bool_str(item.get("vendor_dependency", defaults.get("vendor_dependency", False)))),
        ("original-risk-rating", item.get("original_risk_rating")),
        ("adjusted-risk-rating", item.get("adjusted_risk_rating")),
        ("risk-adjustment", _bool_str(item.get("risk_adjustment", False))),
        ("status", status),
        ("disposition", disposition),
        ("category", item.get("category")),
    ]
    # The human decision behind an open item: who made it, when, and when it is
    # next reviewed.
    pairs_site = [
        ("decided-by", item.get("decided_by")),
        ("decided-on", item.get("decided_on")),
        ("review-by", item.get("review_by")),
    ]
    return [p for p in (_prop(name, value) for name, value in pairs) if p is not None] + \
        [p for p in (_prop(name, value, SITE_NS) for name, value in pairs_site) if p is not None]


def build_metadata(now_iso, system_uuid, ksi_signal):
    """OSCAL metadata with party + role for the operator."""
    # Single source of truth for categorization (assessment F-2 / Decision 1).
    _profile = json.loads((Path(__file__).resolve().parent.parent / "data" / "system-profile.json").read_text())
    _impact = _profile["impact_level"].lower()
    ownership = (ksi_signal or {}).get("ownership") or {}
    operator_name = ownership.get("system_owner") or "Sam Aydlette"
    operator_email = ownership.get("operator_contact")

    operator_party_uuid = str(uuid_module.uuid4())
    party = {
        "uuid": operator_party_uuid,
        "type": "person",
        "name": operator_name,
    }
    if operator_email:
        party["email-addresses"] = [operator_email]

    return {
        "title": f"{SYSTEM_NAME_ORG} Plan of Action and Milestones",
        "last-modified": now_iso,
        "version": "1.0.0",
        "oscal-version": OSCAL_VERSION,
        "roles": [
            {
                "id": "system-owner",
                "title": "System Owner",
            },
            {
                "id": "poam-poc",
                "title": "POA&M Point of Contact",
            },
        ],
        "parties": [party],
        "responsible-parties": [
            {"role-id": "system-owner", "party-uuids": [operator_party_uuid]},
            {"role-id": "poam-poc", "party-uuids": [operator_party_uuid]},
        ],
        "props": [
            {"name": "cloud-service-provider", "ns": FEDRAMP_NS, "value": operator_name},
            {"name": "cloud-service-offering", "ns": FEDRAMP_NS, "value": SYSTEM_NAME_ORG},
            {"name": "impact-level", "ns": FEDRAMP_NS, "value": _impact},
            {"name": "ksi-signal-id", "ns": "https://samaydlette.com/ns/oscal",
             "value": (ksi_signal or {}).get("signal_id", "unknown"),
             "remarks": "signal_id of the canonical inventory this POA&M was built from (reconciliation invariant e)"},
            {"name": "authorization-status", "ns": "https://samaydlette.com/ns/oscal", "value": "self-attested-proof-of-concept"},
            {"name": "fedramp-certified", "ns": "https://samaydlette.com/ns/oscal", "value": "false"},
            {"name": "bootstrap-scope-note", "ns": "https://samaydlette.com/ns/oscal",
             "value": "CI/CD identity plane is in the authorization boundary and inventoried",
             "remarks": ("The infrastructure/bootstrap module (GitHub OIDC provider, the "
                         "github-actions-deploy-oidc and assessment roles, the operators IAM "
                         "group, and their policies) is the CI/CD identity plane. Although it "
                         "lives in a separate Terraform state, these are the highest-privilege "
                         "identities governing the production system, so they are in the "
                         "authorization boundary and are inventoried in ksi-signal.json / iiw.csv "
                         "(ingested from the bootstrap state by build-ksi-signal.py). Their "
                         "security-relevant weaknesses are tracked as POAM-026 (operators IAM "
                         "group) and POAM-027 (deploy/assessment read-only IAM).")},
            {"name": "poam-id-gap-note", "ns": "https://samaydlette.com/ns/oscal",
             "value": "POAM-016 is intentionally not a formal item",
             "remarks": ("The POA&M numbering skips POAM-016 by design: it denotes the "
                         "single-region / no-cross-region architectural decision recorded in "
                         "docs/recovery-plan.md, referenced in prose by POAM-003/POAM-009. It is "
                         "not a Checkov/tfsec-surfaced weakness and is deliberately excluded from "
                         "the formal item set (see scripts/reconcile.py). The gap is intentional, "
                         "not a dropped item.")},
        ],
        "remarks": (
            "This Plan of Action and Milestones is a self-attested proof-of-concept artifact. "
            "The system it describes is NOT FedRAMP-certified. No FedRAMP Recognized independent assessment has been "
            "conducted; no agency Authorization to Operate is in place. The POA&M is published "
            "to demonstrate an architectural pattern (canonical-inventory-derived OSCAL artifacts) "
            "aligned with FedRAMP NTC-0009. Treat all entries as the operator's self-attestation. "
            "Companion artifacts: ksi-signal.json, oscal-ssp.json, vdr-report.json, iiw.csv at "
            "https://samaydlette.com/.well-known/. See https://samaydlette.com/trust/ "
            "for context."
        ),
    }


def build_poam_item(item, defaults):
    """One OSCAL poam-item entry from a POAM_ITEMS row."""
    item_uuid = str(uuid_module.uuid4())
    props = _build_props_for_item(item, defaults)
    return {
        "uuid": item_uuid,
        "title": item["title"],
        "description": item["description"],
        "props": props,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ksi-signal", default="ksi-signal.json", help="Path to live KSI signal (default: ksi-signal.json in CWD)")
    parser.add_argument("--output", default="oscal-poam.json", help="Output OSCAL POA&M JSON path (default: oscal-poam.json)")
    args = parser.parse_args()

    # Read KSI signal for ownership and system-id (best-effort).
    ksi_signal = None
    ksi_path = Path(args.ksi_signal)
    if ksi_path.exists():
        try:
            ksi_signal = json.loads(ksi_path.read_text())
        except json.JSONDecodeError:
            print(f"warning: {ksi_path} is not valid JSON; proceeding without ownership lookup", file=sys.stderr)

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    system_uuid = str(uuid_module.uuid4())

    poam_items = [build_poam_item(item, CONFIG_FINDING_DEFAULTS) for item in POAM_ITEMS]

    poam = {
        "plan-of-action-and-milestones": {
            "uuid": str(uuid_module.uuid4()),
            "metadata": build_metadata(now_iso, system_uuid, ksi_signal),
            "import-ssp": {"href": SSP_HREF},
            "system-id": {"id": SYSTEM_ID},
            "poam-items": poam_items,
        }
    }

    output_path = Path(args.output)
    output_path.write_text(json.dumps(poam, indent=2) + "\n")
    print(f"oscal-poam.json: {len(poam_items)} POA&M items emitted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
