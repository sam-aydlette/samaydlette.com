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
import sys
import uuid as uuid_module
from datetime import datetime, timezone
from pathlib import Path


OSCAL_VERSION = "1.1.2"
FEDRAMP_NS = "https://fedramp.gov/ns/oscal"
SSP_HREF = "https://samaydlette.com/.well-known/oscal-ssp.json"
SYSTEM_ID = "urn:samaydlette:website-prod"
SYSTEM_NAME_ORG = "samaydlette.com"


# =============================================================================
# POA&M ITEMS (mirrors docs/poam.md; both are hand-maintained for now)
# =============================================================================
# The structure here is data-only. The script below converts each entry into
# an OSCAL poam-item with FedRAMP-namespaced props.
# =============================================================================

POAM_ITEMS = [
    {
        "id": "POAM-001",
        "title": "Long-lived AWS access keys for the deployer",
        "description": (
            "The CI deployer authenticates to AWS using an IAM user's access key + "
            "secret access key, stored in GitHub Actions encrypted secrets. If either "
            "secret leaks, the credentials remain valid until manually rotated. As an "
            "active compensating control while the OIDC migration is deferred, the "
            "operator rotates the AWS access key every 90 days; the procedure is "
            "documented in docs/policies/secure-configuration-guide.md and the "
            "rotation log is tracked in docs/security-review.md. The 90-day cadence "
            "bounds the leakage window but does not eliminate the standing-privilege "
            "surface; this POA&M item remains open until the OIDC migration is "
            "complete."
        ),
        "controls": ["ia-2", "ia-5", "ac-2"],
        "weakness_detector_source": "CodeGuard rule codeguard-0-iac-security",
        "weakness_source_identifier": "codeguard-0-iac-security",
        "asset_identifiers": [
            "aws-iam-user::github-actions-deployer",
            "github-secret::AWS_ACCESS_KEY_ID",
            "github-secret::AWS_SECRET_ACCESS_KEY",
        ],
        "point_of_contact": "Sam Aydlette (operator)",
        "resources_required": "Operator time (~half day); no additional cost.",
        "remediation_plan": (
            "Migrate to GitHub OIDC role assumption against AWS. Provision an "
            "aws_iam_openid_connect_provider for token.actions.githubusercontent.com "
            "and a deployer role whose trust policy restricts sub to "
            "repo:sam-aydlette/samaydlette.com:*. Switch the workflow's "
            "aws-actions/configure-aws-credentials step from access-key inputs to "
            "role-to-assume. Verify, then delete the IAM user and remove the GitHub "
            "Actions secrets."
        ),
        "original_detection_date": "2026-05-06",
        "scheduled_completion_date": "2026-08-31",
        "status_date": "2026-05-08",
        "vendor_dependency": False,
        "original_risk_rating": "moderate",
        "adjusted_risk_rating": None,
        "risk_adjustment": False,
        "status": "closed",  # POAM-001 closed 2026-06-15: migrated to GitHub OIDC; legacy user/key/secrets deleted
        "category": "closed",
    },
    {
        "id": "POAM-002",
        "title": "Runtime KSI signal not cryptographically signed",
        "description": (
            "Closed under Task 5 (2026-06-17): the runtime emitter now signs the "
            "runtime signal with an asymmetric KMS key (ECC NIST P-256, SIGN_VERIFY). "
            "It canonicalizes the signal with provenance.attestation absent "
            "(sorted-keys JSON, no whitespace), signs the SHA-256 digest with "
            "ECDSA_SHA_256, places the signature in provenance.attestation, and "
            "publishes the verifying public key at "
            "/.well-known/runtime-signing-pubkey.pem. A consumer verifies the "
            "runtime signal cryptographically without trusting the well-known URL."
        ),
        "controls": ["au-10", "si-7", "sc-12", "sc-13"],
        "weakness_detector_source": "Internal review",
        "weakness_source_identifier": "internal-review-2026-05-06",
        "asset_identifiers": [
            "aws-lambda::compliance-monitor",
            "aws-s3-key::.well-known/ksi-signal-runtime.json",
        ],
        "point_of_contact": "Sam Aydlette (operator)",
        "resources_required": "Operator time (~half day); ~$1/month KMS cost.",
        "remediation_plan": (
            "AWS KMS asymmetric signing in the Lambda. Provision an ECC NIST P-256 "
            "key with key_usage = SIGN_VERIFY, grant the Lambda role kms:Sign and "
            "kms:GetPublicKey, sign the canonical-form bytes, embed the signature "
            "in provenance.attestation, and publish the public key at "
            "/.well-known/runtime-signing-pubkey.pem."
        ),
        "original_detection_date": "2026-05-06",
        "scheduled_completion_date": "2026-06-17",
        "status_date": "2026-06-17",
        "vendor_dependency": False,
        "original_risk_rating": "low",
        "adjusted_risk_rating": None,
        "risk_adjustment": False,
        "status": "closed",
        "category": "closed",
    },
    # Configuration Findings (Checkov suppressions; all currently risk-accepted)
    {
        "id": "POAM-003", "controls": ["cp-9"],
        "title": "S3 cross-region replication not configured",
        "description": "Single-region static site. Cross-region replication adds cost without commensurate availability benefit at the declared 21-day RTO.",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_144",
        "asset_identifiers": ["aws-s3-bucket::website-prod"],
        "original_risk_rating": "low", "adjusted_risk_rating": None, "risk_adjustment": False,
        "status": "false-positive", "category": "false-positive",
    },
    {
        "id": "POAM-004", "controls": ["au-2"],
        "title": "S3 event notifications not configured",
        "description": "Lambda writes to S3 but does not subscribe to S3 events. No event-driven workflow in scope.",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_23",
        "asset_identifiers": ["aws-s3-bucket::website-prod"],
        "original_risk_rating": "low", "adjusted_risk_rating": None, "risk_adjustment": False,
        "status": "false-positive", "category": "false-positive",
    },
    {
        "id": "POAM-005", "controls": ["au-2", "au-3"],
        "title": "S3 access logging not enabled",
        "description": "Closed under Task 7 (2026-06-18): the website bucket now writes S3 server access logs to a dedicated locked-down log bucket (samaydlette-com-logs), authorized by a bucket policy scoped to the S3 log-delivery service from this account/source bucket. The global CKV_AWS_18 suppression was removed; the check passes on its own. CloudFront access logging is enabled out-of-band to the same bucket (C-3).",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_18",
        "asset_identifiers": ["aws-s3-bucket::website-prod"],
        "original_risk_rating": "low", "adjusted_risk_rating": None, "risk_adjustment": False,
        "status_date": "2026-06-18",
        "status": "closed", "category": "closed",
    },
    {
        "id": "POAM-006", "controls": ["si-12"],
        "title": "S3 lifecycle configuration not defined",
        "description": "Closed under Task 8b (2026-06-18): the versioned website bucket now has a lifecycle configuration (abort incomplete multipart uploads after 7 days; expire non-current versions after 90 days; live versions never expired). The CKV_AWS_300 suppression was removed; the check passes on its own.",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_300",
        "asset_identifiers": ["aws-s3-bucket::website-prod"],
        "original_risk_rating": "low", "adjusted_risk_rating": None, "risk_adjustment": False,
        "status_date": "2026-06-18",
        "status": "closed", "category": "closed",
    },
    {
        "id": "POAM-007", "controls": ["sc-7", "si-4"],
        "title": "CloudFront WAF not attached",
        "description": "Cost trade-off (~$120/year). Static personal site has no forms, no auth endpoints, no expensive backend; AWS Shield Standard is the baseline DDoS protection at zero marginal cost.",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_68",
        "asset_identifiers": ["aws-cloudfront-distribution"],
        "original_risk_rating": "moderate", "adjusted_risk_rating": "low", "risk_adjustment": True,
        "status": "risk-accepted", "category": "configuration",
    },
    {
        "id": "POAM-008", "controls": ["si-3"],
        "title": "Log4j-specific WAF rules not configured",
        "description": "No Java runtime in scope (Lambda runs Node.js; site is static HTML/CSS/JS). Log4j-class vulnerabilities cannot exist in this stack.",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_174",
        "asset_identifiers": ["aws-cloudfront-distribution"],
        "original_risk_rating": "low", "adjusted_risk_rating": None, "risk_adjustment": False,
        "status": "false-positive", "category": "false-positive",
    },
    {
        "id": "POAM-009", "controls": ["cp-2", "cp-7"],
        "title": "CloudFront origin failover not configured",
        "description": "Single S3 origin. No secondary origin to fail over to; multi-origin would require multi-region storage (see POAM-016).",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_86",
        "asset_identifiers": ["aws-cloudfront-distribution"],
        "original_risk_rating": "low", "adjusted_risk_rating": None, "risk_adjustment": False,
        "status": "risk-accepted", "category": "configuration",
    },
    {
        "id": "POAM-010", "controls": ["sc-7"],
        "title": "Lambda VPC configuration absent",
        "description": "Lambda has no internet egress, no sensitive data, no private endpoint targets. NAT Gateway (~$45/month) adds cost without commensurate isolation benefit.",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_117",
        "asset_identifiers": ["aws-lambda::compliance-monitor"],
        "original_risk_rating": "low", "adjusted_risk_rating": None, "risk_adjustment": False,
        "status": "risk-accepted", "category": "configuration",
    },
    {
        "id": "POAM-011", "controls": ["sc-12", "sc-28"],
        "title": "Lambda environment variables not customer-key encrypted",
        "description": "Closed under Task 6 (2026-06-16): every Lambda environment block is now encrypted with a customer-managed CMK (compliance Lambda -> at_rest CMK; silk-reeling Lambda -> silk_reeling CMK). The global CKV_AWS_173 Checkov suppression was removed; the check passes on its own.",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_173",
        "asset_identifiers": ["aws-lambda::compliance-monitor"],
        "original_risk_rating": "low", "adjusted_risk_rating": None, "risk_adjustment": False,
        "status_date": "2026-06-16",
        "status": "closed", "category": "closed",
    },
    {
        "id": "POAM-012", "controls": ["sc-5"],
        "title": "Lambda concurrent execution limit not set",
        "description": "Reclassified false positive (Task 8b): reserved concurrency manages concurrency contention/DoS, but the compliance monitor is a daily EventBridge-triggered internal function with no DoS exposure or contention. SC-5 is met at the system boundary (CloudFront + API Gateway throttling + AWS Shield Standard); the check is N/A here, and the account is hard-capped at 10 concurrency so reservation is infeasible regardless.",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_115",
        "asset_identifiers": ["aws-lambda::compliance-monitor"],
        "original_risk_rating": "low", "adjusted_risk_rating": None, "risk_adjustment": False,
        "status": "false-positive", "category": "false-positive",
    },
    {
        "id": "POAM-013", "controls": ["si-4"],
        "title": "Lambda DLQ not configured",
        "description": "Closed under Task 8b (2026-06-18): the compliance Lambda now has an SQS dead-letter queue (SSE-SQS, 14-day retention) via dead_letter_config, so a failed daily async invocation is captured for inspection. The CKV_AWS_116 suppression was removed; the check passes on its own.",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_116",
        "asset_identifiers": ["aws-lambda::compliance-monitor"],
        "original_risk_rating": "low", "adjusted_risk_rating": None, "risk_adjustment": False,
        "status_date": "2026-06-18",
        "status": "closed", "category": "closed",
    },
    {
        "id": "POAM-014", "controls": ["au-2"],
        "title": "Lambda X-Ray tracing not enabled",
        "description": "Observability concern, not a security control. Cost-driven exclusion; CloudWatch Logs covers the diagnostic need.",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_50",
        "asset_identifiers": ["aws-lambda::compliance-monitor"],
        "original_risk_rating": "low", "adjusted_risk_rating": None, "risk_adjustment": False,
        "status": "false-positive", "category": "false-positive",
    },
    {
        "id": "POAM-015", "controls": ["si-7", "sa-12"],
        "title": "Lambda zip not signed via AWS Signer",
        "description": "Reclassified false positive (Task 8b): CKV_AWS_272 flags the absence of one specific signing tool (AWS Signer); no control mandates that tool. SI-7/SA-12 software and supply-chain integrity is established via the Sigstore source-signing chain (deploy-time KSI signal Sigstore-signed and anchored in the public Rekor log; Wasm policy bytes verify against the canonical inventory hash) plus the GitHub OIDC / GitOps chain of custody with no out-of-band code path.",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_272",
        "asset_identifiers": ["aws-lambda::compliance-monitor"],
        "original_risk_rating": "moderate", "adjusted_risk_rating": "low", "risk_adjustment": True,
        "status": "false-positive", "category": "false-positive",
    },
    {
        "id": "POAM-017", "controls": ["au-11"],
        "title": "CloudWatch log retention shorter than 1 year (7-day retention)",
        "description": "Closed under Task 7 (2026-06-18): every CloudWatch log group now has 365-day retention (AU-11). The route53 query-log and silk-reeling Lambda groups were raised from 7 days; the compliance group was already 365 (Task 6). The global CKV_AWS_338 Checkov suppression was removed; the check passes on its own.",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_338",
        "asset_identifiers": ["aws-cloudwatch-log-group::route53-query-log", "aws-cloudwatch-log-group::lambda-execution"],
        "original_risk_rating": "low", "adjusted_risk_rating": None, "risk_adjustment": False,
        "status_date": "2026-06-18",
        "status": "closed", "category": "closed",
    },
    {
        "id": "POAM-018", "controls": ["sc-28"],
        "title": "CloudWatch log group not customer-key encrypted (uses AWS-default encryption)",
        "description": "Closed under Task 6 (2026-06-16): every CloudWatch log group is now encrypted with a customer-managed CMK (compliance Lambda + route53 query-log groups -> at_rest CMK; silk-reeling log group -> silk_reeling CMK). The global CKV_AWS_158 Checkov suppression was removed; the check passes on its own.",
        "weakness_detector_source": "Checkov", "weakness_source_identifier": "CKV_AWS_158",
        "asset_identifiers": ["aws-cloudwatch-log-group::route53-query-log", "aws-cloudwatch-log-group::lambda-execution"],
        "original_risk_rating": "low", "adjusted_risk_rating": None, "risk_adjustment": False,
        "status_date": "2026-06-16",
        "status": "closed", "category": "closed",
    },
]


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


def _prop(name, value, ns=FEDRAMP_NS):
    """Build an OSCAL prop dict, omitting empty values per OSCAL conventions."""
    if value is None or value == "":
        return None
    return {"name": name, "ns": ns, "value": str(value)}


def _build_props_for_item(item, defaults):
    """Produce the full FedRAMP-namespaced props list for a poam-item."""
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
        ("status", item.get("status")),
        ("category", item.get("category")),
    ]
    return [p for p in (_prop(name, value) for name, value in pairs) if p is not None]


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
        ],
        "remarks": (
            "This Plan of Action and Milestones is a self-attested proof-of-concept artifact. "
            "The system it describes is NOT FedRAMP-certified. No FedRAMP Recognized independent assessment has been "
            "conducted; no agency Authorization to Operate is in place. The POA&M is published "
            "to demonstrate an architectural pattern (canonical-inventory-derived OSCAL artifacts) "
            "aligned with FedRAMP NTC-0009. Treat all entries as the operator's self-attestation. "
            "Companion artifacts: ksi-signal.json, oscal-ssp.json, vdr-report.json, iiw.csv at "
            "https://samaydlette.com/.well-known/. See https://samaydlette.com/research/the-plumbing.html "
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
