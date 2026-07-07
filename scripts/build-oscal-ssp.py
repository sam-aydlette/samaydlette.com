#!/usr/bin/env python3
# =============================================================================
# OSCAL SSP GENERATOR
# =============================================================================
# Produces oscal-ssp.json — a NIST OSCAL System Security Plan in the
# FedRAMP Rev 5 Moderate baseline shape, generated deterministically from the
# canonical inventory and the KSI catalog. Sits alongside the KSI signal at
# /.well-known/ for full Rev 5 transparency.
#
# Inputs:
#   - infrastructure/ksi-signal.json                        → live canonical inventory
#   - infrastructure/schemas/ksi-catalog.json               → FedRAMP KSI catalog
#                                                              (FRMR.KSI source)
#   - GITHUB_* env vars (when in CI)                        → metadata provenance
#
# Output:
#   - infrastructure/oscal-ssp.json                         → OSCAL SSP document
#
# Run from the infrastructure/ directory after build-ksi-signal.py:
#   python3 ../scripts/build-oscal-ssp.py
# =============================================================================

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# =============================================================================
# CONSTANTS
# =============================================================================

OSCAL_VERSION = "1.1.2"
SSP_VERSION = "1.0.0"
SYSTEM_NAMESPACE = uuid.UUID("8be0e36b-1be1-4c8a-b76f-1b9d6e4b0a53")  # arbitrary stable namespace

FEDRAMP_NS = "https://fedramp.gov/ns/oscal"

# FedRAMP-published Rev 5 Moderate baseline profile (canonical reference),
# pinned at the authoritative source. NOTE: FedRAMP's OSCAL content moved from
# GSA/fedramp-automation to OSCAL-Foundation/fedramp-resources (FedRAMP Notice
# 0009 / RFC-0024); this is the current resolvable home. The profile is also
# vendored at data/profiles/ (see data/PROVENANCE.md) and resolved against
# locally; this href is the public, pinned, resolvable reference.
FEDRAMP_PROFILE = (
    "https://raw.githubusercontent.com/OSCAL-Foundation/fedramp-resources/"
    "383977291aad960b0811faf6ebf5a893b0811f7f/"
    "baselines/rev5/json/FedRAMP_rev5_MODERATE-baseline_profile.json"
)

# In-scope KSIs for this system after the current gap-closure round.
# This list is the SSP's authoritative scope statement: it is the set of KSIs
# this system claims, and therefore (by transitivity through the KSI catalog's
# controls[] arrays) the set of NIST 800-53 controls in this SSP.
#
# CR26 final (2026-06-24) renumbered the KSIs to mnemonic IDs, retired the AFR
# (Authorization-by-FedRAMP) family, and renamed TPR -> SCR (Supply Chain Risk).
# All 46 KSIs are in scope for this Class C offering (the 5 Class-C-required
# indicators included); where an indicator applies only vacuously (e.g.
# KSI-SVC-RUD federal-customer-data removal, with no federal customer data held),
# the per-control implementation statement records the N/A.
IN_SCOPE_KSIS = {
    # Cybersecurity Education
    "KSI-CED-RAT",
    # Change Management
    "KSI-CMT-LMC", "KSI-CMT-RMV", "KSI-CMT-RVP", "KSI-CMT-VTD",
    # Cloud Native Architecture
    "KSI-CNA-DFP", "KSI-CNA-EIS", "KSI-CNA-IBP", "KSI-CNA-MAT",
    "KSI-CNA-OFA", "KSI-CNA-RNT", "KSI-CNA-RVP", "KSI-CNA-ULN",
    # Identity and Access Management
    "KSI-IAM-AAM", "KSI-IAM-APM", "KSI-IAM-ELP", "KSI-IAM-JIT",
    "KSI-IAM-SNU", "KSI-IAM-SUS",
    # Incident Response
    "KSI-INR-AAR", "KSI-INR-RIR", "KSI-INR-RPI",
    # Monitoring, Logging, and Auditing
    "KSI-MLA-ALA", "KSI-MLA-EVC", "KSI-MLA-LET", "KSI-MLA-OSM", "KSI-MLA-RVL",
    # Policy and Inventory
    "KSI-PIY-GIV", "KSI-PIY-RES", "KSI-PIY-RIS", "KSI-PIY-RSD", "KSI-PIY-RVD",
    # Recovery Planning
    "KSI-RPL-ABO", "KSI-RPL-ARP", "KSI-RPL-RRO", "KSI-RPL-TRC",
    # Supply Chain Risk (formerly Third-Party Risk / TPR)
    "KSI-SCR-MIT", "KSI-SCR-MON",
    # Service Configuration
    "KSI-SVC-ACM", "KSI-SVC-ASM", "KSI-SVC-EIS", "KSI-SVC-PRR",
    "KSI-SVC-RUD", "KSI-SVC-SIN", "KSI-SVC-VCM", "KSI-SVC-VRI",
}

# Maps each in-scope KSI to the documentation file that records its
# implementation. Used to populate `link` references in the SSP statements.
KSI_DOC_REFS = {
    "KSI-CED-RAT": "docs/training-log.md",
    "KSI-CMT-LMC": "docs/architecture-decisions.md",
    "KSI-CMT-RMV": "docs/architecture-decisions.md",
    "KSI-CMT-RVP": "docs/architecture-decisions.md",
    "KSI-CMT-VTD": "docs/architecture-decisions.md",
    "KSI-CNA-DFP": "docs/architecture-decisions.md",
    "KSI-CNA-EIS": "docs/architecture-decisions.md",
    "KSI-CNA-IBP": "docs/architecture-decisions.md",
    "KSI-CNA-MAT": "docs/architecture-decisions.md",
    "KSI-CNA-OFA": "docs/recovery-plan.md",
    "KSI-CNA-RNT": "docs/architecture-decisions.md",
    "KSI-CNA-RVP": "docs/architecture-decisions.md",
    "KSI-CNA-ULN": "docs/architecture-decisions.md",
    "KSI-IAM-AAM": "docs/architecture-decisions.md",
    "KSI-IAM-APM": "docs/architecture-decisions.md",
    "KSI-IAM-ELP": "docs/architecture-decisions.md",
    "KSI-IAM-JIT": "docs/architecture-decisions.md",
    "KSI-IAM-SNU": "infrastructure/main.tf",
    "KSI-IAM-SUS": "docs/incident-response.md",
    "KSI-INR-AAR": "docs/incident-response.md",
    "KSI-INR-RIR": "docs/incident-response.md",
    "KSI-INR-RPI": "docs/incident-response.md",
    "KSI-MLA-ALA": "docs/architecture-decisions.md",
    "KSI-MLA-EVC": "docs/architecture-decisions.md",
    "KSI-MLA-LET": "docs/architecture-decisions.md",
    "KSI-MLA-OSM": "infrastructure/policies.rego",
    "KSI-MLA-RVL": "docs/ksi-signal.md",
    "KSI-PIY-GIV": "docs/ksi-signal.md",
    "KSI-PIY-RES": "docs/security-review.md",
    "KSI-PIY-RIS": "docs/security-review.md",
    "KSI-PIY-RSD": "docs/architecture-decisions.md",
    "KSI-PIY-RVD": "website/.well-known/security.txt",
    "KSI-RPL-ABO": "docs/recovery-plan.md",
    "KSI-RPL-ARP": "docs/recovery-plan.md",
    "KSI-RPL-RRO": "docs/recovery-plan.md",
    "KSI-RPL-TRC": "docs/recovery-plan.md",
    "KSI-SCR-MIT": "docs/supply-chain.md",
    "KSI-SCR-MON": "docs/supply-chain.md",
    "KSI-SVC-ACM": "docs/architecture-decisions.md",
    "KSI-SVC-ASM": "infrastructure/main.tf",
    "KSI-SVC-EIS": "docs/architecture-decisions.md",
    "KSI-SVC-PRR": "docs/architecture-decisions.md",
    "KSI-SVC-RUD": "docs/supply-chain.md",
    "KSI-SVC-SIN": "infrastructure/main.tf",
    "KSI-SVC-VCM": "docs/architecture-decisions.md",
    "KSI-SVC-VRI": "docs/ksi-signal.md",
}

# =============================================================================
# CONTROL IMPLEMENTATION PROFILES
# =============================================================================
# OSCAL implementation-status values: implemented | partial | planned |
# alternative | not-applicable.
#
# FedRAMP-style control-origination values (as a `props.control-origination`):
#   sp-system   — implemented by this system's code/configuration
#   sp-corporate — implemented at the operator/organization level
#                  (training, policy, governance) rather than in code
#   shared      — partially inherited from AWS, partially this system's
#                  responsibility (e.g., we choose AES-256, AWS provides the
#                  cryptographic stack)
#   inherited   — fully inherited from AWS (physical security, hardware
#                  maintenance, hypervisor isolation)
#   customer-configured — would be configured by an end customer (N/A here;
#                  there is no end customer)
#   customer-provided   — would be provided by an end customer (N/A here)
#
# CONTROL_OVERRIDES holds explicit profiles for the controls the system
# actively implements with traceable evidence. FAMILY_DEFAULTS holds
# fall-throughs by control-family prefix for everything else. The `*-1`
# (policy-and-procedures) controls in every family route to a shared default.
# =============================================================================

def _load_hub_overrides():
    """Load the control-implementation hub (the OSCAL Component Definition) and
    reconstruct the {control_id: {status, origination, statement}} mapping the
    generator consumes. The Component Definition under data/component-definitions/
    is the source of truth for per-control implementations (Phase 2 / A1);
    origination is carried as a prop so this projection is exact."""
    import json as _json
    from pathlib import Path as _Path
    _cd = _json.loads((_Path(__file__).resolve().parent.parent
        / "data" / "component-definitions"
        / "samaydlette-com-component-definition.json").read_text())["component-definition"]
    _out = {}
    for _comp in _cd["components"]:
        for _ci in _comp["control-implementations"]:
            for _ir in _ci["implemented-requirements"]:
                _props = {_p["name"]: _p["value"] for _p in _ir["props"]}
                _out[_ir["control-id"]] = {
                    "status": _props["implementation-status"],
                    "origination": _props["control-origination"],
                    "statement": _ir["description"],
                }
    return _out


CONTROL_OVERRIDES = _load_hub_overrides()

# =============================================================================
# INVENTORY-DERIVED APP-AUTHENTICATION DISPOSITIONS
# =============================================================================
# The hub and the family fall-throughs were written for the pre-app system
# ("no human end users"). When the canonical inventory carries an
# identity_provider component (the Silk Reeling Cognito pool), the user-facing
# authentication controls are real and implemented — and when the app is torn
# down, they honestly revert to the hub/family dispositions. Deriving this
# from the inventory (not a hand-set flag) means the SSP cannot claim an
# authentication surface that isn't deployed, or deny one that is.
# =============================================================================

APP_AUTH_CONTROL_PROFILES = {
    "ia-2": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Every human user is uniquely identified and authenticated. The "
            "operator (sole organizational user) authenticates to GitHub with "
            "password plus TOTP MFA and to AWS via IAM with MFA; CI "
            "authenticates via ephemeral GitHub OIDC role assumption with no "
            "stored credentials. Application end-users authenticate through "
            "Amazon Cognito: individually invited accounts (admin-only "
            "creation), 14-character minimum password, mandatory TOTP MFA. "
            "The API Gateway data routes validate the Cognito-issued JWT "
            "before any application code runs (POAM-021/022 closed "
            "2026-06-22). This disposition is derived from the canonical "
            "inventory's identity_provider component and reverts if the "
            "application is decommissioned."
        ),
    },
    "ia-2.1": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "MFA for privileged accounts: the operator's GitHub and AWS "
            "identities — the only privileged accounts — require virtual "
            "TOTP MFA. Hardware (phishing-resistant) authenticators are the "
            "tracked upgrade under POAM-025 (operational requirement, open)."
        ),
    },
    "ia-2.2": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "MFA for non-privileged accounts: application end-user accounts "
            "in the Cognito pool have MFA configuration ON (mandatory TOTP); "
            "a user cannot complete sign-in without the second factor."
        ),
    },
    "ia-2.8": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Replay resistance: end-user sessions use short-lived, "
            "expiry-bound Cognito JWTs validated at the API Gateway; TOTP "
            "codes are one-time by construction; AWS API access uses "
            "SigV4-signed requests; CI tokens are single-run OIDC tokens. "
            "Phishing-resistant (WebAuthn) authenticators remain the "
            "documented upgrade path (POAM-025 direction)."
        ),
    },
    "ia-8": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Non-organizational users — the invited application end-users of "
            "the gated Silk Reeling app — are identified and authenticated "
            "through Amazon Cognito with mandatory TOTP MFA before the API "
            "Gateway authorizer admits any data-route request. No federal "
            "customer or agency users exist; anonymous public access is "
            "limited to the static site's read-only content."
        ),
    },
    "ac-7": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Unsuccessful logon attempts are bounded by Amazon Cognito's "
            "account lockout on repeated failures, and the API stage is "
            "throttled (20 req/s, burst 10), so credential guessing is both "
            "locked out per-account and rate-limited in aggregate "
            "(POAM-023 closed 2026-06-22)."
        ),
    },
    "ac-11": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Device session lock with pattern-hiding is a function of the "
            "end user's device, outside this system's boundary; the "
            "browser-based SPA holds no server-side session to lock. "
            "Exposure from an unattended session is bounded by AC-12's "
            "token expiry instead."
        ),
    },
    "ac-12": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Session termination is automatic: application sessions are "
            "Cognito-issued JWTs with bounded validity, enforced at the API "
            "Gateway authorizer on every request — an expired token "
            "terminates access with no server-side session to linger. "
            "Operator console/CLI sessions use AWS's default session "
            "expiration."
        ),
    },
}


def _app_auth_overrides(signal):
    """Return the app-authentication control profiles iff the canonical
    inventory carries an identity_provider component (the app's Cognito
    pool). An empty dict otherwise, so the pre-app dispositions apply."""
    components = signal.get("components") or []
    has_idp = any(c.get("type") == "identity_provider" for c in components)
    return APP_AUTH_CONTROL_PROFILES if has_idp else {}


FAMILY_DEFAULTS = {
    # Access Control — explicit overrides handle AC-2/3/4/6/17. The remaining
    # AC-* and AC-*.* enhancements are dominated by user-account features
    # (session lock, attribute-based access control, wireless access), most
    # of which are structurally not applicable to a system with no human end
    # users. The handful that aren't are inherited from AWS IAM defaults.
    "ac-": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Access Control family controls beyond those with explicit "
            "overrides (AC-2/3/4/6/17) and the inventory-derived "
            "app-authentication profiles (AC-7/11/12 while the gated app "
            "is deployed) are predominantly features of environments this "
            "system does not have: wireless interfaces, mobile clients, "
            "and multi-user internal session models. Those remaining "
            "controls are structurally not applicable; the few that are "
            "not user-centric (e.g., AC-20 use of external systems) are "
            "addressed by the AWS-managed service boundary."
        ),
    },
    # Audit — most enhancements are inherited from AWS (CloudTrail handles
    # the heavy lifting automatically); operator configures content/retention.
    "au-": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Audit family controls beyond those with explicit overrides "
            "(AU-2/3/12) are addressed through CloudWatch Logs (Lambda "
            "execution and API access logs, 365-day CMK-encrypted "
            "retention), the S3/CloudFront access logs in the dedicated "
            "log bucket, and the account's CloudTrail management-event "
            "capture for control-plane activity. Audit storage capacity, "
            "time-stamp generation, and audit-record protection are "
            "AWS-managed features of those services. Audit review cadence "
            "is documented in docs/architecture-decisions.md "
            "(KSI-MLA-RVL section)."
        ),
    },
    # Assessment, Authorization, and Monitoring — assessment is the OPA gate;
    # monitoring is the runtime emitter. Authorization-process sub-controls
    # (CA-2, CA-6) appear as separate not-applicable entries.
    "ca-": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Assessment, Authorization, and Monitoring family: control "
            "assessment is performed by the OPA gate at deploy time and the "
            "runtime KSI emitter at runtime; both produce structured "
            "validation records embedded in the KSI signal. System-level "
            "continuous monitoring is implemented via the runtime emitter "
            "(KSI-CNA-EIS). Authorization sub-controls in the FedRAMP sense "
            "(CA-2, CA-6) are tracked as separate not-applicable entries; "
            "no agency authorization is in scope."
        ),
    },
    # Configuration Management — explicit overrides handle CM-2/3/4/5/6/7/8;
    # the remaining enhancements (CM-2.2 automation, CM-3.4 security
    # representative, CM-7.5 authorized software, etc.) are addressed by
    # the same gitops + OPA mechanism.
    "cm-": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Configuration Management family controls beyond those with "
            "explicit overrides (CM-2/3/4/5/6/7/8) are addressed by the "
            "same mechanisms: gitops-driven change management, OPA gate "
            "evaluation on every PR, Terraform-defined immutable "
            "configuration, runtime drift detection by the KSI emitter. "
            "Enhancements specific to authorized-software management "
            "(CM-7.5) are addressed by the canonical inventory's npm "
            "component list with PURL identification and Dependabot "
            "monitoring."
        ),
    },
    # Identification and Authentication — most enhancements presume end users
    # and are not applicable; service-level I&A is shared with AWS.
    "ia-": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Identification and Authentication family controls beyond "
            "IA-3 (non-user identification, addressed via AWS IAM "
            "principals) and the inventory-derived app-authentication "
            "profiles (IA-2 and enhancements, IA-8, while the gated app "
            "is deployed) cover identity-proofing and authenticator-"
            "management machinery for user populations this system does "
            "not have; those remaining enhancements are structurally not "
            "applicable. Deployer authentication holds no stored "
            "credential at all: CI assumes a scoped role via ephemeral "
            "GitHub OIDC tokens (POAM-001 closed 2026-06-15)."
        ),
    },
    # Incident Response — explicit overrides handle IR-4/6/8; remaining
    # enhancements presume formal organizational IR structures and collapse
    # into self-attestation for a sole-operator system.
    "ir-": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Incident Response family controls beyond those with explicit "
            "overrides (IR-4/6/8) are addressed at the documentation level "
            "in docs/incident-response.md and via the security.txt external "
            "interface. Enhancements that presume formal organizational IR "
            "structures (IR-2 training programs for an IR workforce, IR-7 "
            "IR support staff, IR-3 IR testing exercises with multiple "
            "participants) collapse into self-attestation by the operator "
            "for a sole-operator system; the procedures and capabilities "
            "are in place. Tabletops are run annually per "
            "docs/security-review.md."
        ),
    },
    # System and Communications Protection — explicit overrides handle
    # SC-7/8/13; remaining enhancements are mostly inherited TLS/crypto
    # primitives from AWS or N/A for static-site architecture.
    "sc-": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "System and Communications Protection family controls beyond "
            "those with explicit overrides (SC-7/8/13) are addressed "
            "through AWS-managed TLS and cryptographic primitives "
            "(inherited; SC-12 cryptographic key management for ACM-issued "
            "certificates, SC-23 session authenticity for HTTPS) and the "
            "system's CloudFront response-headers policy (HSTS, frame-deny, "
            "content-type-options). Enhancements addressing static-site-"
            "irrelevant features (SC-2 application partitioning, SC-3 "
            "security function isolation, SC-39 process isolation for "
            "multi-tenant compute) are not applicable."
        ),
    },
    # System and Information Integrity — explicit overrides handle
    # SI-2/3/4/7; remaining enhancements are mostly addressed by the runtime
    # KSI emitter, the OPA gate, or are SI-7 enhancements covered already.
    "si-": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "System and Information Integrity family controls beyond those "
            "with explicit overrides (SI-2/3/4/7) are addressed by the "
            "same mechanisms: Sigstore-signed canonical inventory (SI-7 "
            "enhancements for software/firmware integrity), runtime KSI "
            "emitter for continuous integrity monitoring, OPA gate for "
            "input validation on Terraform configurations and HTML content. "
            "SI-10 and SI-11 (information input validation, error handling) "
            "are not applicable — the system processes no untrusted input "
            "at runtime."
        ),
    },

    # Awareness and Training — implemented; sole-operator self-attestation.
    "at-": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Training is self-attested in docs/training-log.md. The "
            "system has one employee (the operator), who holds every "
            "role; coverage of role-specific topics (privileged-access, "
            "development, IR/DR) collapses into ongoing professional "
            "reading and the artifacts produced. Effectiveness review is "
            "annual, recorded in docs/security-review.md. The training "
            "regimen is in place; external evidence (training certs, "
            "attendance logs) is not produced because there is no "
            "workforce to maintain rosters for."
        ),
    },
    # Contingency Planning — implemented; sp-system.
    "cp-": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Contingency planning is documented in docs/recovery-plan.md "
            "with declared RTO of 21 days and RPO of 24 hours. Backups "
            "are S3 object versioning + git history (RPO satisfied with "
            "orders of magnitude headroom). Recovery testing was "
            "exercised end-to-end during initial implementation; annual "
            "tabletops are scheduled. Enhancements that presume alternate "
            "processing sites or geographically distributed operations "
            "centers are tracked as separate not-applicable entries; the "
            "single-region static-site deployment does not exercise them."
        ),
    },
    # Maintenance — fully inherited (AWS handles all platform maintenance)
    "ma-": {
        "status": "implemented",
        "origination": "inherited",
        "statement": (
            "Inherited from AWS. AWS handles all hardware and platform "
            "maintenance under their FedRAMP certification. The system "
            "has no on-premises hardware and no operator-side "
            "maintenance actions; the Lambda runtime is AWS-managed."
        ),
    },
    # Media Protection — inherited
    "mp-": {
        "status": "implemented",
        "origination": "inherited",
        "statement": (
            "Inherited from AWS. The system stores no data outside "
            "AWS-managed storage services (S3 with server-side "
            "encryption; CloudWatch Logs). Storage media handling, "
            "sanitization, and disposal are AWS-managed under their "
            "FedRAMP certification."
        ),
    },
    # Physical and Environmental — inherited
    "pe-": {
        "status": "implemented",
        "origination": "inherited",
        "statement": (
            "Inherited from AWS. AWS data centers operate under their "
            "FedRAMP-certified physical and environmental security "
            "program. The system has no operator-managed physical "
            "facilities."
        ),
    },
    # Personnel Security — sole-operator: position-level controls collapse to
    # self-attestation; multi-person controls (separation, transfer) are
    # tracked as separate not-applicable entries.
    "ps-": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "The system is operated by a single individual (the author) "
            "who is the owner of the GitHub organization, the AWS "
            "account, and the data. Personnel security controls covering "
            "the operator's role (position designation, screening, "
            "responsibility assignment) are met by self-attestation. "
            "Controls that presume a workforce with multiple roles "
            "(separation procedures, transfer review, access revocation "
            "on personnel changes) are tracked as separate not-applicable "
            "entries. See docs/training-log.md and docs/security-review.md."
        ),
    },
    # Planning — implemented via the doc set
    "pl-": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Planning is documented across the docs/ tree: "
            "docs/architecture-decisions.md (system architecture and "
            "design choices), docs/security-review.md (annual planning "
            "cycle), docs/recovery-plan.md (contingency planning), "
            "docs/incident-response.md (response planning). Plans are "
            "version-controlled and reviewed annually."
        ),
    },
    # Program Management — sole-operator self-attestation; multi-person
    # roles tracked as separate not-applicable entries.
    "pm-": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Program management functions (governance, policy, investment "
            "review) collapse into self-attestation for a sole-operator "
            "system; reviews are recorded in docs/security-review.md. "
            "Enhancements that presume a CISO, a board, or an enterprise-"
            "architecture function are tracked as separate not-applicable "
            "entries."
        ),
    },
    # Risk Assessment — partial implementation via tooling
    "ra-": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Risk assessment is performed via the OPA gate at deploy "
            "time, automated SCA via Dependabot, and IaC scanning via "
            "Checkov + tfsec in CI. Findings are surfaced through "
            "GitHub Security and reviewed against severity gates. "
            "Annual review is recorded in docs/security-review.md."
        ),
    },
    # System and Services Acquisition — shared between AWS (managed services)
    # and the operator (OSS supply-chain controls).
    "sa-": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "The system uses AWS managed services (S3, CloudFront, "
            "Lambda, Route 53, ACM) and OSS dependencies (npm, "
            "Terraform providers, GitHub Actions). Acquisition controls "
            "for the AWS services are inherited under AWS's FedRAMP "
            "certification; OSS dependencies are subject to the supply-"
            "chain controls in docs/supply-chain.md. Enhancements that "
            "presume vendor-management agreements with custom contracts "
            "are tracked as separate not-applicable entries; a sole-"
            "operator consumer of public OSS has no contracts to manage."
        ),
    },
    # Supply chain — handled in detail by overrides + supply-chain doc
    "sr-": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Supply-chain risk management for this system is described "
            "in docs/supply-chain.md. PURL-based component identifi"
            "cation, Sigstore-signed provenance, automated monitoring "
            "(Dependabot), and SHA-pinning of build-chain components "
            "together cover the supply-chain controls. The canonical "
            "inventory is the SBOM-equivalent."
        ),
    },
}

# Default for any *-1 (policy and procedures) control across all families.
# Points at the per-family policy doc in docs/policies/, which is the
# authoritative -1 satisfaction artifact (one file per family, plus the
# Secure Configuration Guide). The 20x rule integration each policy
# enumerates (SCN, VDR, MAS, SCG, etc.) is also captured in those files.
POLICY_AND_PROCEDURES_DEFAULT = {
    "status": "implemented",
    "origination": "sp-corporate",
    "statement_template": (
        "Policies and procedures for the {family_name} ({family_code}) "
        "family are documented in docs/policies/{family_lower}-policy.md, "
        "which describes the family-level approach, scope, AWS-inherited "
        "responsibilities (where applicable, citing AWS authorization "
        "package AGENCYAMAZONEW), the FedRAMP 20x rule integration relevant "
        "to the family (e.g., SCN/VDR/MAS/SCG/CCM/ICP/UCM as applicable), "
        "and the review cadence. Reviews and updates occur on the cadences "
        "defined in docs/security-review.md and the per-policy doc."
    ),
}

# Controls that are conventionally inherited from the underlying CSP (AWS,
# in this implementation) under their own FedRAMP certification. These are
# emitted as implemented-requirement entries with status=implemented and
# origination=inherited regardless of whether an in-scope KSI references
# them — a real Rev 5 SSP must address the full Moderate baseline, and the 20x
# KSI catalog focuses on tenant-side capabilities, so the inherited families
# fall out of KSI scope and need to be added explicitly.
#
# Sources: AWS FedRAMP Authorization Boundary; FedRAMP Customer Responsibility
# Matrix conventions for IaaS-on-AWS deployments. The list below is
# conservative — only controls where the operator does nothing and the
# underlying CSP carries the entire responsibility.
#
# If a control here is also referenced by an in-scope KSI, the KSI-derived
# classification wins (it has more specific context); see the dedupe in
# build_control_implementation.
# FedRAMP Rev 5 Moderate baseline (323 controls). Source: FedRAMP-published
# Moderate-baseline profile. Every control here gets an implemented-requirement
# entry in the SSP, even if no in-scope KSI references it, because a real
# Rev 5 SSP must address the full baseline. Status and origination are
# resolved per-control via CONTROL_OVERRIDES → POLICY_AND_PROCEDURES_DEFAULT
# → FAMILY_DEFAULTS, with INHERITED_FROM_AWS overriding when applicable.
def _load_baseline_controls():
    """FedRAMP Rev 5 Moderate baseline control set (323), sourced authoritatively
    from the vendored FedRAMP-published resolved-profile catalog rather than a
    hand-maintained list (Phase 2 / A1 re-anchoring)."""
    import json as _json
    from pathlib import Path as _Path
    _cat = _json.loads((_Path(__file__).resolve().parent.parent / "data" / "profiles"
        / "FedRAMP_rev5_MODERATE-baseline-resolved-profile_catalog.json").read_text())["catalog"]
    _ids = set()
    def _walk(_g):
        for _c in _g.get("controls", []) or []:
            _ids.add(_c["id"]); _walk(_c)
        for _sg in _g.get("groups", []) or []:
            _walk(_sg)
    _walk(_cat)
    return frozenset(_ids)


def _norm_ctrl(_pid):
    import re as _re
    _m = _re.match(r"([a-z]{2})-0*(\d+)(?:\.0*(\d+))?$", _pid.split("_")[0])
    if not _m:
        return None
    _f, _n, _e = _m.groups()
    return f"{_f}-{_n}" + (f".{_e}" if _e else "")


def _normalize_ws(value):
    r"""Collapse internal whitespace runs (including newlines) to single spaces
    and strip the ends, so every emitted parameter/string value satisfies OSCAL's
    string pattern ^\S(.*\S)?$. Long ODP descriptions in the FedRAMP profile (e.g.
    ps-03_odp.01/.02) carry embedded paragraph breaks that would otherwise make
    the generated SSP invalid against the NIST OSCAL schema."""
    import re as _re
    return _re.sub(r"\s+", " ", value).strip()


def _load_fedramp_parameters():
    """FedRAMP-defined parameter values (264) from the vendored Moderate profile,
    grouped by control. Emitted as OSCAL set-parameters per implemented-requirement
    so the SSP documents the FedRAMP-required values (FedRAMP compliance)."""
    import json as _json
    from pathlib import Path as _Path
    _prof = _json.loads((_Path(__file__).resolve().parent.parent / "data" / "profiles"
        / "FedRAMP_rev5_MODERATE-baseline_profile.json").read_text())["profile"]
    _out = {}
    for _sp in _prof.get("modify", {}).get("set-parameters", []) or []:
        _cid = _norm_ctrl(_sp["param-id"])
        if not _cid:
            continue
        _entry = {"param-id": _sp["param-id"]}
        _vals = [_normalize_ws(_c["description"]) for _c in _sp.get("constraints", []) if _c.get("description")]
        if _vals:
            _entry["values"] = _vals
        _out.setdefault(_cid, []).append(_entry)
    return _out


FEDRAMP_PARAMS = _load_fedramp_parameters()
BASELINE_CONTROLS = _load_baseline_controls()

INHERITED_FROM_AWS = {
    # Physical and Environmental Protection — entirely AWS for cloud customers.
    # Moderate-baseline PE family.
    "pe-1": "Policy and Procedures",
    "pe-2": "Physical Access Authorizations",
    "pe-3": "Physical Access Control",
    "pe-6": "Monitoring Physical Access",
    "pe-8": "Visitor Access Records",
    "pe-12": "Emergency Lighting",
    "pe-13": "Fire Protection",
    "pe-14": "Environmental Controls",
    "pe-15": "Water Damage Protection",
    "pe-16": "Delivery and Removal",

    # Maintenance — AWS handles all platform and hardware maintenance.
    "ma-1": "Policy and Procedures",
    "ma-4": "Nonlocal Maintenance",
    "ma-5": "Maintenance Personnel",

    # Media Protection — AWS-managed storage media; AWS-handled disposal.
    "mp-1": "Policy and Procedures",
    "mp-2": "Media Access",
    "mp-6": "Media Sanitization",
    "mp-7": "Media Use",

    # Contingency — alternate sites and telecom are AWS-managed.
    # S3 storage is multi-AZ-durable (CP-6); CloudFront's global edge network
    # is the alternate processing path (CP-7); AWS provides the underlying
    # network and telecom (CP-8). Operator does not configure or maintain
    # any of these.
    "cp-6": "Alternate Storage Site",
    "cp-7": "Alternate Processing Site",
    "cp-8": "Telecommunications Services",

    # System and Services Acquisition — operator uses only currently-supported
    # AWS services and OSS dependencies that have active maintainers; AWS's
    # service-deprecation lifecycle is the inheritance source.
    "sa-22": "Unsupported System Components",

    # System and Communications Protection — DNS resolution is wholly managed
    # by Route 53. The operator configures hosted-zone records (covered under
    # CM-2 via Terraform) but the resolution infrastructure, integrity, and
    # availability are AWS's responsibility.
    "sc-20": "Secure Name/Address Resolution Service (Authoritative Source)",
    "sc-21": "Secure Name/Address Resolution Service (Recursive or Caching Resolver)",
    "sc-22": "Architecture and Provisioning for Name/Address Resolution Service",

    # Supply Chain — physical component disposal is AWS's responsibility for
    # all underlying hardware. Operator-side OSS dependency inspection and
    # disposal is covered under SR-3/SR-11 via the supply-chain doc.
    "sr-12": "Component Disposal",

    # Maintenance — Moderate adds maintenance-tools enhancements; AWS handles
    # all maintenance tooling and personnel under its FedRAMP certification.
    "ma-3": "Maintenance Tools",
    "ma-3.1": "Inspect Tools",
    "ma-3.2": "Inspect Media",
    "ma-3.3": "Prevent Unauthorized Removal",
    "ma-5.1": "Individuals Without Appropriate Access",
    "ma-6": "Timely Maintenance",

    # Physical and Environmental — Moderate adds power, intrusion, fire-
    # detection-and-suppression enhancements. All AWS-managed.
    "pe-4": "Access Control for Transmission",
    "pe-5": "Access Control for Output Devices",
    "pe-6.1": "Intrusion Alarms and Surveillance Equipment",
    "pe-9": "Power Equipment and Cabling",
    "pe-10": "Emergency Shutoff",
    "pe-11": "Emergency Power",
    "pe-13.1": "Detection Systems — Automatic Activation and Notification",
    "pe-13.2": "Suppression Systems — Automatic Activation and Notification",

    # Time synchronization — AWS provides NTP-synchronized infrastructure.
    "sc-45": "System Time Synchronization",
    "sc-45.1": "Synchronization with Authoritative Time Source",

    # Contingency — alternate-site enhancements: separation, accessibility,
    # priority of service. All AWS-managed at the infrastructure layer.
    "cp-6.1": "Separation from Primary Site",
    "cp-6.3": "Accessibility",
    "cp-7.1": "Separation from Primary Site",
    "cp-7.2": "Accessibility",
    "cp-7.3": "Priority of Service",
    "cp-8.1": "Priority of Service Provisions",
    "cp-8.2": "Single Points of Failure",
}

# Mapping of family code → human-readable name, for templated statements.
FAMILY_NAMES = {
    "ac": "Access Control",
    "at": "Awareness and Training",
    "au": "Audit and Accountability",
    "ca": "Assessment, Authorization, and Monitoring",
    "cm": "Configuration Management",
    "cp": "Contingency Planning",
    "ia": "Identification and Authentication",
    "ir": "Incident Response",
    "ma": "Maintenance",
    "mp": "Media Protection",
    "pe": "Physical and Environmental Protection",
    "pl": "Planning",
    "pm": "Program Management",
    "ps": "Personnel Security",
    "ra": "Risk Assessment",
    "sa": "System and Services Acquisition",
    "sc": "System and Communications Protection",
    "si": "System and Information Integrity",
    "sr": "Supply Chain Risk Management",
}


def resolve_control_profile(control_id, control_title, app_overrides=None):
    """Return (status, origination, statement) for a NIST 800-53 control.

    Resolution order:
      1. Inventory-derived app-authentication profile (present only while
         the canonical inventory carries an identity_provider component).
      2. Explicit per-control override in CONTROL_OVERRIDES.
      3. *-1 controls (policy and procedures) hit POLICY_AND_PROCEDURES_DEFAULT.
      4. Family default in FAMILY_DEFAULTS.
      5. Last-resort generic fallback.
    """
    if app_overrides and control_id in app_overrides:
        p = app_overrides[control_id]
        return p["status"], p["origination"], p["statement"]

    if control_id in CONTROL_OVERRIDES:
        p = CONTROL_OVERRIDES[control_id]
        return p["status"], p["origination"], p["statement"]

    # *-1 controls (e.g., ac-1, au-1, cm-1) — every family has one.
    if control_id.endswith("-1"):
        family_code = control_id.split("-", 1)[0]
        family_name = FAMILY_NAMES.get(family_code, family_code.upper())
        statement = POLICY_AND_PROCEDURES_DEFAULT["statement_template"].format(
            family_name=family_name,
            family_code=family_code.upper(),
            family_lower=family_code.lower(),
        )
        return (
            POLICY_AND_PROCEDURES_DEFAULT["status"],
            POLICY_AND_PROCEDURES_DEFAULT["origination"],
            statement,
        )

    # Family defaults — match by prefix.
    for prefix, profile in FAMILY_DEFAULTS.items():
        if control_id.startswith(prefix):
            return profile["status"], profile["origination"], profile["statement"]

    # No fallback. Every in-scope control must be handled either by an
    # explicit per-control override, the *-1 policy-and-procedures default,
    # or a family-level fall-through. A control reaching this branch means
    # a new KSI was added that references a control family we haven't
    # classified — we want the build to fail loudly so the gap is caught
    # before deploy, not papered over with a fake "planned" placeholder.
    raise ValueError(
        f"No implementation profile defined for control {control_id} "
        f"({control_title}). Add a CONTROL_OVERRIDES entry or a "
        f"FAMILY_DEFAULTS entry for the {control_id.split('-', 1)[0]}- "
        f"family in scripts/build-oscal-ssp.py."
    )


# =============================================================================
# HELPERS
# =============================================================================


def stable_uuid(name):
    """Generate a deterministic UUID v5 from a stable name."""
    return str(uuid.uuid5(SYSTEM_NAMESPACE, name))


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# =============================================================================
# OSCAL SECTION BUILDERS
# =============================================================================


def build_metadata(signal):
    return {
        "title": "samaydlette.com — System Security Plan (Self-Attested PoC, NOT FedRAMP-Certified)",
        "last-modified": now_iso(),
        "version": SSP_VERSION,
        "oscal-version": OSCAL_VERSION,
        "remarks": (
            "This System Security Plan is a self-attested proof-of-concept artifact. "
            "The system it describes is NOT FedRAMP-certified. No FedRAMP Recognized independent assessment has "
            "been conducted; no agency Authorization to Operate is in place. The SSP "
            "is published to demonstrate an architectural pattern (canonical-inventory-"
            "derived OSCAL artifacts) aligned with FedRAMP NTC-0009. Treat all "
            "implementation statements as the operator's self-attestation. Companion "
            "artifacts: ksi-signal.json, oscal-poam.json, vdr-report.json, iiw.csv at "
            "https://samaydlette.com/.well-known/. See "
            "https://samaydlette.com/research/the-plumbing.html for context."
        ),
        "parties": [
            {
                "uuid": stable_uuid("party:operator"),
                "type": "person",
                "name": "Sam Aydlette",
                "short-name": "operator",
                "email-addresses": ["sam.aydlette@gmail.com"],
            },
            {
                "uuid": stable_uuid("party:organization"),
                "type": "organization",
                "name": "samaydlette.com (sole-operator)",
                "short-name": "samaydlette",
            },
        ],
        "responsible-parties": [
            {
                "role-id": "system-owner",
                "party-uuids": [stable_uuid("party:operator")],
            },
            {
                "role-id": "authorizing-official",
                "party-uuids": [stable_uuid("party:operator")],
            },
            {
                "role-id": "system-poc-technical",
                "party-uuids": [stable_uuid("party:operator")],
            },
        ],
        "props": [
            {
                "name": "ksi-signal-source",
                "value": signal.get("signal_id", "unknown"),
                "remarks": "signal_id of the canonical inventory used as evidence for this SSP",
            },
            {
                "name": "ksi-signal-emitted-at",
                "value": signal.get("emitted_at", "unknown"),
            },
            {
                "name": "source-commit",
                "value": signal.get("provenance", {}).get("source", {}).get("commit", "unknown"),
            },
            {
                "name": "authorization-status",
                "ns": "https://samaydlette.com/ns/oscal",
                "value": "self-attested-proof-of-concept",
                "remarks": "This SSP is operator-self-attested; no FedRAMP Recognized independent assessment, no agency ATO.",
            },
            {
                "name": "fedramp-certified",
                "ns": "https://samaydlette.com/ns/oscal",
                "value": "false",
            },
            {
                "name": "cloud-service-provider",
                "ns": FEDRAMP_NS,
                "value": "Sam Aydlette",
            },
            {
                "name": "cloud-service-offering",
                "ns": FEDRAMP_NS,
                "value": "samaydlette.com",
            },
            {
                "name": "impact-level",
                "ns": FEDRAMP_NS,
                "value": "moderate",
            },
            {
                "name": "fedramp-class",
                "ns": FEDRAMP_NS,
                "value": "C",
                "remarks": "FedRAMP 20x Class C target; equivalent to traditional Moderate.",
            },
        ],
    }


def _silk_reeling_present(signal):
    """True when the gated Silk Reeling app Lambda is in the canonical inventory.

    Lets the SSP document the Anthropic interconnection + data flow ONLY when the
    app is actually deployed, so it never claims an interconnection that doesn't
    exist.
    """
    for c in signal.get("components", []):
        # Normalize separators: the canonical inventory names the function
        # component `aws::function::silk_reeling` (underscore), while the cloud
        # resources use `silk-reeling` (hyphen). Match either by folding both to
        # hyphens before the substring test.
        ident = f"{c.get('component_id', '')} {c.get('native_id', '')}".lower().replace("_", "-")
        if c.get("type") == "function" and "silk-reeling" in ident:
            return True
    return False


def build_system_characteristics(signal):
    # Single source of truth for categorization (assessment F-2 / Decision 1).
    # The SSP previously hardcoded "low" across every objective — a direct
    # contradiction of the Moderate baseline it is built against. Read the
    # authoritative FIPS-199 levels from data/system-profile.json so the SSP,
    # KSI signal, POA&M, VDR, and dashboard all assert the same impact level.
    _profile = json.loads((Path(__file__).resolve().parent.parent / "data" / "system-profile.json").read_text())
    _f199 = _profile["fips_199"]
    _sens = _f199["high_water_mark"]  # "moderate"
    sc = {
        "system-ids": [
            {
                "identifier-type": "https://ietf.org/rfc/rfc4122",
                "id": stable_uuid("system:samaydlette-website-prod"),
            },
            {
                "identifier-type": "samaydlette:urn",
                "id": signal.get("system_id", "urn:samaydlette:website-prod"),
            },
        ],
        "system-name": "samaydlette.com",
        "system-name-short": "samaydlette",
        "description": (
            "Static personal website served from S3 via CloudFront. Compliance "
            "automation pipeline emits a signed canonical inventory and KSI "
            "validation report on every deploy; runtime Lambda re-validates "
            "the live AWS configuration on a schedule. Sole-operator "
            "deployment; no end users, no federal customer data, no FedRAMP "
            "certification in scope."
        ),
        "security-sensitivity-level": _sens,
        "system-information": {
            "information-types": [
                {
                    "uuid": stable_uuid("info:public-website-content"),
                    "title": "Public website content",
                    "description": (
                        "Articles, books, and other public-facing content "
                        "authored by the operator. No federal customer data."
                    ),
                    "categorizations": [
                        {
                            "system": "https://doi.org/10.6028/NIST.SP.800-60v2r1",
                            "information-type-ids": ["C.2.8.12"],
                        }
                    ],
                    "confidentiality-impact": {
                        "base": f"fips-199-{_f199['confidentiality']}",
                    },
                    "integrity-impact": {
                        "base": f"fips-199-{_f199['integrity']}",
                    },
                    "availability-impact": {
                        "base": f"fips-199-{_f199['availability']}",
                    },
                }
            ]
        },
        "security-impact-level": {
            "security-objective-confidentiality": _f199["confidentiality"],
            "security-objective-integrity": _f199["integrity"],
            "security-objective-availability": _f199["availability"],
        },
        "status": {"state": "operational"},
        "authorization-boundary": {
            "description": (
                "AWS account containing one S3 bucket (origin), one CloudFront "
                "distribution (CDN), one Lambda function (runtime KSI emitter), "
                "the IAM role and policy supporting the Lambda, an EventBridge "
                "rule scheduling the Lambda, and a Route 53 hosted zone for DNS. "
                "GitHub repository and GitHub Actions runners are part of the "
                "build chain and produce signed attestations recorded in Rekor; "
                "they are inside the boundary for provenance purposes."
            )
        },
        # Base network architecture (always emitted). No public inbound compute
        # ingress exists in the base system; the only compute is the internal
        # scheduled KSI Lambda. See the Authorization Boundary Diagram (ABD)
        # back-matter resource for the rendered topology.
        "network-architecture": {
            "description": (
                "Route 53 resolves the apex and www records to a single "
                "CloudFront distribution. CloudFront terminates TLS (minimum "
                "TLS 1.2; the viewer-protocol policy fails secure by redirecting "
                "or rejecting cleartext, SC-7/SC-8) and serves the static site "
                "from the private S3 origin via origin access control. The daily "
                "KSI-validation Lambda runs internally on an EventBridge schedule "
                "with no public endpoint and writes the runtime signal to S3; it "
                "is not reachable from the internet. The base system therefore "
                "exposes no inbound public compute ingress — only the CloudFront "
                "edge fronting static content."
            ),
            "links": [
                {
                    "href": "#" + stable_uuid("resource:authorization-boundary"),
                    "rel": "diagram",
                    "text": "Authorization Boundary Diagram (network topology)",
                }
            ],
        },
    }
    # The gated Silk Reeling app, when deployed, adds an external interconnection
    # (Anthropic API) and a boundary-crossing data flow. Emitted only when the
    # app is present in the canonical inventory. See docs/poam.md POAM-020 (SA-9).
    if _silk_reeling_present(signal):
        sc["data-flow"] = {
            "description": (
                "Browser captures pose landmarks client-side and POSTs them to "
                "the Silk Reeling app Lambda over TLS (CloudFront → API Gateway "
                "HTTP API → Lambda; the app's /api/* routes are gated by a "
                "Cognito JWT authorizer at the gateway, and the app also "
                "validates the JWT in-Lambda so it stays standalone-deployable, "
                "per POAM-022). The Lambda "
                "computes movement deviations locally "
                "and sends ONLY a derived summary (per-joint angle deviations, "
                "similarity scores, hotspots, exercise identifier) to the "
                "Anthropic API over TLS for natural-language feedback. No video, "
                "no raw landmarks, and no personal data cross the boundary; pose "
                "frames are processed transiently and not persisted. The Anthropic "
                "API is an external, non-FedRAMP-authorized service (SA-9), "
                "enumerated as an interconnection component; residual risk is "
                "accepted in POAM-020."
            )
        }
        # Silk Reeling adds a public inbound path and a new outbound egress that
        # do not exist in the base system. Extend (do not replace) the base
        # network-architecture description.
        sc["network-architecture"]["description"] += (
            " When the Silk Reeling app is deployed, CloudFront adds a "
            "dedicated /silk-reeling/* cache behavior (caching disabled, "
            "forwarding the Authorization header, with a CloudFront Function "
            "that strips the path prefix) that routes to an API Gateway HTTP "
            "API. The $default route serves the SPA unauthenticated (so the "
            "login page can load); the ANY /api/{proxy+} route carries a Cognito "
            "JWT authorizer (required TOTP MFA), and the stage enforces "
            "rate-limit throttling (POAM-022/POAM-023). The HTTP API uses an "
            "AWS_PROXY integration to the Python 3.13 ZIP Lambda, which holds "
            "its Anthropic API credential in Secrets Manager encrypted with a "
            "customer-managed CMK. This introduces new public inbound compute ingress "
            "(SC-7) absent from the base system. The Lambda's only outbound "
            "internet path is an egress over TLS to the external Anthropic API "
            "for natural-language feedback; that service is non-FedRAMP-"
            "authorized and is documented as an interconnection (SA-9/CA-3), "
            "with residual risk accepted in POAM-020."
        )
    return sc


def build_system_implementation(signal):
    """Components are sourced from the canonical inventory in the KSI signal.

    Cloud resources become OSCAL `service` components. Software components
    (npm packages) and static artifacts (HTML files) are summarized as
    properties of the cloud component they ride on, rather than enumerated
    as separate OSCAL components — the SSP would otherwise be unreadable
    with 108 npm entries, and the canonical inventory at
    /.well-known/ksi-signal.json is the authoritative full enumeration.
    """
    components = []

    # The operator user, present for OSCAL completeness.
    users = [
        {
            "uuid": stable_uuid("user:operator"),
            "title": "Operator",
            "short-name": "operator",
            "description": "Sole operator and IR lead.",
            "role-ids": ["system-owner"],
            "authorized-privileges": [
                {
                    "title": "Full administrative access",
                    "functions-performed": [
                        "Deploy infrastructure",
                        "Modify content",
                        "Respond to incidents",
                    ],
                }
            ],
        }
    ]

    # Cloud components from the canonical inventory.
    for c in signal.get("components", []):
        ctype = c.get("type")
        if ctype not in {"object_store", "cdn_distribution", "function"}:
            continue
        comp_uuid = stable_uuid(f"component:{c['component_id']}")
        attrs = c.get("attributes") or {}
        props = [
            {"name": "canonical-inventory-id", "value": c["component_id"]},
            {"name": "normalized-type", "value": ctype},
        ]
        if c.get("native_id"):
            props.append({"name": "aws-arn", "value": c["native_id"]})
        for k in ("region", "id", "domain_name", "function_name", "runtime"):
            if k in attrs and attrs[k]:
                props.append({"name": k.replace("_", "-"), "value": str(attrs[k])})

        components.append({
            "uuid": comp_uuid,
            "type": "service",
            "title": _component_title(ctype),
            "description": _component_description(ctype, c),
            "props": props,
            "status": {"state": "operational"},
            "responsible-roles": [
                {
                    "role-id": "system-owner",
                    "party-uuids": [stable_uuid("party:operator")],
                }
            ],
        })

    # Summary of software components (npm packages from the Lambda runtime).
    npm_count = sum(1 for c in signal.get("components", []) if c.get("type") == "npm_package")
    if npm_count:
        components.append({
            "uuid": stable_uuid("component:lambda-software-stack"),
            "type": "software",
            "title": "Lambda runtime software stack",
            "description": (
                f"Aggregated software components ({npm_count} npm packages) "
                "running inside the runtime KSI emitter Lambda. The full "
                "PURL-identified enumeration is in the canonical inventory at "
                "/.well-known/ksi-signal.json (components[] where type == "
                "'npm_package'). Supply-chain monitoring is via Dependabot; "
                "see docs/supply-chain.md."
            ),
            "props": [
                {"name": "package-count", "value": str(npm_count)},
                {"name": "ecosystem", "value": "npm"},
                {"name": "inventory-source", "value": "/.well-known/ksi-signal.json"},
            ],
            "status": {"state": "operational"},
        })

    # Summary of static content artifacts.
    html_count = sum(1 for c in signal.get("components", []) if c.get("type") == "html_artifact")
    if html_count:
        components.append({
            "uuid": stable_uuid("component:static-content"),
            "type": "this-system",
            "title": "Static website content",
            "description": (
                f"Aggregated HTML artifacts ({html_count} files) served by "
                "CloudFront. Each file is content-addressable via SHA-256; the "
                "full enumeration is in the canonical inventory."
            ),
            "props": [
                {"name": "file-count", "value": str(html_count)},
                {"name": "inventory-source", "value": "/.well-known/ksi-signal.json"},
            ],
            "status": {"state": "operational"},
        })

    # External interconnection: Anthropic API used by the Silk Reeling app for
    # feedback. Present only when the app is deployed. Non-FedRAMP-authorized
    # external service (SA-9, POAM-020); data flow in system-characteristics.
    if _silk_reeling_present(signal):
        components.append({
            "uuid": stable_uuid("component:interconnection-anthropic-api"),
            "type": "interconnection",
            "title": "Anthropic API (LLM feedback)",
            "description": (
                "External system interconnection from the Silk Reeling app "
                "Lambda to the Anthropic API (api.anthropic.com) over TLS, used "
                "to turn derived movement-deviation summaries into natural-"
                "language feedback. Only the derived summary crosses the boundary "
                "(per-joint deviations, scores, hotspots, exercise id) — no video, "
                "raw landmarks, or personal data. NOT FedRAMP-authorized; residual "
                "risk accepted in POAM-020, with migration to Claude on AWS "
                "Bedrock as the documented remediation."
            ),
            "props": [
                {"name": "interconnection-direction", "value": "outbound"},
                {"name": "service-provider", "value": "Anthropic"},
                {"name": "remote-endpoint", "value": "https://api.anthropic.com"},
                {"name": "transport-security", "value": "TLS 1.2+"},
                {"name": "fedramp-authorized", "value": "no"},
                {"name": "data-crossing-boundary", "value": "derived deviation summary (non-PII)"},
                {"name": "related-poam", "value": "POAM-020"},
            ],
            "status": {"state": "operational"},
            "responsible-roles": [
                {
                    "role-id": "system-owner",
                    "party-uuids": [stable_uuid("party:operator")],
                }
            ],
        })

    return {
        "users": users,
        "components": components,
    }


def _component_title(ctype):
    return {
        "object_store": "S3 bucket (website origin)",
        "cdn_distribution": "CloudFront distribution",
        "function": "Lambda function (runtime KSI emitter)",
    }.get(ctype, ctype)


def _component_description(ctype, c):
    base = {
        "object_store": "Object store hosting site content. Versioning and "
                        "encryption enabled; public access fully blocked; "
                        "origin access scoped to the CloudFront distribution.",
        "cdn_distribution": "CDN serving the site to viewers. Viewer protocol "
                            "redirect-to-HTTPS; minimum TLS 1.2 (2021 cipher "
                            "suite); HSTS, CSP, frame-deny enforced via "
                            "response-headers policy.",
        "function": "Runtime KSI emitter. Reads the deploy-time signal, "
                    "queries live AWS configuration of named components, and "
                    "publishes a fresh runtime KSI signal at /.well-known/.",
    }.get(ctype, "Cloud component.")
    if c.get("native_id"):
        base += f" Native ID: {c['native_id']}."
    return base


def build_control_implementation(signal, catalog):
    """For each in-scope KSI, look up the controls it claims, and emit one
    `implemented-requirement` per unique control. Each requirement carries:

      - props.implementation-status       — implemented | partial | planned |
                                            alternative | not-applicable
      - props.control-origination         — sp-system | sp-corporate |
                                            shared | inherited |
                                            customer-configured |
                                            customer-provided | not-applicable
      - statements[].remarks              — actual implementation prose

    Status and statement come from CONTROL_OVERRIDES (per-control hand-written)
    or from FAMILY_DEFAULTS (per-family fallback) or from the resolver's last-
    resort placeholder. The placeholder marks any control that fell through
    every path so review can pick it up.

    Live-signal validations are also taken into account: if the canonical
    inventory's runtime validations include any `result: "fail"` referencing
    a KSI that contributes to a given control, the control's status is
    downgraded to `partial` regardless of the override, with a remark
    pointing at the live signal.
    """
    # Reverse-index: control_id → (set of contributing KSI ids, control title)
    controls_to_ksis = {}
    control_titles = {}
    ksi_records = {}

    for domain_key, domain in catalog.get("KSI", {}).items():
        for ind in domain.get("indicators") or []:
            ksi_id = ind.get("id")
            if not ksi_id:
                continue
            ksi_records[ksi_id] = ind
            if ksi_id not in IN_SCOPE_KSIS:
                continue
            for c in ind.get("controls") or []:
                cid = c.get("control_id")
                if not cid:
                    continue
                controls_to_ksis.setdefault(cid, set()).add(ksi_id)
                if c.get("title"):
                    control_titles.setdefault(cid, c["title"])

    # Per-KSI fail tracking from the live signal. We surface a per-control
    # remark when one of the contributing KSIs has an open failure.
    failing_ksis = _failing_ksis_from_signal(signal)
    app_auth = _app_auth_overrides(signal)

    # Emit an implemented-requirement for every control that is either:
    # (a) referenced by an in-scope KSI, (b) in the FedRAMP Rev 5 Moderate
    # baseline (so the SSP addresses the full baseline), or (c) in the
    # AWS-inherited list. The classification for each comes from
    # CONTROL_OVERRIDES → POLICY_AND_PROCEDURES_DEFAULT → FAMILY_DEFAULTS,
    # except for items that are purely INHERITED_FROM_AWS (no KSI ref, no
    # explicit override), which use a generic AWS-inheritance statement.
    all_control_ids = (
        set(controls_to_ksis.keys())
        | set(BASELINE_CONTROLS)
        | set(INHERITED_FROM_AWS.keys())
    )

    implemented_reqs = []
    status_counts = {}

    for control_id in sorted(all_control_ids):
        ksis = sorted(controls_to_ksis.get(control_id, []))
        title = control_titles.get(control_id, control_id.upper())

        # If the control is purely AWS-inherited (no KSI reference, no
        # explicit override, no family-default classification beyond what
        # the inherited path provides), emit it via the inherited path's
        # generic statement instead of running it through the resolver.
        purely_inherited = (
            control_id in INHERITED_FROM_AWS
            and control_id not in CONTROL_OVERRIDES
            and control_id not in app_auth
            and not ksis
        )

        if purely_inherited:
            inherited_title = INHERITED_FROM_AWS[control_id]
            status = "implemented"
            origination = "inherited"
            statement = (
                f"{inherited_title} ({control_id.upper()}) is inherited "
                f"from AWS under the AWS FedRAMP certification. The "
                f"system has no operator-side responsibility for this "
                f"control; AWS's published customer-responsibility "
                f"matrix carries the full implementation. This entry is "
                f"included so the SSP addresses the FedRAMP Rev 5 Moderate "
                f"baseline in full, even where the 20x KSI catalog is "
                f"silent because the control has no tenant-side surface."
            )
        else:
            status, origination, statement = resolve_control_profile(
                control_id, title, app_overrides=app_auth)

        # Live-signal-driven downgrade: if a contributing KSI is currently
        # failing, force the status to `partial` and append a remark.
        contributing_failures = [k for k in ksis if k in failing_ksis]
        live_remarks = []
        if contributing_failures:
            if status == "implemented":
                status = "partial"
            live_remarks.append(
                "Live signal currently shows failing validations from "
                f"contributing KSIs: {', '.join(contributing_failures)}. "
                "See /.well-known/ksi-signal.json (deploy-time) and "
                "/.well-known/ksi-signal-runtime.json (runtime) for the "
                "specific failures."
            )

        status_counts[status] = status_counts.get(status, 0) + 1

        props = [
            {
                "name": "implementation-status",
                "value": status,
            },
            {
                "name": "control-origination",
                "ns": "https://fedramp.gov/ns/oscal",
                "value": origination,
            },
        ]
        if live_remarks:
            props.append({
                "name": "implementation-status-remarks",
                "value": " ".join(live_remarks),
            })

        # Statement remarks: the actual prose, plus a footer naming the
        # contributing KSIs so a reader can trace back to the catalog.
        ksi_footer = (
            f"\n\nContributing KSIs (via the FedRAMP KSI catalog at "
            f"infrastructure/schemas/ksi-catalog.json): {', '.join(ksis)}. "
            f"Each KSI's live deploy-time status and the validations/components "
            f"that evidence it are published per-KSI in the signal's ksis[] "
            f"block at /.well-known/ksi-signal.json (keyed by the same KSI id)."
        )
        statement_text = statement + ksi_footer

        # Inherited controls also get an AWS FedRAMP reference link so the
        # SSP's reader can follow the inheritance chain even when the
        # control is reached via the KSI-derived path.
        links = _links_for_ksis(ksis)
        if origination == "inherited":
            props.append({
                "name": "leveraged-authorization",
                "value": "AWS FedRAMP Certification, Class C (commercial regions)",
            })
            links.append({
                "href": "https://aws.amazon.com/compliance/fedramp/",
                "rel": "reference",
                "text": "AWS FedRAMP certification",
            })

        ir = {
            "uuid": stable_uuid(f"req:{control_id}"),
            "control-id": control_id,
            "props": props,
            "statements": [
                {
                    "statement-id": f"{control_id}_smt",
                    "uuid": stable_uuid(f"stmt:{control_id}"),
                    "remarks": statement_text,
                }
            ],
            "links": links,
        }
        # FedRAMP-defined parameter values (set-parameters) for this control,
        # adopted from the vendored FedRAMP Moderate profile. Required for
        # FedRAMP compliance — the SSP documents the FedRAMP-mandated values.
        _params = FEDRAMP_PARAMS.get(control_id)
        if _params:
            ir["set-parameters"] = _params
        implemented_reqs.append(ir)

    # Print the status distribution for visibility on every run; helps spot
    # mass-classification problems early.
    summary = ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items()))
    print(f"info: control implementation-status distribution: {summary}", file=sys.stderr)
    print(
        f"info: total implemented-requirements: {len(implemented_reqs)} "
        f"(Moderate baseline: {len(BASELINE_CONTROLS)}, "
        f"KSI-only beyond baseline: {len(set(controls_to_ksis) - BASELINE_CONTROLS)})",
        file=sys.stderr,
    )

    return {
        "description": (
            "Each NIST 800-53 Rev 5 control in this section is either "
            "(a) referenced by one or more KSIs the system claims, with "
            "implementation status and origination resolved per-control via "
            "explicit overrides or family-level fall-throughs, or "
            "(b) part of the FedRAMP Rev 5 Moderate baseline that AWS carries "
            "wholly under its FedRAMP certification (PE, MP, parts of MA), "
            "and is therefore emitted here as inherited so the SSP addresses "
            "the baseline in full. Evidence references point at the live "
            "KSI signal at /.well-known/ksi-signal.json (deploy-time, signed "
            "via Sigstore), the runtime signal at "
            "/.well-known/ksi-signal-runtime.json, the AWS FedRAMP "
            "certification page, and the documentation set in docs/."
        ),
        "implemented-requirements": implemented_reqs,
    }


def _failing_ksis_from_signal(signal):
    """Return the set of KSI ids whose contributing validations include any
    `result: "fail"` in the live signal. Used to downgrade affected controls
    from `implemented` to `partial` automatically.
    """
    failing = set()
    # The KSI signal's validations carry policy.id and component_refs. Only
    # the runtime emitter currently uses a policy id like 'runtime.s3_security';
    # the deploy-time gate's validations use 'terraform.compliance' and don't
    # encode a KSI id directly. So we surface failures conservatively: any
    # validation with result=='fail' marks the catch-all bucket so SSP
    # consumers know to look at the signal.
    for v in signal.get("validations") or []:
        if v.get("result") == "fail":
            # Map runtime-policy ids to KSI ids by convention. Best-effort.
            policy_id = (v.get("policy") or {}).get("id", "")
            if policy_id == "runtime.s3_security":
                failing.update({"KSI-SVC-ACM", "KSI-SVC-SIN", "KSI-CMT-LMC"})
            elif policy_id == "runtime.cloudfront_security":
                failing.update({"KSI-SVC-VCM", "KSI-CNA-ULN"})
            elif policy_id == "terraform.compliance":
                # Deploy-time policy: granular KSI mapping not encoded.
                # Mark representative ids so the downgrade fires for affected
                # controls; we treat infrastructure findings as touching
                # config/monitoring families broadly.
                failing.update({"KSI-MLA-EVC", "KSI-SVC-ACM"})
    return failing


def _links_for_ksis(ksis):
    links = [
        {
            "href": "https://samaydlette.com/.well-known/ksi-signal.json",
            "rel": "evidence",
            "media-type": "application/json",
            "text": "Live KSI signal (deploy-time, Sigstore-signed)",
        },
        {
            "href": "https://samaydlette.com/.well-known/ksi-signal-runtime.json",
            "rel": "evidence",
            "media-type": "application/json",
            "text": "Live runtime KSI signal",
        },
        {
            "href": "https://samaydlette.com/.well-known/ksi-signal.bundle",
            "rel": "evidence",
            "media-type": "application/json",
            "text": "Sigstore signature bundle for the deploy-time signal",
        },
    ]
    seen_docs = set()
    for ksi_id in ksis:
        doc = KSI_DOC_REFS.get(ksi_id)
        if doc and doc not in seen_docs:
            seen_docs.add(doc)
            links.append({
                "href": f"https://github.com/sam-aydlette/samaydlette.com/blob/main/{doc}",
                "rel": "reference",
                "text": f"Implementation documentation ({doc})",
            })
    return links


def build_back_matter(signal):
    return {
        "resources": [
            {
                "uuid": stable_uuid("resource:ksi-signal"),
                "title": "Canonical inventory and validation signal",
                "description": (
                    "Live KSI signal informed by a canonical inventory of "
                    "this system's components. Regenerated on every deploy, "
                    "signed via Sigstore keyless. The inventory layer is "
                    "what makes this SSP's component definitions and "
                    "control evidence compose with reports from other "
                    "systems."
                ),
                "rlinks": [
                    {
                        "href": "https://samaydlette.com/.well-known/ksi-signal.json",
                        "media-type": "application/json",
                    }
                ],
            },
            {
                "uuid": stable_uuid("resource:ksi-signal-schema"),
                "title": "KSI signal JSON Schema",
                "rlinks": [
                    {
                        "href": "https://samaydlette.com/.well-known/ksi-signal.schema.json",
                        "media-type": "application/schema+json",
                    }
                ],
            },
            {
                "uuid": stable_uuid("resource:fedramp-ksi-catalog"),
                "title": "FedRAMP 20x KSI Catalog (FRMR.KSI)",
                "description": "FedRAMP-published KSI catalog with NIST 800-53 control mappings.",
                "rlinks": [
                    {
                        "href": "https://www.fedramp.gov/",
                        "media-type": "text/html",
                    }
                ],
            },
            {
                "uuid": stable_uuid("resource:repo"),
                "title": "Source repository",
                "rlinks": [
                    {
                        "href": "https://github.com/sam-aydlette/samaydlette.com",
                        "media-type": "text/html",
                    }
                ],
            },
            {
                "uuid": stable_uuid("resource:poam"),
                "title": "Plan of Action and Milestones (POA&M)",
                "description": (
                    "Tracked security weaknesses with remediation plans. The "
                    "POA&M is the single Rev 5 register; risk-accepted items "
                    "are carried with status 'Risk-accepted'. The OSCAL "
                    "machine-readable form is the authoritative copy."
                ),
                "rlinks": [
                    {"href": "https://samaydlette.com/.well-known/oscal-poam.json", "media-type": "application/oscal+json"},
                    {"href": "https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/poam.md", "media-type": "text/markdown"},
                ],
            },
            {
                "uuid": stable_uuid("resource:cmp"),
                "title": "Continuous Monitoring Plan",
                "description": "The system's continuous-monitoring strategy, mechanisms, and cadences. Satisfies NIST CA-7 and the FedRAMP 20x Collaborative Continuous Monitoring (CCM) rule.",
                "rlinks": [
                    {"href": "https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/continuous-monitoring-plan.md", "media-type": "text/markdown"},
                ],
            },
            {
                "uuid": stable_uuid("resource:pta"),
                "title": "Privacy Threshold Analysis (PTA)",
                "description": "Determination that the system processes no PII; full PIA not required at this time.",
                "rlinks": [
                    {"href": "https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/privacy-threshold-analysis.md", "media-type": "text/markdown"},
                ],
            },
            {
                "uuid": stable_uuid("resource:rob"),
                "title": "Rules of Behavior",
                "description": "Sole-operator acceptable-use commitments per NIST PL-4.",
                "rlinks": [
                    {"href": "https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/rules-of-behavior.md", "media-type": "text/markdown"},
                ],
            },
            {
                "uuid": stable_uuid("resource:incident-response"),
                "title": "Incident Response Plan",
                "rlinks": [{"href": "https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/incident-response.md", "media-type": "text/markdown"}],
            },
            {
                "uuid": stable_uuid("resource:recovery-plan"),
                "title": "Recovery / Contingency Plan",
                "rlinks": [{"href": "https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/recovery-plan.md", "media-type": "text/markdown"}],
            },
            {
                "uuid": stable_uuid("resource:supply-chain"),
                "title": "Supply Chain Risk Management Plan",
                "rlinks": [{"href": "https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/supply-chain.md", "media-type": "text/markdown"}],
            },
            {
                "uuid": stable_uuid("resource:training-log"),
                "title": "Training Log",
                "rlinks": [{"href": "https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/training-log.md", "media-type": "text/markdown"}],
            },
            {
                "uuid": stable_uuid("resource:security-review"),
                "title": "Annual Security Review",
                "rlinks": [{"href": "https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/security-review.md", "media-type": "text/markdown"}],
            },
            {
                "uuid": stable_uuid("resource:architecture-decisions"),
                "title": "Architectural and Operational Decisions",
                "description": "ADR-style records, including the SA-11.2 threat model.",
                "rlinks": [{"href": "https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/architecture-decisions.md", "media-type": "text/markdown"}],
            },
            {
                "uuid": stable_uuid("resource:authorization-boundary"),
                "title": "Authorization Boundary Diagram",
                "description": "ABD per FedRAMP guidance, with data flows, FIPS-validated cryptographic modules, and out-of-boundary items.",
                "rlinks": [{"href": "https://samaydlette.com/research/authorization-boundary.html", "media-type": "text/html"}],
            },
            *_policy_doc_resources(),
        ]
    }


def _policy_doc_resources():
    """Emit one back-matter resource per per-family policy doc plus SCG.

    Each family policy doc (docs/policies/<family>-policy.md) becomes a resource
    so the SSP's *-1 implementation-requirement can reference it via
    link rel='reference' href='#<uuid>'.
    """
    families = [
        ("ac", "Access Control"),
        ("at", "Awareness and Training"),
        ("au", "Audit and Accountability"),
        ("ca", "Assessment, Authorization, and Monitoring"),
        ("cm", "Configuration Management"),
        ("cp", "Contingency Planning"),
        ("ia", "Identification and Authentication"),
        ("ir", "Incident Response"),
        ("ma", "Maintenance"),
        ("mp", "Media Protection"),
        ("pe", "Physical and Environmental Protection"),
        ("pl", "Planning"),
        ("ps", "Personnel Security"),
        ("pt", "PII Processing and Transparency"),
        ("ra", "Risk Assessment"),
        ("sa", "System and Services Acquisition"),
        ("sc", "System and Communications Protection"),
        ("si", "System and Information Integrity"),
        ("sr", "Supply Chain Risk Management"),
    ]
    resources = []
    for code, name in families:
        resources.append({
            "uuid": stable_uuid(f"resource:policy-{code}"),
            "title": f"{name} Policy and Procedures ({code.upper()}-1)",
            "description": f"Per-family policy document satisfying {code.upper()}-1, with FedRAMP 20x rule integration where applicable.",
            "rlinks": [{
                "href": f"https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/policies/{code}-policy.md",
                "media-type": "text/markdown",
            }],
        })
    resources.append({
        "uuid": stable_uuid("resource:scg"),
        "title": "Secure Configuration Guide",
        "description": "FedRAMP 20x Secure Configuration Guide for top-level administrative accounts (AWS root, GitHub repo owner).",
        "rlinks": [{
            "href": "https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/policies/secure-configuration-guide.md",
            "media-type": "text/markdown",
        }],
    })
    return resources


# =============================================================================
# MAIN
# =============================================================================


def main():
    cwd = Path.cwd()
    signal_path = cwd / "ksi-signal.json"
    catalog_path = cwd / "schemas" / "ksi-catalog.json"
    output_path = cwd / "oscal-ssp.json"

    if not signal_path.exists():
        print(f"error: {signal_path} not found; run build-ksi-signal.py first", file=sys.stderr)
        sys.exit(1)
    if not catalog_path.exists():
        print(f"error: {catalog_path} not found", file=sys.stderr)
        sys.exit(1)

    signal = json.loads(signal_path.read_text())
    catalog = json.loads(catalog_path.read_text())

    ssp = {
        "system-security-plan": {
            "uuid": stable_uuid("ssp:samaydlette-website-prod"),
            "metadata": build_metadata(signal),
            "import-profile": {"href": FEDRAMP_PROFILE},
            "system-characteristics": build_system_characteristics(signal),
            "system-implementation": build_system_implementation(signal),
            "control-implementation": build_control_implementation(signal, catalog),
            "back-matter": build_back_matter(signal),
        }
    }

    output_path.write_text(json.dumps(ssp, indent=2) + "\n")

    n_components = len(ssp["system-security-plan"]["system-implementation"]["components"])
    n_reqs = len(ssp["system-security-plan"]["control-implementation"]["implemented-requirements"])
    print(
        f"Wrote {output_path} "
        f"({n_components} components, {n_reqs} control requirements)"
    )


if __name__ == "__main__":
    main()
