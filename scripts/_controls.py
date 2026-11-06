"""The control projection: one implemented-requirement per NIST 800-53 Rev5
control, with its implementation status, origination and statement.

This is the control hub the SDR's per-control status and the trust center's
Rev5 Moderate figures project from. It used to live inside the OSCAL SSP builder
(scripts/build-oscal-ssp.py), and consumers read it back out of the generated
oscal-ssp.json. The SSP was retired under CR26 (the SDR and CPO replace it), so
the projection now lives here and consumers compute it in memory from the same
two inputs the SSP used:

  - the canonical inventory  (infrastructure/ksi-signal.json)
  - the FedRAMP KSI catalog  (infrastructure/schemas/ksi-catalog.json)

The entries are exactly the implemented-requirements the SSP carried (same
UUIDs, props, statements, links and set-parameters), so the projection is
unchanged by the retirement; tests/test_controls.py pins that against the last
SSP the retired builder produced.

Control sources, in resolution order: the OSCAL component definition under
data/component-definitions/ (CONTROL_OVERRIDES), the app-authentication
profiles when the inventory carries an identity provider, the
policy-and-procedures default, the per-family defaults, and the AWS-inherited
list. A control that falls through every path raises: no control is published
with an invented status. A contributing KSI that the signal marks failing
downgrades the control from implemented to partial.
"""

import json
import sys
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_SIGNAL = REPO / "infrastructure" / "ksi-signal.json"
DEFAULT_CATALOG = REPO / "infrastructure" / "schemas" / "ksi-catalog.json"

SYSTEM_NAMESPACE = uuid.UUID("8be0e36b-1be1-4c8a-b76f-1b9d6e4b0a53")  # arbitrary stable namespace

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
    "KSI-MLA-RVL": "docs/architecture-decisions.md",
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
            "tracked upgrade under POAM-025 (see the register for status)."
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
            "(KSI-CNA-EIS), and the freshness of the published evidence is "
            "watched hourly by the evidence SLA watchdog, whose alarms email "
            "the operator. Authorization sub-controls in the FedRAMP sense "
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
            "are in place. Incident exercises are recorded in "
            "data/incidents.json and the recovery tabletop is held by "
            "scripts/hold-recovery-exercise.py each November with "
            "simulated responders (DEC-194, DEC-195)."
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

    # Awareness and Training — implemented; generated training, simulated trainee.
    "at-": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Training is generated and taken by machine "
            "(scripts/_training.py): the packet is built from the "
            "system's own data (decisions, incidents, rules, and a core "
            "covering privileged access, development and IR/DR; "
            "docs/training-log.md lists the areas), and a simulated "
            "trainee takes its quiz whenever it changes (DEC-194). The "
            "Security Decision Record counts the packet's currency and "
            "the trainee's completion and score trend as two automated "
            "methods for KSI-CED-RAT. External evidence (training certs, "
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
            "exercised end-to-end during initial implementation and is "
            "exercised by scripts/hold-recovery-exercise.py every month "
            "(the live site rebuilt from the deployed commit and compared, "
            "versioning and point-in-time recovery re-read) with a "
            "simulated tabletop each November. Enhancements that presume alternate "
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
            "design choices), docs/security-review.md (the generated "
            "Annual Security Review), docs/recovery-plan.md (contingency "
            "planning), docs/incident-response.md (response planning). "
            "Plans are version-controlled, machine-checked on every "
            "deploy and night (scripts/check-non-machine-vv.py) and "
            "re-checked with their sha256 in each Annual Security Review "
            "(scripts/hold-security-review.py)."
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
            "system; the investment review is the generated Annual "
            "Security Review (scripts/hold-security-review.py, "
            "docs/security-review.md). "
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
            "The Annual Security Review (scripts/hold-security-review.py, "
            "docs/security-review.md) re-checks the threat model against "
            "new component types."
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
        "and how it is verified: machine checks on every deploy and night "
        "(scripts/check-non-machine-vv.py) and the generated Annual Security "
        "Review (scripts/hold-security-review.py); updates are reviewed pull "
        "requests."
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
        f"family in scripts/_controls.py."
    )




def stable_uuid(name):
    """Generate a deterministic UUID v5 from a stable name."""
    return str(uuid.uuid5(SYSTEM_NAMESPACE, name))


def contributing_ksis(catalog):
    """({control_id: set of in-scope KSI ids that claim it}, {control_id: title})
    from the KSI catalog's controls[] arrays."""
    controls_to_ksis = {}
    control_titles = {}
    for domain in catalog.get("KSI", {}).values():
        for ind in domain.get("indicators") or []:
            ksi_id = ind.get("id")
            if not ksi_id or ksi_id not in IN_SCOPE_KSIS:
                continue
            for c in ind.get("controls") or []:
                cid = c.get("control_id")
                if not cid:
                    continue
                controls_to_ksis.setdefault(cid, set()).add(ksi_id)
                if c.get("title"):
                    control_titles.setdefault(cid, c["title"])
    return controls_to_ksis, control_titles


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
    controls_to_ksis, control_titles = contributing_ksis(catalog)

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
    """Return the set of KSI ids the signal itself marks as failing. Used to
    downgrade affected controls from `implemented` to `partial` automatically.

    The signal's ksis[] block is the authoritative per-KSI verdict (status
    plus evidence.failed_validation_ids), so consume that attribution rather
    than re-deriving it here from validations[] with a coarse policy-id map —
    the map both missed KSIs the signal marks failing and dragged in KSIs the
    signal marks passing.
    """
    ksi_records = signal.get("ksis") or []
    if ksi_records:
        return {
            k["id"]
            for k in ksi_records
            if k.get("status") == "fail"
            or (k.get("evidence") or {}).get("failed_validation_ids")
        }
    # Legacy fallback for signals predating the ksis[] block: coarse
    # policy-id convention mapping over raw validations.
    failing = set()
    for v in signal.get("validations") or []:
        if v.get("result") == "fail":
            policy_id = (v.get("policy") or {}).get("id", "")
            if policy_id == "runtime.s3_security":
                failing.update({"KSI-SVC-ACM", "KSI-SVC-SIN", "KSI-CMT-LMC"})
            elif policy_id == "runtime.cloudfront_security":
                failing.update({"KSI-SVC-VCM", "KSI-CNA-ULN"})
            elif policy_id == "terraform.compliance":
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


def project(signal, catalog):
    """The implemented-requirements for this inventory and catalog."""
    return build_control_implementation(signal, catalog)["implemented-requirements"]


def load(signal_path=None, catalog_path=None):
    """Read the inventory and catalog and project them. A missing input stops
    the caller: a framework figure computed from no controls would read as a
    real figure."""
    sp = Path(signal_path) if signal_path else DEFAULT_SIGNAL
    cp = Path(catalog_path) if catalog_path else DEFAULT_CATALOG
    for p, what in ((sp, "canonical inventory"), (cp, "KSI catalog")):
        if not p.is_file():
            raise SystemExit(f"::error::control projection: {what} {p} not found (fail-closed)")
    return project(json.loads(sp.read_text()), json.loads(cp.read_text()))


def prop(ir, name):
    for p in ir.get("props", []) or []:
        if p.get("name") == name:
            return p.get("value")
    return None


def status_map(irs):
    """{control-id: (implementation-status, control-origination)}."""
    return {ir["control-id"]: (prop(ir, "implementation-status"), prop(ir, "control-origination")) for ir in irs}
