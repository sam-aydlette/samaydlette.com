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

# FedRAMP-published Rev 5 Moderate baseline profile (canonical reference).
FEDRAMP_PROFILE = (
    "https://github.com/GSA/fedramp-automation/releases/latest/download/"
    "FedRAMP_rev5_MODERATE-baseline_profile.json"
)

# In-scope KSIs for this system after the current gap-closure round.
# This list is the SSP's authoritative scope statement: it is the set of KSIs
# this system claims, and therefore (by transitivity through the KSI catalog's
# controls[] arrays) the set of NIST 800-53 controls in this SSP.
#
# AFR-* are excluded because they are FedRAMP-authorization-process-only.
# IAM-01, IAM-02, IAM-06, IAM-07 are excluded because the system has no end users.
# PIY-08 is excluded because the system has no executive structure separate from
# the operator.
# SVC-10 is excluded because the system has no federal customer data.
IN_SCOPE_KSIS = {
    # Cybersecurity Education
    "KSI-CED-01", "KSI-CED-02", "KSI-CED-03", "KSI-CED-04",
    # Configuration Management
    "KSI-CMT-01", "KSI-CMT-02", "KSI-CMT-03", "KSI-CMT-04",
    # Cloud Native Architecture
    "KSI-CNA-01", "KSI-CNA-02", "KSI-CNA-03", "KSI-CNA-04",
    "KSI-CNA-05", "KSI-CNA-06", "KSI-CNA-07", "KSI-CNA-08",
    # Identity & Access Management (only the non-end-user-facing ones)
    "KSI-IAM-03", "KSI-IAM-04", "KSI-IAM-05",
    # Incident Response
    "KSI-INR-01", "KSI-INR-02", "KSI-INR-03",
    # Monitoring, Logging, and Auditing
    "KSI-MLA-01", "KSI-MLA-02", "KSI-MLA-05", "KSI-MLA-07", "KSI-MLA-08",
    # Policy and Inventory
    "KSI-PIY-01", "KSI-PIY-03", "KSI-PIY-04", "KSI-PIY-06",
    # Recovery Planning
    "KSI-RPL-01", "KSI-RPL-02", "KSI-RPL-03", "KSI-RPL-04",
    # Secure Service
    "KSI-SVC-01", "KSI-SVC-02", "KSI-SVC-04", "KSI-SVC-05",
    "KSI-SVC-06", "KSI-SVC-08", "KSI-SVC-09",
    # Third-Party Risk
    "KSI-TPR-03", "KSI-TPR-04",
}

# Maps each in-scope KSI to the documentation file that records its
# implementation. Used to populate `link` references in the SSP statements.
KSI_DOC_REFS = {
    "KSI-CED-01": "docs/training-log.md",
    "KSI-CED-02": "docs/training-log.md",
    "KSI-CED-03": "docs/training-log.md",
    "KSI-CED-04": "docs/training-log.md",
    "KSI-CMT-01": "README.md",
    "KSI-CMT-02": "README.md",
    "KSI-CMT-03": "README.md",
    "KSI-CMT-04": "docs/architecture-decisions.md",
    "KSI-CNA-01": "docs/architecture-decisions.md",
    "KSI-CNA-02": "docs/architecture-decisions.md",
    "KSI-CNA-03": "docs/architecture-decisions.md",
    "KSI-CNA-04": "README.md",
    "KSI-CNA-05": "docs/architecture-decisions.md",
    "KSI-CNA-06": "docs/architecture-decisions.md",
    "KSI-CNA-07": "README.md",
    "KSI-CNA-08": "docs/ksi-signal.md",
    "KSI-IAM-03": "docs/architecture-decisions.md",
    "KSI-IAM-04": "docs/architecture-decisions.md",
    "KSI-IAM-05": "infrastructure/main.tf",
    "KSI-INR-01": "docs/incident-response.md",
    "KSI-INR-02": "docs/incident-response.md",
    "KSI-INR-03": "docs/incident-response.md",
    "KSI-MLA-01": "docs/architecture-decisions.md",
    "KSI-MLA-02": "docs/architecture-decisions.md",
    "KSI-MLA-05": "infrastructure/policies.rego",
    "KSI-MLA-07": "docs/ksi-signal.md",
    "KSI-MLA-08": "docs/architecture-decisions.md",
    "KSI-PIY-01": "docs/ksi-signal.md",
    "KSI-PIY-03": "website/.well-known/security.txt",
    "KSI-PIY-04": "docs/architecture-decisions.md",
    "KSI-PIY-06": "docs/security-review.md",
    "KSI-RPL-01": "docs/recovery-plan.md",
    "KSI-RPL-02": "docs/recovery-plan.md",
    "KSI-RPL-03": "docs/recovery-plan.md",
    "KSI-RPL-04": "docs/recovery-plan.md",
    "KSI-SVC-01": "docs/architecture-decisions.md",
    "KSI-SVC-02": "infrastructure/main.tf",
    "KSI-SVC-04": "infrastructure/main.tf",
    "KSI-SVC-05": "docs/ksi-signal.md",
    "KSI-SVC-06": "docs/architecture-decisions.md",
    "KSI-SVC-08": "docs/architecture-decisions.md",
    "KSI-SVC-09": "docs/architecture-decisions.md",
    "KSI-TPR-03": "docs/supply-chain.md",
    "KSI-TPR-04": "docs/supply-chain.md",
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

CONTROL_OVERRIDES = {
    # ---- Configuration management (operator-implemented) ----
    "cm-2": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "The configuration baseline is the Terraform configuration in "
            "`infrastructure/`, version-controlled in git. Every deployed "
            "configuration corresponds to a specific commit on `main`, "
            "recorded in `provenance.source.commit` of the canonical "
            "inventory at /.well-known/ksi-signal.json. Drift from the "
            "baseline is detected daily by the runtime KSI emitter "
            "(`infrastructure/lambda/index.js`), which queries the live AWS "
            "configuration of every named cloud component and publishes a "
            "fresh signal at /.well-known/ksi-signal-runtime.json."
        ),
    },
    "cm-3": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "All changes reach production through pull requests to `main`, "
            "which trigger the CI workflow defined in "
            "`.github/workflows/deploy-with-opa.yml`. Out-of-band changes "
            "are detected by drift between the deploy-time and runtime KSI "
            "signals. Changes are recorded in the git log (immutable, "
            "GitHub-side) and in the canonical inventory's provenance "
            "block."
        ),
    },
    "cm-3.2": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Automated testing of changes is performed by the OPA gate in "
            "`scripts/terraform-plan.sh`, which evaluates "
            "`infrastructure/policies.rego` against the Terraform plan and "
            "every HTML artifact before merge. Test results are recorded "
            "in `validations.json` and embedded in the KSI signal."
        ),
    },
    "cm-4": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Security impact analysis is performed by three CI gates on "
            "every pull request: OPA over the Terraform plan and content; "
            "Checkov and tfsec over the Terraform configuration. Results "
            "are surfaced in the GitHub Security tab. Changes producing "
            "any HIGH-severity finding cannot merge without explicit "
            "override."
        ),
    },
    "cm-5": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Access restrictions for change are enforced by GitHub branch "
            "protection on `main` (operator-configured) and by AWS IAM on "
            "the deployer credentials (shared with AWS). The deployer "
            "credentials live only in GitHub Actions encrypted secrets; "
            "see POAM-001 in docs/poam.md for the planned migration to "
            "OIDC role assumption."
        ),
    },
    "cm-6": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Configuration settings are codified in Terraform "
            "(`infrastructure/main.tf`, `variables.tf`). The OPA policy "
            "file (`infrastructure/policies.rego`) enforces the "
            "configuration baselines: S3 encryption + versioning + public-"
            "access block; CloudFront viewer-protocol redirect-to-HTTPS "
            "and minimum TLS 1.2 (2021 cipher suite). The runtime emitter "
            "validates the live configuration against the same baselines."
        ),
    },
    "cm-7": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Least functionality: the system runs only the components "
            "required for serving static content and emitting compliance "
            "signals. The Lambda IAM role is scoped to the minimum AWS "
            "actions needed (read-only access to bucket configuration and "
            "the deploy-time signal; PutObject scoped to a single S3 key; "
            "read-only CloudFront access scoped to the one distribution). "
            "No general-purpose compute, no VPC, no NAT gateway, no shell "
            "access to anything."
        ),
    },
    "cm-8": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "The system component inventory is the canonical inventory at "
            "/.well-known/ksi-signal.json (`components[]` field). It "
            "enumerates every cloud resource (S3 bucket, CloudFront "
            "distribution, Lambda function — by ARN), every npm package "
            "in the Lambda runtime (by Package URL), and every static "
            "HTML artifact (by SHA-256). The inventory is regenerated on "
            "every deploy and signed via Sigstore keyless. See "
            "docs/ksi-signal.md for the full schema."
        ),
    },

    # ---- Access control (mostly N/A end-users; some shared) ----
    "ac-2": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Account management is in place for the only accounts the "
            "system has: non-user accounts. The Lambda IAM role and the "
            "deployer credentials are version-controlled in "
            "`infrastructure/main.tf`. Account lifecycle (create, modify, "
            "delete) occurs only through pull-request gitops; the git log "
            "is the audit trail. End-user account management features "
            "(MFA, password complexity, account inactivity) are not "
            "applicable; the system has no human end users. AC-2 "
            "enhancements covering user-facing capabilities are tracked "
            "as separate implemented-requirement entries with "
            "implementation-status: not-applicable."
        ),
    },
    "ac-3": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Access enforcement is provided by AWS IAM (inherited "
            "implementation). The system contributes the policy itself, "
            "scoped to least privilege in `infrastructure/main.tf` "
            "(`aws_iam_role_policy.lambda_opa`). The bucket policy "
            "restricts S3 read access to the CloudFront service principal "
            "with a `SourceArn` condition; no other principal can read "
            "the bucket directly."
        ),
    },
    "ac-4": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Information flow enforcement: the system has exactly two "
            "logical paths. (1) viewer → CloudFront → S3, read-only, "
            "viewer-protocol redirect-to-HTTPS, TLS 1.2+. (2) Lambda → "
            "AWS API, scoped via IAM. There is no internal east-west "
            "traffic, no VPC, and no other ingress or egress paths."
        ),
    },
    "ac-6": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Least privilege is the explicit design principle for the "
            "Lambda IAM role: read-only on three S3 configuration APIs, "
            "read-only on one specific CloudFront distribution, write on "
            "exactly one S3 key (`.well-known/ksi-signal-runtime.json`). "
            "The role has no human-assumable trust policy. CloudFront "
            "permissions are scoped to the distribution ARN, not `*`."
        ),
    },
    "ac-17": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Remote access is not applicable to this system. There is no "
            "compute resource accepting remote-administration sessions: "
            "no SSH, no RDP, no bastion, no VPN, no remote-access "
            "gateway. The only `compute_instance`-shaped components in "
            "the canonical inventory are the Lambda function (which "
            "accepts no inbound network connections) and the S3 + "
            "CloudFront services (which are managed services with no "
            "operator-side remote access)."
        ),
    },

    # ---- Audit and accountability (CloudTrail + CloudWatch) ----
    "au-2": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Event logging is provided by CloudTrail (account-wide, "
            "captures all AWS API calls including the deployer's), "
            "Lambda execution logs (CloudWatch Logs), and GitHub Actions "
            "workflow run history (immutable, GitHub-side). The system "
            "configures Lambda logging via the runtime's standard "
            "integration. CloudFront access logging is consciously "
            "excluded for cost; see README 'Conscious Trade-offs'."
        ),
    },
    "au-3": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Audit record content includes: timestamp, event type, "
            "actor identity (IAM principal), source IP, resource "
            "affected, action attempted, outcome. CloudTrail records all "
            "of these by default. Lambda logs add execution context "
            "(request ID, function version, stream). The KSI signal "
            "adds: signal_id, emitted_at, provenance (commit SHA, "
            "workflow run ID), and per-validation policy/result/component "
            "references."
        ),
    },
    "au-12": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Audit record generation is automatic (CloudTrail by default; "
            "Lambda runtime logging by default). The KSI signal's "
            "validation records are also auto-generated by the OPA gate "
            "and the runtime emitter; both produce structured records "
            "with a stable schema."
        ),
    },

    # ---- Identification and authentication ----
    "ia-2": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "User identification and authentication is not applicable: "
            "the system has no human end users. Identification of "
            "non-user accounts (services, the Lambda role, the deployer) "
            "is covered under IA-3 below."
        ),
    },
    "ia-3": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Device/service identification is via AWS IAM principals "
            "(the Lambda role is identified by ARN; the deployer is "
            "identified by IAM user ARN; cosign signing is identified by "
            "GitHub OIDC subject). Verification is provided by AWS STS "
            "and GitHub's OIDC provider respectively (inherited)."
        ),
    },

    # ---- Incident response ----
    "ir-4": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Incident handling is documented in docs/incident-response.md. "
            "The runbook covers detection sources, triage steps, "
            "containment patterns by incident class, recovery "
            "procedures, and an after-action-report template. The IR "
            "lead is the sole operator. The procedures are in place and "
            "the response capability exists; tabletops are scheduled "
            "annually per docs/security-review.md. No incidents have "
            "occurred to date that exercised the runbook end-to-end."
        ),
    },
    "ir-6": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Incident reporting external interface is the security.txt "
            "mailbox per RFC 9116 at /.well-known/security.txt. It "
            "names the contact, the canonical URL, the policy URL "
            "(docs/incident-response.md), and the expiration. There is "
            "no FedRAMP-process reporting (FSI/ICP) because no "
            "FedRAMP authorization is in scope."
        ),
    },
    "ir-8": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "The incident response plan is documented in "
            "docs/incident-response.md. Reviews are scheduled annually "
            "as part of the security review. KSI-INR-02 (pattern review) "
            "is satisfied by the same cadence; the current "
            "incident count is zero, so the pattern set is empty."
        ),
    },

    # ---- Risk assessment ----
    "ra-5": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Vulnerability scanning is automated via three tools: "
            "Dependabot (GitHub Advisory Database, scoped to npm + "
            "GitHub Actions + Terraform per .github/dependabot.yml); "
            "Checkov (Terraform IaC scanning in the security-scan CI "
            "job); tfsec (Terraform-specific static analysis in the "
            "same job). Results are surfaced in the GitHub Security "
            "tab. The PURL-based canonical inventory enables external "
            "vulnerability correlation without depending on GitHub's "
            "tooling."
        ),
    },

    # ---- System and communications protection ----
    "sc-7": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Boundary protection: the only ingress to the system is "
            "CloudFront, which fronts an S3 bucket with public access "
            "fully blocked. AWS Shield Standard is included by default; "
            "AWS WAF is consciously excluded on cost grounds (~$120/yr "
            "vs. zero attack surface for static content). The Lambda "
            "has no internet egress and no NAT gateway."
        ),
    },
    "sc-8": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Transmission confidentiality: viewer ↔ CloudFront uses TLS "
            "1.2 minimum (2021 cipher suite enforced in the CloudFront "
            "viewer-certificate config). CloudFront ↔ S3 and Lambda ↔ "
            "AWS APIs are TLS-encrypted within AWS's network. The CSP "
            "in the response-headers policy includes HSTS with "
            "`preload` and `includeSubdomains` for one year."
        ),
    },
    "sc-13": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Cryptographic protection: AES-256 for S3 server-side "
            "encryption (configured in `aws_s3_bucket_server_side_"
            "encryption_configuration.website`); TLS 1.2+ for transport "
            "(configured in CloudFront viewer-certificate); SHA-256 for "
            "content addressing in the canonical inventory; ECDSA P-256 "
            "for Sigstore signing of the KSI signal (Fulcio-issued "
            "certificate, ephemeral key)."
        ),
    },

    # ---- System and information integrity ----
    "si-2": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Flaw remediation: Dependabot opens version-update PRs "
            "weekly for npm dependencies and GitHub Actions, monthly "
            "for Terraform providers. Vulnerability alerts are emailed "
            "and surfaced in GitHub Security. The OPA gate runs on "
            "every PR, ensuring that no remediation merge introduces a "
            "configuration regression."
        ),
    },
    "si-3": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Malicious code protection: the system has no executable "
            "upload paths. The S3 bucket holds static content authored "
            "by the operator and delivered via CloudFront; the Lambda "
            "runs only operator-authored JavaScript and AWS-provided "
            "SDK code (verified via Sigstore signature on the deploy-"
            "time signal). There is no surface for end-user uploads, "
            "macros, or executable email attachments."
        ),
    },
    "si-4": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "System monitoring is performed by the runtime KSI emitter "
            "(`infrastructure/lambda/index.js`). It queries the live "
            "AWS configuration of every cloud component named in the "
            "deploy-time signal and publishes a runtime signal at "
            "/.well-known/ksi-signal-runtime.json with current pass/"
            "fail validations. Drift between the deploy-time and "
            "runtime signals is the primary tamper signal the system "
            "produces and is detectable from outside the boundary."
        ),
    },
    "si-7": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Software, firmware, and information integrity: the deploy-"
            "time KSI signal is signed via Sigstore keyless with the "
            "GitHub Actions OIDC identity. The signing certificate is "
            "issued by Fulcio; the signature is recorded in the public "
            "Rekor transparency log; the bundle is published at "
            "/.well-known/ksi-signal.bundle. Any consumer can verify "
            "the integrity of the canonical inventory and its embedded "
            "validations using `cosign verify-blob`."
        ),
    },

    # ---- Supply chain risk management ----
    "sr-3": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Supply chain controls: dependencies are pinned (npm via "
            "package-lock.json with integrity hashes; GitHub Actions "
            "via SHA pins; Terraform providers via version constraints; "
            "OPA binary via SHA-256 verification). Risk monitoring is "
            "automated via Dependabot. The PURL-based canonical "
            "inventory enables external SCRM tooling. See "
            "docs/supply-chain.md."
        ),
    },
    "sr-11": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Component authenticity: every npm package's lockfile "
            "integrity hash is preserved in the canonical inventory; "
            "GitHub Actions are SHA-pinned (pinned to commit, not tag); "
            "the OPA binary is verified via published SHA-256 checksum "
            "in the workflow before installation."
        ),
    },

    # ---- Controls that look like operator-side responsibilities via the
    # KSIs that reference them, but whose actual NIST implementation is
    # wholly AWS-inherited. The operator's contribution (having a recovery
    # plan that takes advantage of these capabilities) is covered by the
    # adjacent overrides like RPL/CP family defaults.

    "cp-6": {
        "status": "implemented",
        "origination": "inherited",
        "statement": (
            "S3 storage is multi-AZ durable by default; AWS provides the "
            "alternate storage site infrastructure under its FedRAMP "
            "authorization. The operator selects S3 as the origin and "
            "enables versioning (covered under CM-2/CM-6); the alternate-"
            "site capability itself is inherited."
        ),
    },
    "cp-7": {
        "status": "implemented",
        "origination": "inherited",
        "statement": (
            "CloudFront's global edge network provides alternate "
            "processing across hundreds of points of presence; AWS "
            "operates and maintains the edge infrastructure under its "
            "FedRAMP authorization. The operator selects CloudFront as "
            "the CDN; the alternate-processing capability is inherited."
        ),
    },
    "cp-8": {
        "status": "implemented",
        "origination": "inherited",
        "statement": (
            "Telecommunications services (network connectivity, BGP "
            "routing, DDoS-mitigation backbone) are wholly AWS's "
            "responsibility under its FedRAMP authorization. The "
            "operator does not configure or maintain any "
            "telecommunications infrastructure."
        ),
    },
    "sa-22": {
        "status": "implemented",
        "origination": "inherited",
        "statement": (
            "Unsupported system components are managed via AWS's "
            "service-deprecation lifecycle, which operates under its "
            "FedRAMP authorization. The operator's stack uses only "
            "currently-supported AWS services (S3, CloudFront, Lambda, "
            "Route 53, ACM, EventBridge, CloudWatch, IAM); AWS publishes "
            "deprecation timelines on its service-end-of-life calendar."
        ),
    },
    "sc-20": {
        "status": "implemented",
        "origination": "inherited",
        "statement": (
            "Authoritative DNS resolution is provided by Amazon Route 53. "
            "DNSSEC, response signing, and the authoritative resolver "
            "infrastructure are managed by AWS under its FedRAMP "
            "authorization. The operator configures the hosted-zone "
            "records via Terraform (covered under CM-2); the resolution "
            "service itself is inherited."
        ),
    },
    "sc-21": {
        "status": "implemented",
        "origination": "inherited",
        "statement": (
            "Recursive and caching DNS resolution is performed by client-"
            "side resolvers and intermediate AWS infrastructure when "
            "AWS-internal services resolve names; both are managed under "
            "AWS's FedRAMP authorization. The operator runs no resolver."
        ),
    },
    "sc-22": {
        "status": "implemented",
        "origination": "inherited",
        "statement": (
            "Route 53's resolution architecture, including provisioning, "
            "redundancy, and global anycast, is wholly AWS's "
            "responsibility under its FedRAMP authorization. The operator "
            "does not manage resolver topology or provisioning."
        ),
    },

    # ---- Baseline controls whose family defaults need a specific classification

    "ac-22": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "All website content is intentionally public. The operator "
            "(sole author) reviews each piece of content before it merges "
            "to `main`; the gitops gate ensures no content reaches "
            "production without that review. Content is monitored "
            "informally for unauthorized modification via drift detection "
            "(the runtime KSI emitter compares deployed HTML hashes "
            "against the deploy-time signal)."
        ),
    },
    "au-8": {
        "status": "implemented",
        "origination": "inherited",
        "statement": (
            "Time stamps in audit records use AWS-managed NTP-synchronized "
            "clocks. CloudTrail and CloudWatch Logs both timestamp records "
            "automatically; the underlying time service is part of AWS's "
            "infrastructure under its FedRAMP authorization. The operator "
            "does not run any time servers."
        ),
    },
    "pl-4": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Rules of behavior collapse into self-attestation by the sole "
            "operator. The repository's CONTRIBUTING-style conventions "
            "(no commits to main without PR; no secrets in code; no "
            "hand-edits in production) function as the rules; they are "
            "enforced by GitHub branch protection and the OPA gate, not "
            "by signed acknowledgments."
        ),
    },
    "pl-4.1": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Social media and external-site usage restrictions for the "
            "sole operator: the operator does not post system credentials, "
            "AWS account IDs, or production URLs on any external platform "
            "in a way that would compromise the system's posture. This is "
            "self-attested; the system has no organizational social media "
            "footprint to govern."
        ),
    },
    "sa-4.10": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Use of approved PIV products is not applicable. The system "
            "has no human end users; PIV credentials are not in scope for "
            "any authentication flow on this site."
        ),
    },
    "sc-15": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Collaborative computing devices and applications are not "
            "applicable. The system runs no collaborative computing "
            "platforms (no video conferencing, no shared whiteboards, no "
            "co-authoring tools) and exposes no such capabilities to any "
            "user."
        ),
    },
    "sc-28": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Information at rest is protected by S3 server-side "
            "encryption (AES-256 by default, configured in "
            "`infrastructure/main.tf`'s "
            "`aws_s3_bucket_server_side_encryption_configuration`). The "
            "encryption keys and key-management infrastructure are "
            "AWS-managed (inherited); the configuration choice and "
            "enforcement via OPA are the operator's contribution."
        ),
    },
    "sc-28.1": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Cryptographic protection for information at rest is provided "
            "by AES-256 server-side encryption on S3. AWS provides the "
            "cryptographic implementation under its FedRAMP authorization; "
            "the operator enables it via Terraform and verifies it via "
            "OPA at deploy time and the runtime KSI emitter at runtime."
        ),
    },
    "ca-5": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Plan of Action and Milestones is documented in "
            "`docs/poam.md`. Two open POA&M items are tracked: POAM-001 "
            "(migrate the deployer from long-lived AWS access keys to "
            "GitHub OIDC role assumption) and POAM-002 (sign the runtime "
            "KSI signal cryptographically). Each carries a target close "
            "date, severity, compensating controls, and remediation plan."
        ),
    },
    "cm-11": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "User-installed software is not applicable. The system has "
            "no human end users with the ability to install software. "
            "The Lambda runtime's software is fully controlled by the "
            "deploy pipeline (npm package-lock + Sigstore-signed "
            "provenance); no other compute accepts user-installed "
            "software."
        ),
    },
    "cm-10": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Software usage restrictions are enforced through the npm "
            "lockfile (each dependency is pinned to a specific version "
            "with an integrity hash) and the canonical inventory (which "
            "publishes the full software inventory for any consumer to "
            "verify). License compliance is reviewed during dependency "
            "additions; the operator avoids GPL and copyleft-restricted "
            "components for compatibility."
        ),
    },
    "ir-2": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Incident response training collapses into self-attestation "
            "by the sole operator (who is also the IR lead). Coverage is "
            "documented in `docs/training-log.md` (KSI-CED-04 section). "
            "The runbook in `docs/incident-response.md` serves as the "
            "training material; reviews are annual."
        ),
    },
    "sr-2": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "The supply-chain risk management plan is documented in "
            "`docs/supply-chain.md`. It describes in-scope third-party "
            "components (npm, GitHub Actions, Terraform providers, OPA, "
            "cosign), the risk-identification approach (PURL-based "
            "inventory in the canonical KSI signal), the monitoring "
            "approach (Dependabot + Checkov + tfsec), and the inheritance "
            "from AWS for AWS-side supply chain."
        ),
    },
    "sr-2.1": {
        "status": "not-applicable",
        "origination": "sp-corporate",
        "statement": (
            "Establishment of a dedicated SCRM team is not applicable for "
            "a sole-operator system. The supply-chain risk management "
            "function is the operator's responsibility, addressed via the "
            "documented practices in `docs/supply-chain.md`. There is no "
            "team to establish."
        ),
    },

    # ===== Moderate-baseline-only overrides =====

    # Authorization-process controls. CA-2 / CA-2.1 / CA-2.3 / CA-6 / CA-7.1 /
    # CA-8 / CA-8.1 / CA-8.2 all presume a formal assessor engagement and an
    # agency authorization decision. Neither is in scope for this PoC, so
    # they are marked not-applicable with the same rationale used for the
    # AFR KSIs.
    "ca-2": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Formal control assessment by an external assessor is not in "
            "scope. No agency authorization is being pursued. The system's "
            "self-assessment runs continuously via the OPA gate at deploy "
            "time and the runtime KSI emitter; results are published in "
            "the live KSI signal at /.well-known/ksi-signal.json."
        ),
    },
    "ca-2.1": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Independent assessors are not engaged for this PoC. No agency "
            "authorization is in scope; the assessment-evidence chain is "
            "the publicly verifiable Sigstore-signed KSI signal, which any "
            "independent reader can verify directly."
        ),
    },
    "ca-2.3": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Results from external organizations are leveraged: the system "
            "inherits AWS's FedRAMP authorization for the underlying "
            "infrastructure (S3, CloudFront, Lambda, Route 53, ACM). AWS "
            "is the external organization whose results are leveraged."
        ),
    },
    "ca-6": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Authorization in the FedRAMP / agency-ATO sense is not in "
            "scope. The system has no Authorizing Official, no FedRAMP "
            "package, and no agency relying on its authorization. The "
            "self-attested operating posture is documented in the SSP, "
            "the live KSI signal, and the docs/ tree."
        ),
    },
    "ca-7.1": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Independent continuous-monitoring assessment is not in scope. "
            "Continuous monitoring itself is performed by the runtime KSI "
            "emitter; the verification chain is public Sigstore signing, "
            "which is independently auditable by any reader without a "
            "designated independent assessor."
        ),
    },
    "ca-8": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Formal penetration testing is not in scope for this PoC. The "
            "system's threat surface is small (static personal site, no "
            "user input, no compute beyond a daily Lambda) and an "
            "independent pen-test engagement is not commissioned. If the "
            "system were ever scoped for FedRAMP authorization, this "
            "would become a real planned item."
        ),
    },
    "ca-8.1": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Independent penetration-testing agent is not engaged. No "
            "formal pen-test contract is in scope; the operator is not "
            "shelling out for an external assessor to prove the point of "
            "this PoC. Equivalent rationale applies as for CA-2.1 / CA-8."
        ),
    },
    "ca-8.2": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Red team exercises are not in scope. Adversary-simulation "
            "engagements presume a formal assessor relationship and a "
            "blast radius that warrants the cost. Neither is in scope for "
            "a static personal site PoC. Token spillage scenarios are "
            "addressed in docs/incident-response.md (Information Spillage "
            "Response) for IR-9."
        ),
    },

    # ===== AC family Moderate-only overrides =====

    "ac-2.7": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Privileged user accounts: the only privileged account in the "
            "system is the AWS Lambda execution role. Its scope is "
            "narrowly defined in `infrastructure/main.tf` "
            "(`aws_iam_role_policy.lambda_opa`): read-only on the bucket's "
            "configuration APIs, write-only on a single S3 key, read-only "
            "on one CloudFront distribution. The role has no human-"
            "assumable trust policy and no console access."
        ),
    },
    "ac-2.9": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Restrictions on shared and group accounts are not applicable: "
            "the system has no shared or group accounts. The only non-user "
            "account is the Lambda role (a service principal); the only "
            "human account is the operator's AWS account."
        ),
    },
    "ac-2.12": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Account monitoring for atypical usage is not applicable: the "
            "system has no human end-user accounts whose usage patterns "
            "could be profiled."
        ),
    },
    "ac-2.13": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Disabling accounts for high-risk individuals is not "
            "applicable: the system has no human end-user accounts."
        ),
    },
    "ac-4.21": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Physical or logical separation of information flows is not "
            "applicable: the system has a single information flow (public "
            "site content), which is by design fully public. There is no "
            "second information class that requires separation."
        ),
    },
    "ac-11": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Device lock is not applicable: the system has no operator-"
            "managed devices in scope. The operator's personal laptop is "
            "outside the system boundary."
        ),
    },
    "ac-11.1": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Pattern-hiding displays are not applicable: see AC-11."
        ),
    },
    "ac-17.4": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Privileged remote-access commands are not applicable: there "
            "is no remote-access surface in the system. See AC-17."
        ),
    },
    "ac-19.5": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Mobile device encryption is not applicable: the system "
            "manages no mobile devices."
        ),
    },
    "ac-20.2": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Portable storage device restrictions are not applicable: the "
            "system uses no portable storage. All storage is in S3."
        ),
    },
    "ac-21": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Information sharing controls are not applicable: the system "
            "shares no information with external partners. The site's "
            "content is by design fully public; there are no controlled-"
            "information exchanges."
        ),
    },

    # ===== CM family Moderate-only overrides =====

    "cm-5.1": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Automated access enforcement and audit records for change "
            "access: GitHub branch protection on `main` automates the "
            "access-enforcement decision (no merge without a passing CI "
            "run); the GitHub Actions workflow run history records every "
            "change with attribution. AWS IAM enforces deployer-side "
            "access; CloudTrail records every API call."
        ),
    },
    "cm-5.5": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Privilege limitation for production: the deployer credentials "
            "are the only IAM principal with write access to production "
            "resources. They are scoped to the actions needed by the "
            "Terraform-managed resources and live only as GitHub Actions "
            "encrypted secrets. The Lambda execution role has read-only "
            "access to configuration APIs and write access to one S3 key."
        ),
    },
    "cm-6.1": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Automated management, application, and verification of "
            "configuration settings: Terraform manages all configuration; "
            "OPA verifies the configuration against `policies.rego` at "
            "deploy time; the runtime KSI emitter re-verifies the live "
            "configuration daily. All three steps are automated."
        ),
    },

    # ===== IA family Moderate-only overrides =====

    "ia-2.5": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Individual authentication with group authentication is not "
            "applicable: no group accounts exist. See AC-2.9."
        ),
    },
    "ia-2.6": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Access from a separate device for authentication is not "
            "applicable: the system has no human end-user authentication. "
            "See IA-2."
        ),
    },
    "ia-5.7": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "No embedded unencrypted static authenticators: the system "
            "embeds no static authenticators. The Sigstore keyless signing "
            "chain produces ephemeral certificates per workflow run; "
            "deployer credentials live only in GitHub Actions encrypted "
            "secrets, never in source. There is no static authenticator "
            "to embed."
        ),
    },
    "ia-12": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Identity proofing is not applicable: the system has no human "
            "end users to proof. The operator's identity is established "
            "via GitHub and AWS account ownership, neither of which is "
            "in scope for IA-12 in this system's boundary."
        ),
    },
    "ia-12.2": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": "See IA-12. No end users, no identity evidence to collect.",
    },
    "ia-12.3": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": "See IA-12. No end users, no identity evidence to validate.",
    },
    "ia-12.5": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": "See IA-12. No end users, no addresses to confirm.",
    },

    # ===== IR family Moderate-only =====
    # IR-9 family is implemented via a dedicated Information Spillage
    # Response section in docs/incident-response.md.

    "ir-9": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Information spillage response is documented in "
            "docs/incident-response.md under the 'Information Spillage "
            "Response' section. In-scope spillage scenarios for a static "
            "site include accidentally posted credentials, AWS account "
            "identifiers, or pre-publication private content. The response "
            "procedure (identify, remove from public surfaces, rotate any "
            "compromised credentials, document) is in the runbook."
        ),
    },
    "ir-9.2": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Spillage-response training: incorporated into the runbook "
            "review the operator performs annually per "
            "docs/security-review.md (KSI-CED-04). For a sole-operator "
            "system there is no separate cohort to train; the IR lead "
            "and the trainee are the same person."
        ),
    },
    "ir-9.3": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Post-spill operations: the spillage scope is bounded by the "
            "static-site surface (public content, deploy credentials, "
            "AWS account IDs in published artifacts). After containment "
            "the system continues normal operation; no quarantine of a "
            "production environment is required because the production "
            "environment is the public site."
        ),
    },
    "ir-9.4": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Exposure to unauthorized personnel: the public site by "
            "design has no 'unauthorized personnel'; any reader is "
            "authorized. Spillage exposure is therefore handled as "
            "premature publication of content not yet ready for public "
            "release, addressed by the IR-9 response procedure."
        ),
    },

    # ===== MP family — physical media N/A overrides =====

    "mp-3": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Media marking is not applicable: the system uses no physical "
            "media. All storage is on AWS-managed services (S3, "
            "CloudWatch Logs); media-level marking would be AWS's concern "
            "if any physical media were involved at the infrastructure "
            "layer (covered as inherited under MP-1)."
        ),
    },
    "mp-4": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Media storage is not applicable: see MP-3. No physical "
            "media in operator scope."
        ),
    },
    "mp-5": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Media transport is not applicable: see MP-3. No physical "
            "media to transport."
        ),
    },

    # ===== PE Moderate-only =====
    "pe-17": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Alternate work site controls are not applicable for a sole-"
            "operator system. The operator's work locations are personal "
            "and outside the system boundary; no agency-defined alternate "
            "work site exists."
        ),
    },

    # ===== PS Moderate-only =====
    "ps-3.3": {
        "status": "not-applicable",
        "origination": "sp-corporate",
        "statement": (
            "Information requiring special protective measures is not "
            "applicable: the system processes no controlled-information "
            "categories (CUI, PII, PHI, classified). All site content is "
            "intentionally public; no special-protection screening is "
            "warranted."
        ),
    },

    # ===== RA Moderate-only =====
    "ra-5.5": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Privileged-access vulnerability scanning is not applicable: "
            "the system has no general-purpose hosts to scan with "
            "privileged credentials. The Lambda runtime is AWS-managed; "
            "vulnerability scanning at the dependency level is via "
            "Dependabot (RA-5)."
        ),
    },
    "ra-9": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Criticality analysis is documented in docs/recovery-plan.md. "
            "The declared RTO of 21 days and RPO of 24 hours embodies the "
            "criticality assessment: low-criticality (the world manages "
            "without the operator's opinions for three weeks). Asset "
            "criticality is implicit in the canonical inventory; no "
            "component beyond the static site itself is critical to a "
            "mission."
        ),
    },

    # ===== SA Moderate-only =====

    "sa-4.1": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Functional properties of controls are documented for AWS "
            "managed services in AWS's published service documentation "
            "(inherited). For operator-implemented controls, the "
            "functional properties are documented in this SSP's per-"
            "control statements and the docs/architecture-decisions.md "
            "file."
        ),
    },
    "sa-4.2": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Design and implementation information for AWS-managed "
            "services is published by AWS in its service documentation "
            "(inherited). For operator-implemented components, the "
            "design and implementation are visible in the open-source "
            "repository and the per-control statements in this SSP."
        ),
    },
    "sa-4.9": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Functions, ports, protocols, and services in use are "
            "minimal and documented: the system uses HTTPS (port 443) "
            "for all viewer traffic, AWS APIs (HTTPS) for control-plane "
            "operations, and DNS (port 53) for resolution. No other "
            "ports or protocols are exposed. The Lambda has no inbound "
            "network listener; the Lambda runtime accepts only "
            "EventBridge invocations."
        ),
    },
    "sa-9.1": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Risk assessment and approval for external system services: "
            "the operator has explicitly chosen AWS services after risk "
            "review; the choices are documented in "
            "docs/architecture-decisions.md and "
            "docs/security-review.md (annual review). Each service "
            "selection (S3, CloudFront, Lambda, Route 53, ACM, "
            "EventBridge, CloudWatch, IAM) is recorded with rationale."
        ),
    },
    "sa-9.2": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Identification of functions, ports, protocols, and services "
            "for external services: AWS documents each service's network "
            "characteristics; the operator's usage profile is documented "
            "via Terraform configuration and the canonical inventory. "
            "See SA-4.9."
        ),
    },
    "sa-9.5": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Processing, storage, and service location: the system runs "
            "in the AWS us-east-2 region (configured in "
            "`infrastructure/variables.tf`). CloudFront is global by "
            "design; ACM certificates for CloudFront are in us-east-1 as "
            "AWS requires. No data leaves AWS commercial regions."
        ),
    },
    "sa-11": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Developer testing and evaluation: every pull request to "
            "`main` runs the OPA gate (configuration), Checkov "
            "(IaC scanning), tfsec (Terraform-specific scanning), and "
            "Dependabot (SCA via the GitHub Advisory Database). "
            "Static-analysis findings are surfaced in the GitHub "
            "Security tab. Tests gate merges; failing PRs cannot reach "
            "production."
        ),
    },
    "sa-11.1": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Static code analysis: Checkov and tfsec run as required CI "
            "checks on every pull request, scanning Terraform and "
            "associated configuration. Results are uploaded to the "
            "GitHub Security tab as SARIF reports."
        ),
    },
    "sa-11.2": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Threat modeling and vulnerability analyses are documented "
            "in docs/architecture-decisions.md under the 'Threat "
            "Modeling' section. The model identifies the principal "
            "threat surfaces (deploy chain, runtime emitter, public "
            "artifacts), top threats considered (repo compromise, "
            "deployer credential leak, runtime Lambda compromise), and "
            "the mitigations in place. Vulnerability analysis is "
            "automated via the SAST/SCA tools described under SA-11."
        ),
    },
    "sa-15": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Development process, standards, and tools: the gitops "
            "workflow (PR → OPA gate → review → merge → deploy) is the "
            "development standard. Tools (Terraform, OPA, Checkov, "
            "tfsec, Dependabot, cosign) are documented in this SSP and "
            "in the README. The operator follows a consistent process "
            "for every change."
        ),
    },

    # ===== SC Moderate-only =====
    "sc-7.18": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Fail-secure boundary protection: CloudFront's viewer-"
            "protocol policy is set to redirect-to-HTTPS, with TLS 1.2+ "
            "enforced. If the policy fails to apply, the deploy gate "
            "blocks and the runtime emitter detects the drift. AWS "
            "provides the underlying TLS-termination and certificate "
            "infrastructure; the operator configures the fail-closed "
            "policy."
        ),
    },
    "sc-7.12": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Host-based protection is not applicable: the system has no "
            "general-purpose hosts. The Lambda runtime is AWS-managed; "
            "host-level protections are inherited under PE/MA where "
            "applicable."
        ),
    },
    "sc-39": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Process isolation is not applicable in the multi-tenant-"
            "compute sense: the system has no multi-tenant compute. "
            "AWS provides process isolation at the Lambda runtime "
            "layer (inherited)."
        ),
    },

    # ===== SI Moderate-only =====
    "si-2.3": {
        "status": "implemented",
        "origination": "sp-corporate",
        "statement": (
            "Time to remediate flaws and benchmarks for corrective "
            "actions: Dependabot's severity gating defines the SLA. "
            "Critical CVEs are addressed within one week of advisory "
            "publication; high-severity within one month; lower "
            "severities reviewed at the next dependency-update cycle. "
            "Tracked in the annual security review."
        ),
    },
    "si-4.1": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "System-wide intrusion detection is not applicable: the "
            "system has no general-purpose compute hosting that would "
            "host an IDS agent. AWS-side intrusion detection is "
            "inherited; CloudTrail captures AWS API activity."
        ),
    },
    "si-4.16": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Correlation of monitoring information: CloudTrail "
            "correlates AWS API activity (inherited); the canonical "
            "KSI signal correlates compliance validations across "
            "components by component_refs. Drift between the deploy-"
            "time and runtime KSI signals is the cross-source "
            "correlation surface."
        ),
    },
    "si-4.18": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Analysis of traffic and covert exfiltration is not "
            "applicable: the system has no compute that initiates "
            "outbound traffic to untrusted destinations. Lambda "
            "egress is to AWS APIs only; CloudFront is unidirectional "
            "(serving public content)."
        ),
    },
    "si-4.23": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Host-based monitoring devices are not applicable: see "
            "SI-4.1."
        ),
    },
    "si-6": {
        "status": "implemented",
        "origination": "sp-system",
        "statement": (
            "Security and privacy function verification: the OPA gate "
            "evaluates security functions on every deploy, and the "
            "runtime KSI emitter re-verifies the live configuration "
            "daily. Both produce structured records in the KSI signal. "
            "Verification failures block deploy or are recorded as "
            "drift in the runtime signal."
        ),
    },
    "si-8": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": (
            "Spam protection is not applicable: the system runs no "
            "email service or message-receiving endpoint."
        ),
    },
    "si-8.2": {
        "status": "not-applicable",
        "origination": "sp-system",
        "statement": "See SI-8. No spam-handling surface to update.",
    },
    "si-16": {
        "status": "implemented",
        "origination": "inherited",
        "statement": (
            "Memory protection: AWS Lambda's runtime provides per-"
            "invocation isolation, address-space layout randomization, "
            "and process-level memory protection inherited from the "
            "underlying execution environment. The operator runs no "
            "custom compute that requires additional memory-protection "
            "controls."
        ),
    },

    # ===== SR Moderate-only =====
    "sr-6": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Supplier assessments and reviews: AWS's supplier-assessment "
            "program is inherited under its FedRAMP authorization. For "
            "OSS suppliers (npm, Terraform providers, GitHub Actions, "
            "OPA, cosign), the operator's review is via Dependabot "
            "automated alerts plus Sigstore-signed provenance for "
            "cosign-signed artifacts. See docs/supply-chain.md."
        ),
    },
}

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
            "overrides (AC-2/3/4/6/17) are predominantly user-account "
            "features (session management, wireless access, mobile-device "
            "authentication, attribute-based access). The system has no "
            "human end users, no wireless interfaces, no mobile clients, "
            "and no internal session model — these controls are "
            "structurally not applicable. The few that are not user-"
            "centric (e.g., AC-20 use of external systems) are addressed "
            "by the AWS-managed service boundary."
        ),
    },
    # Audit — most enhancements are inherited from AWS (CloudTrail handles
    # the heavy lifting automatically); operator configures content/retention.
    "au-": {
        "status": "implemented",
        "origination": "shared",
        "statement": (
            "Audit family controls beyond those with explicit overrides "
            "(AU-2/3/12) are addressed primarily through CloudTrail "
            "(account-wide AWS API logging, inherited from AWS) and "
            "CloudWatch Logs (Lambda execution, configured by the system). "
            "Audit storage capacity, time-stamp generation, and audit-"
            "record protection are AWS-managed features of those services. "
            "Audit review cadence is documented in docs/architecture-"
            "decisions.md (KSI-MLA-02 section)."
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
            "(KSI-CNA-08). Authorization sub-controls in the FedRAMP sense "
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
            "Identification and Authentication family controls beyond IA-3 "
            "(non-user identification, addressed via AWS IAM principals) "
            "are dominated by user-facing features: MFA, password "
            "complexity, identity proofing, authenticator management for "
            "human accounts. The system has no human end users; these "
            "controls are structurally not applicable. The few exceptions "
            "(IA-5 authenticator management for the deployer's secrets) "
            "are addressed via GitHub Actions encrypted secrets and "
            "tracked under POAM-001 for migration to OIDC."
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
            "maintenance under their FedRAMP authorization. The system "
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
            "FedRAMP authorization."
        ),
    },
    # Physical and Environmental — inherited
    "pe-": {
        "status": "implemented",
        "origination": "inherited",
        "statement": (
            "Inherited from AWS. AWS data centers operate under their "
            "FedRAMP-authorized physical and environmental security "
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
            "authorization; OSS dependencies are subject to the supply-"
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
# in this implementation) under their own FedRAMP authorization. These are
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
BASELINE_CONTROLS = frozenset({
    # Access Control (43)
    "ac-1", "ac-2", "ac-2.1", "ac-2.2", "ac-2.3", "ac-2.4", "ac-2.5",
    "ac-2.7", "ac-2.9", "ac-2.12", "ac-2.13",
    "ac-3", "ac-4", "ac-4.21", "ac-5", "ac-6", "ac-6.1", "ac-6.2",
    "ac-6.5", "ac-6.7", "ac-6.9", "ac-6.10",
    "ac-7", "ac-8", "ac-11", "ac-11.1", "ac-12", "ac-14",
    "ac-17", "ac-17.1", "ac-17.2", "ac-17.3", "ac-17.4",
    "ac-18", "ac-18.1", "ac-18.3", "ac-19", "ac-19.5",
    "ac-20", "ac-20.1", "ac-20.2", "ac-21", "ac-22",
    # Awareness and Training (6)
    "at-1", "at-2", "at-2.2", "at-2.3", "at-3", "at-4",
    # Audit and Accountability (16)
    "au-1", "au-2", "au-3", "au-3.1", "au-4", "au-5",
    "au-6", "au-6.1", "au-6.3", "au-7", "au-7.1", "au-8",
    "au-9", "au-9.4", "au-11", "au-12",
    # Assessment, Authorization, and Monitoring (14)
    "ca-1", "ca-2", "ca-2.1", "ca-2.3", "ca-3", "ca-5", "ca-6",
    "ca-7", "ca-7.1", "ca-7.4", "ca-8", "ca-8.1", "ca-8.2", "ca-9",
    # Configuration Management (27)
    "cm-1", "cm-2", "cm-2.2", "cm-2.3", "cm-2.7",
    "cm-3", "cm-3.2", "cm-3.4", "cm-4", "cm-4.2",
    "cm-5", "cm-5.1", "cm-5.5", "cm-6", "cm-6.1",
    "cm-7", "cm-7.1", "cm-7.2", "cm-7.5",
    "cm-8", "cm-8.1", "cm-8.3", "cm-9", "cm-10", "cm-11",
    "cm-12", "cm-12.1",
    # Contingency Planning (23)
    "cp-1", "cp-2", "cp-2.1", "cp-2.3", "cp-2.8", "cp-3",
    "cp-4", "cp-4.1",
    "cp-6", "cp-6.1", "cp-6.3", "cp-7", "cp-7.1", "cp-7.2", "cp-7.3",
    "cp-8", "cp-8.1", "cp-8.2",
    "cp-9", "cp-9.1", "cp-9.8", "cp-10", "cp-10.2",
    # Identification and Authentication (27)
    "ia-1", "ia-2", "ia-2.1", "ia-2.2", "ia-2.5", "ia-2.6",
    "ia-2.8", "ia-2.12", "ia-3", "ia-4", "ia-4.4",
    "ia-5", "ia-5.1", "ia-5.2", "ia-5.6", "ia-5.7",
    "ia-6", "ia-7", "ia-8", "ia-8.1", "ia-8.2", "ia-8.4",
    "ia-11", "ia-12", "ia-12.2", "ia-12.3", "ia-12.5",
    # Incident Response (17)
    "ir-1", "ir-2", "ir-3", "ir-3.2", "ir-4", "ir-4.1",
    "ir-5", "ir-6", "ir-6.1", "ir-6.3", "ir-7", "ir-7.1",
    "ir-8", "ir-9", "ir-9.2", "ir-9.3", "ir-9.4",
    # Maintenance (10)
    "ma-1", "ma-2", "ma-3", "ma-3.1", "ma-3.2", "ma-3.3",
    "ma-4", "ma-5", "ma-5.1", "ma-6",
    # Media Protection (7)
    "mp-1", "mp-2", "mp-3", "mp-4", "mp-5", "mp-6", "mp-7",
    # Physical and Environmental Protection (19)
    "pe-1", "pe-2", "pe-3", "pe-4", "pe-5",
    "pe-6", "pe-6.1", "pe-8", "pe-9", "pe-10", "pe-11",
    "pe-12", "pe-13", "pe-13.1", "pe-13.2",
    "pe-14", "pe-15", "pe-16", "pe-17",
    # Planning (7)
    "pl-1", "pl-2", "pl-4", "pl-4.1", "pl-8", "pl-10", "pl-11",
    # Personnel Security (10)
    "ps-1", "ps-2", "ps-3", "ps-3.3", "ps-4", "ps-5",
    "ps-6", "ps-7", "ps-8", "ps-9",
    # Risk Assessment (11)
    "ra-1", "ra-2", "ra-3", "ra-3.1", "ra-5", "ra-5.2",
    "ra-5.3", "ra-5.5", "ra-5.11", "ra-7", "ra-9",
    # System and Services Acquisition (21)
    "sa-1", "sa-2", "sa-3", "sa-4", "sa-4.1", "sa-4.2", "sa-4.9",
    "sa-4.10", "sa-5", "sa-8", "sa-9", "sa-9.1", "sa-9.2", "sa-9.5",
    "sa-10", "sa-11", "sa-11.1", "sa-11.2", "sa-15", "sa-15.3", "sa-22",
    # System and Communications Protection (29)
    "sc-1", "sc-2", "sc-4", "sc-5", "sc-7", "sc-7.3", "sc-7.4",
    "sc-7.5", "sc-7.7", "sc-7.8", "sc-7.12", "sc-7.18",
    "sc-8", "sc-8.1", "sc-10", "sc-12", "sc-13", "sc-15",
    "sc-17", "sc-18", "sc-20", "sc-21", "sc-22", "sc-23",
    "sc-28", "sc-28.1", "sc-39", "sc-45", "sc-45.1",
    # System and Information Integrity (24)
    "si-1", "si-2", "si-2.2", "si-2.3", "si-3", "si-4",
    "si-4.1", "si-4.2", "si-4.4", "si-4.5", "si-4.16", "si-4.18",
    "si-4.23", "si-5", "si-6", "si-7", "si-7.1", "si-7.7",
    "si-8", "si-8.2", "si-10", "si-11", "si-12", "si-16",
    # Supply Chain Risk Management (12)
    "sr-1", "sr-2", "sr-2.1", "sr-3", "sr-5", "sr-6",
    "sr-8", "sr-10", "sr-11", "sr-11.1", "sr-11.2", "sr-12",
})

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
    # all maintenance tooling and personnel under its FedRAMP authorization.
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


def resolve_control_profile(control_id, control_title):
    """Return (status, origination, statement) for a NIST 800-53 control.

    Resolution order:
      1. Explicit per-control override in CONTROL_OVERRIDES.
      2. *-1 controls (policy and procedures) hit POLICY_AND_PROCEDURES_DEFAULT.
      3. Family default in FAMILY_DEFAULTS.
      4. Last-resort generic fallback.
    """
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
        "title": "samaydlette.com — System Security Plan (Self-Attested PoC, NOT FedRAMP-Authorized)",
        "last-modified": now_iso(),
        "version": SSP_VERSION,
        "oscal-version": OSCAL_VERSION,
        "remarks": (
            "This System Security Plan is a self-attested proof-of-concept artifact. "
            "The system it describes is NOT FedRAMP-authorized. No 3PAO assessment has "
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
                "remarks": "This SSP is operator-self-attested; no 3PAO assessment, no agency ATO.",
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
        ident = f"{c.get('component_id', '')} {c.get('native_id', '')}".lower()
        if c.get("type") == "function" and "silk-reeling" in ident:
            return True
    return False


def build_system_characteristics(signal):
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
            "authorization in scope."
        ),
        "security-sensitivity-level": "low",
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
                        "base": "fips-199-low",
                    },
                    "integrity-impact": {
                        "base": "fips-199-low",
                    },
                    "availability-impact": {
                        "base": "fips-199-low",
                    },
                }
            ]
        },
        "security-impact-level": {
            "security-objective-confidentiality": "low",
            "security-objective-integrity": "low",
            "security-objective-availability": "low",
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
    }
    # The gated Silk Reeling app, when deployed, adds an external interconnection
    # (Anthropic API) and a boundary-crossing data flow. Emitted only when the
    # app is present in the canonical inventory. See docs/poam.md POAM-020 (SA-9).
    if _silk_reeling_present(signal):
        sc["data-flow"] = {
            "description": (
                "Browser captures pose landmarks client-side and POSTs them to "
                "the Silk Reeling app Lambda over TLS (CloudFront → API Gateway "
                "HTTP API → Lambda; the app's in-Lambda HTTP Basic Auth gates "
                "every request, no Gateway authorizer per POAM-022). The Lambda "
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
            and not ksis
        )

        if purely_inherited:
            inherited_title = INHERITED_FROM_AWS[control_id]
            status = "implemented"
            origination = "inherited"
            statement = (
                f"{inherited_title} ({control_id.upper()}) is inherited "
                f"from AWS under the AWS FedRAMP authorization. The "
                f"system has no operator-side responsibility for this "
                f"control; AWS's published customer-responsibility "
                f"matrix carries the full implementation. This entry is "
                f"included so the SSP addresses the FedRAMP Rev 5 Moderate "
                f"baseline in full, even where the 20x KSI catalog is "
                f"silent because the control has no tenant-side surface."
            )
        else:
            status, origination, statement = resolve_control_profile(control_id, title)

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
            f"infrastructure/schemas/ksi-catalog.json): {', '.join(ksis)}."
        )
        statement_text = statement + ksi_footer

        # Inherited controls also get an AWS FedRAMP reference link so the
        # SSP's reader can follow the inheritance chain even when the
        # control is reached via the KSI-derived path.
        links = _links_for_ksis(ksis)
        if origination == "inherited":
            props.append({
                "name": "leveraged-authorization",
                "value": "AWS FedRAMP Authorization (commercial regions)",
            })
            links.append({
                "href": "https://aws.amazon.com/compliance/fedramp/",
                "rel": "reference",
                "text": "AWS FedRAMP authorization",
            })

        implemented_reqs.append({
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
        })

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
            "wholly under its FedRAMP authorization (PE, MP, parts of MA), "
            "and is therefore emitted here as inherited so the SSP addresses "
            "the baseline in full. Evidence references point at the live "
            "KSI signal at /.well-known/ksi-signal.json (deploy-time, signed "
            "via Sigstore), the runtime signal at "
            "/.well-known/ksi-signal-runtime.json, the AWS FedRAMP "
            "authorization page, and the documentation set in docs/."
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
                failing.update({"KSI-CMT-02", "KSI-CNA-04", "KSI-SVC-04"})
            elif policy_id == "runtime.cloudfront_security":
                failing.update({"KSI-SVC-02", "KSI-CNA-04"})
            elif policy_id == "terraform.compliance":
                # Deploy-time policy: granular KSI mapping not encoded.
                # Mark a synthetic id so the downgrade fires for affected
                # controls; we treat infrastructure findings as touching
                # CMT/CNA/SVC families broadly.
                failing.update({"KSI-CMT-03", "KSI-MLA-05"})
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
