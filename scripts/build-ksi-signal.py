#!/usr/bin/env python3
# =============================================================================
# DEPLOY-TIME KSI SIGNAL EMITTER
# =============================================================================
# Produces ksi-signal.json — a FedRAMP 20x-style KSI validation signal extended
# with normalized component identifiers, as proposed in
# https://samaydlette.com/pages/article-27.html.
#
# Inputs (joined into one signal):
#   - terraform output -json            → ARNs of deployed AWS resources
#   - terraform show -json              → full state, used for resource discovery
#   - lambda/package-lock.json          → npm packages inside the compliance Lambda
#   - sbom-python.json (CycloneDX)      → Silk Reeling Lambda's Python/PyPI deps
#                                         (Syft `syft dir:_pkg`, written by deploy)
#   - sbom-js.json     (CycloneDX)      → Silk Reeling SPA's npm deps
#                                         (Syft `syft dir:_silk_src/frontend`)
#   - ../website/**/*.html              → static HTML artifacts (sha256-hashed)
#   - validations.json                  → OPA results from scripts/terraform-plan.sh
#   - GITHUB_* env vars                 → SLSA-style build provenance (when in CI)
#
# Output:
#   - ksi-signal.json — conforms to schemas/ksi-signal.schema.json
#
# Run from the infrastructure/ directory:
#   python3 ../scripts/build-ksi-signal.py
# =============================================================================

import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# =============================================================================
# CONSTANTS
# =============================================================================
# These are the cross-CSP normalization decisions called out explicitly in the
# accompanying research paper. Adding a new CSP means extending TYPE_BY_TF_TYPE
# (and possibly the schema's component.type enum) — the join keys themselves
# (PURL for software, native ARN/ID for cloud, sha256 for static content)
# don't need to change.
# =============================================================================

SIGNAL_VERSION = "1.0.0"
SYSTEM_ID = "urn:samaydlette:website-prod"
CSP = "aws"

# Maps Terraform resource types to the normalized component.type vocabulary in
# the schema. Resource types that aren't a "component" in the portfolio sense
# (IAM bindings, bucket-attached config like versioning/encryption, log groups)
# are absent on purpose — their effect is folded into attributes on the parent
# component, not represented as separate components.
TYPE_BY_TF_TYPE = {
    "aws_s3_bucket": "object_store",
    "aws_cloudfront_distribution": "cdn_distribution",
    "aws_lambda_function": "function",
    "aws_route53_zone": "dns_zone",
    "aws_acm_certificate": "tls_certificate",
    "aws_cloudwatch_event_rule": "event_schedule",
    "aws_iam_role": "iam_role",
    "aws_iam_role_policy": "iam_policy",
    "aws_iam_policy": "iam_policy",  # managed policy (e.g., bootstrap assessment-readonly)
    # CI/CD identity plane (infrastructure/bootstrap): the GitHub OIDC provider,
    # the deploy/assessment roles (aws_iam_role above), and the operators group.
    # These are the highest-privilege identities governing the production system,
    # so they are inventoried, not excused — ingested from the bootstrap module's
    # separate Terraform state by build_bootstrap_components().
    "aws_iam_group": "iam_group",
    "aws_iam_openid_connect_provider": "oidc_provider",
    "aws_cloudtrail": "audit_log_trail",
    "aws_cloudwatch_log_group": "log_group",
    # In-boundary components previously omitted (assessment F-1/B-1): the API
    # Gateway fronting the Silk Reeling app, the two Secrets Manager secrets it
    # reads, and the customer-managed KMS key. The reconciliation gate's live
    # deny-by-default enumeration (scripts/reconcile.py, invariant a) fails the
    # build if any live in-boundary resource is still missing from the inventory.
    "aws_apigatewayv2_api": "api_gateway",
    "aws_secretsmanager_secret": "secrets_manager",
    "aws_kms_key": "kms_key",
    # Task 3: the Cognito user pool is the identity provider gating the Silk
    # Reeling app (replaced the shared Basic-Auth secret). Its app client and
    # Hosted-UI domain fold into it as attributes (ATTRIBUTE_PARENTS below).
    "aws_cognito_user_pool": "identity_provider",
}

# Authoritative, external type vocabulary: each normalized component.type maps
# to its CloudFormation resource-type identifier. This is what the schema now
# validates against (an open, vendor-maintained namespace) so a newly-added
# resource type cannot silently fall outside a hand-maintained enum — it carries
# its CFN type on the `resource_type` field, and an unmapped one is caught by
# the gate rather than disappearing. Software/external components (npm, pypi,
# html, external_service) are not AWS resources and carry no CFN type.
CFN_TYPE_BY_NORMALIZED = {
    "object_store": "AWS::S3::Bucket",
    "cdn_distribution": "AWS::CloudFront::Distribution",
    "function": "AWS::Lambda::Function",
    "dns_zone": "AWS::Route53::HostedZone",
    "tls_certificate": "AWS::CertificateManager::Certificate",
    "event_schedule": "AWS::Events::Rule",
    "iam_role": "AWS::IAM::Role",
    "iam_policy": "AWS::IAM::RolePolicy",
    "iam_group": "AWS::IAM::Group",
    "oidc_provider": "AWS::IAM::OIDCProvider",
    "audit_log_trail": "AWS::CloudTrail::Trail",
    "log_group": "AWS::Logs::LogGroup",
    "api_gateway": "AWS::ApiGatewayV2::Api",
    "secrets_manager": "AWS::SecretsManager::Secret",
    "kms_key": "AWS::KMS::Key",
    "identity_provider": "AWS::Cognito::UserPool",
}

# Resource types that fold into a parent component as attributes. The mapping
# value is the parent component's normalized type — used to find the parent.
ATTRIBUTE_PARENTS = {
    "aws_s3_bucket_versioning": "object_store",
    "aws_s3_bucket_server_side_encryption_configuration": "object_store",
    "aws_s3_bucket_public_access_block": "object_store",
    "aws_s3_bucket_policy": "object_store",
    "aws_cloudfront_response_headers_policy": "cdn_distribution",
    # API Gateway sub-resources fold into the api_gateway component so a consumer
    # sees one interface with its route/integration/stage config, not four things.
    "aws_apigatewayv2_integration": "api_gateway",
    "aws_apigatewayv2_route": "api_gateway",
    "aws_apigatewayv2_stage": "api_gateway",
    # The Cognito JWT authorizer is a property of the API's access control, not a
    # standalone component — fold it into the api_gateway it protects (Task 3).
    "aws_apigatewayv2_authorizer": "api_gateway",
    # The app client and Hosted-UI domain are facets of the identity provider.
    "aws_cognito_user_pool_client": "identity_provider",
    "aws_cognito_user_pool_domain": "identity_provider",
}

# =============================================================================
# MAS (Minimum Assessment Scope) attributes per component type
# =============================================================================
# Per FedRAMP 20x rule MAS-CSO-FLO, every information resource must declare a
# FIPS 199 security category and an information-flow summary. The defaults
# below are the system-specific assignments for samaydlette.com; another system
# would override these with its own categorization.
#
# Categorization rationale: this is a public static site with no PII, so
# confidentiality is LOW everywhere. Integrity is MODERATE because defacement
# is the highest-impact realistic threat. Availability is LOW because a
# personal site can tolerate downtime within the declared 21-day RTO.
# High-water mark across the system: MODERATE (driven by integrity).
# =============================================================================

MAS_DEFAULTS = {
    "object_store": {
        "security_category": {"confidentiality": "low", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "inbound", "counterparty": "cdn_distribution", "channel": "aws-internal-tls", "data_class": "public-content"},
            {"direction": "outbound", "counterparty": "cdn_distribution", "channel": "aws-internal-tls", "data_class": "public-content"},
            {"direction": "inbound", "counterparty": "github-actions", "channel": "tls-1.2", "data_class": "public-content"},
        ],
    },
    "cdn_distribution": {
        "security_category": {"confidentiality": "low", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "inbound", "counterparty": "public-internet", "channel": "tls-1.2", "data_class": "public-content"},
            {"direction": "outbound", "counterparty": "public-internet", "channel": "tls-1.2", "data_class": "public-content"},
            {"direction": "inbound", "counterparty": "object_store", "channel": "aws-internal-tls", "data_class": "public-content"},
        ],
    },
    "function": {
        "security_category": {"confidentiality": "low", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "inbound", "counterparty": "eventbridge", "channel": "aws-internal-tls", "data_class": "configuration"},
            {"direction": "outbound", "counterparty": "aws-service-api", "channel": "aws-internal-tls", "data_class": "configuration"},
            {"direction": "outbound", "counterparty": "object_store", "channel": "aws-internal-tls", "data_class": "audit"},
        ],
    },
    "npm_package": {
        "security_category": {"confidentiality": "not-applicable", "integrity": "moderate", "availability": "not-applicable"},
        "information_flow": [],
    },
    "pypi_package": {
        "security_category": {"confidentiality": "not-applicable", "integrity": "moderate", "availability": "not-applicable"},
        "information_flow": [],
    },
    "html_artifact": {
        "security_category": {"confidentiality": "low", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "outbound", "counterparty": "object_store", "channel": "aws-internal-tls", "data_class": "public-content"},
        ],
    },
    "dns_zone": {
        "security_category": {"confidentiality": "low", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "inbound", "counterparty": "public-internet", "channel": "dns", "data_class": "public-dns"},
            {"direction": "outbound", "counterparty": "public-internet", "channel": "dns", "data_class": "public-dns"},
        ],
    },
    "tls_certificate": {
        "security_category": {"confidentiality": "not-applicable", "integrity": "moderate", "availability": "low"},
        "information_flow": [],
    },
    "event_schedule": {
        "security_category": {"confidentiality": "not-applicable", "integrity": "low", "availability": "low"},
        "information_flow": [
            {"direction": "outbound", "counterparty": "function", "channel": "aws-internal-tls", "data_class": "configuration"},
        ],
    },
    "iam_role": {
        "security_category": {"confidentiality": "moderate", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "internal", "counterparty": "aws-service-api", "channel": "aws-internal-tls", "data_class": "authorization-claims"},
        ],
    },
    "iam_policy": {
        "security_category": {"confidentiality": "moderate", "integrity": "moderate", "availability": "low"},
        "information_flow": [],
    },
    "audit_log_trail": {
        "security_category": {"confidentiality": "moderate", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "inbound", "counterparty": "aws-service-api", "channel": "aws-internal-tls", "data_class": "audit"},
        ],
    },
    "log_group": {
        "security_category": {"confidentiality": "low", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "inbound", "counterparty": "function", "channel": "aws-internal-tls", "data_class": "logs"},
        ],
    },
    "external_service": {
        "security_category": {"confidentiality": "low", "integrity": "moderate", "availability": "low"},
        "information_flow": [],
    },
    "api_gateway": {
        "security_category": {"confidentiality": "low", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "inbound", "counterparty": "public-internet", "channel": "tls-1.2", "data_class": "user-input"},
            {"direction": "outbound", "counterparty": "function", "channel": "aws-internal-tls", "data_class": "user-input"},
        ],
    },
    "secrets_manager": {
        # Confidentiality is MODERATE here: this resource holds credentials.
        # That does not raise the system high-water mark (still Moderate).
        "security_category": {"confidentiality": "moderate", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "outbound", "counterparty": "function", "channel": "aws-internal-tls", "data_class": "credential"},
        ],
    },
    "kms_key": {
        "security_category": {"confidentiality": "low", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "inbound", "counterparty": "function", "channel": "aws-internal-tls", "data_class": "configuration"},
            {"direction": "inbound", "counterparty": "secrets_manager", "channel": "aws-internal-tls", "data_class": "configuration"},
        ],
    },
    "identity_provider": {
        # Confidentiality is MODERATE: the pool holds user credentials and TOTP
        # MFA secrets. Integrity is MODERATE (it is the access-control authority).
        # This does not raise the system high-water mark (still Moderate).
        "security_category": {"confidentiality": "moderate", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "inbound", "counterparty": "public-internet", "channel": "tls-1.2", "data_class": "credential"},
            {"direction": "outbound", "counterparty": "api_gateway", "channel": "tls-1.2", "data_class": "credential"},
        ],
    },
}

# =============================================================================
# IIW (Integrated Inventory Workbook) attributes per component type
# =============================================================================
# Stamped onto component.attributes so the canonical inventory carries the
# fields the FedRAMP IIW (SSP Appendix M) requires. The build-iiw.py projector
# reads these to emit an IIW-compatible CSV.
# =============================================================================

IIW_DEFAULTS = {
    "object_store": {
        "function": "Origin storage for static site content and /.well-known/ artifacts",
        "diagram_label": "S3 origin bucket",
        "public": False,
        "baseline_configuration": "AWS S3 default + bucket policy enforcing OAC + public access block",
        "iiw_asset_type": "Object Storage (S3 bucket)",
    },
    "cdn_distribution": {
        "function": "Public content delivery (TLS 1.2+, OAC to origin)",
        "diagram_label": "CloudFront distribution",
        "public": True,
        "baseline_configuration": "AWS CloudFront default + custom security headers policy",
        "iiw_asset_type": "Content Delivery Network (CloudFront distribution)",
    },
    "function": {
        "function": "Daily runtime KSI emitter; revalidates live AWS configuration",
        "diagram_label": "Lambda — runtime KSI emitter",
        "public": False,
        "baseline_configuration": "AWS Lambda default + IAM scope (read 3 S3 config APIs, 1 CF distribution; write 1 S3 key)",
        "iiw_asset_type": "Compute Function (Lambda)",
    },
    "npm_package": {
        "function": "Runtime dependency of the compliance/KSI Lambda (npm)",
        "diagram_label": "Open-source policy and signing tooling running inside CI",
        "public": False,
        "baseline_configuration": "package-lock.json integrity hash; Dependabot-monitored",
        "iiw_asset_type": "Software Package (npm)",
    },
    "pypi_package": {
        "function": "Python dependency of the Silk Reeling application (PyPI)",
        "diagram_label": "Open-source Python dependency of the Silk Reeling app",
        "public": False,
        "baseline_configuration": "lockfile integrity hash; Dependabot-monitored",
        "iiw_asset_type": "Software Package (PyPI)",
    },
    "html_artifact": {
        "function": "Public site content",
        "diagram_label": "S3 origin bucket (content)",
        "public": True,
        "baseline_configuration": "Static HTML served via CloudFront; SHA-256 content-addressed in canonical inventory",
        "iiw_asset_type": "Static Content Artifact",
    },
    "dns_zone": {
        "function": "Authoritative DNS for the public domain",
        "diagram_label": "Route 53 hosted zone",
        "public": True,
        "baseline_configuration": "AWS Route 53; DNSSEC signing enabled (customer-managed KSK in KMS us-east-1, D-3; SC-20/SC-21)",
        "iiw_asset_type": "DNS Zone (Route 53)",
    },
    "tls_certificate": {
        "function": "Public TLS certificate for the CDN",
        "diagram_label": "ACM TLS certificate",
        "public": False,
        "baseline_configuration": "AWS ACM-managed; auto-renewing; FIPS-validated cipher suites via CloudFront",
        "iiw_asset_type": "TLS Certificate (ACM)",
    },
    "event_schedule": {
        "function": "Daily trigger for the runtime KSI emitter Lambda",
        "diagram_label": "EventBridge schedule",
        "public": False,
        "baseline_configuration": "AWS EventBridge default; rate-based schedule",
        "iiw_asset_type": "Event Schedule (EventBridge)",
    },
    "iam_role": {
        "function": "IAM role assumed by the runtime KSI emitter Lambda",
        "diagram_label": "IAM — Lambda role",
        "public": False,
        "baseline_configuration": "Trust policy bound to lambda.amazonaws.com; inline policy hashed in attributes (body in infrastructure/main.tf)",
        "iiw_asset_type": "IAM Role",
    },
    "iam_policy": {
        "function": "Inline policy attached to the Lambda role",
        "diagram_label": "IAM — Lambda policy",
        "public": False,
        "baseline_configuration": "Inline policy on the Lambda role; body hashed in attributes (body in infrastructure/main.tf for full review)",
        "iiw_asset_type": "IAM Policy",
    },
    "audit_log_trail": {
        "function": "Account-wide management-event audit (CloudTrail)",
        "diagram_label": "CloudTrail",
        "public": False,
        "baseline_configuration": "Account-managed; default management-event capture",
        "iiw_asset_type": "Audit Log Trail (CloudTrail)",
    },
    "log_group": {
        "function": "CloudWatch log group for Lambda execution / Route 53 query logs",
        "diagram_label": "CloudWatch Logs",
        "public": False,
        "baseline_configuration": "AWS CloudWatch; 365-day retention (AU-11; POAM-017); customer-CMK encryption at rest (POAM-018)",
        "iiw_asset_type": "Log Group (CloudWatch)",
    },
    "external_service": {
        "function": "External service in boundary per ROT #2 (affects CIA without separate FedRAMP ATO)",
        "diagram_label": "External service",
        "public": True,
        "baseline_configuration": "Public service; configuration governed by upstream provider; verification mechanism noted in attributes",
        "iiw_asset_type": "External Service (no FedRAMP ATO)",
    },
    "api_gateway": {
        "function": "HTTP API fronting the Silk Reeling app Lambda (TLS termination, request routing, throttling)",
        "diagram_label": "API Gateway (HTTP)",
        "public": True,
        "baseline_configuration": "API Gateway v2 HTTP API; managed-interface SC-7 boundary; stage throttling + access logging (Task 3)",
        "iiw_asset_type": "API Gateway (HTTP API)",
    },
    "secrets_manager": {
        "function": "Secrets Manager secret holding an application credential",
        "diagram_label": "Secrets Manager",
        "public": False,
        "baseline_configuration": "AWS Secrets Manager; KMS-encrypted at rest; rotation per disposition",
        "iiw_asset_type": "Secret (Secrets Manager)",
    },
    "kms_key": {
        "function": "Customer-managed KMS key for at-rest encryption / asymmetric signing",
        "diagram_label": "KMS key",
        "public": False,
        "baseline_configuration": "Customer-managed CMK; FIPS 140-validated module; key policy in main.tf",
        "iiw_asset_type": "KMS Key (customer-managed)",
    },
    "identity_provider": {
        "function": "Cognito user pool gating the Silk Reeling app (admin-create users, required TOTP MFA, OAuth2 PKCE Hosted UI; issues the JWTs the API Gateway authorizer validates)",
        "diagram_label": "Cognito user pool",
        "public": True,
        "baseline_configuration": "AWS Cognito user pool; MFA ON (software-token/TOTP), admin-create-only, 14-char password policy; public PKCE app client (no secret); Hosted-UI domain (Task 3)",
        "iiw_asset_type": "Identity Provider (Cognito user pool)",
    },
    "iam_group": {
        "function": "IAM group for the human operator(s); holds IAM administration privileges (POAM-026)",
        "diagram_label": "IAM — operators group",
        "public": False,
        "baseline_configuration": "Bootstrap module; group-attached managed policies; members authenticate with MFA (POAM-025). Broad IAM admin tracked as POAM-026.",
        "iiw_asset_type": "IAM Group",
    },
    "oidc_provider": {
        "function": "GitHub Actions OIDC identity provider trusted by the CI/CD deploy role (workload identity; replaced long-lived keys per POAM-001)",
        "diagram_label": "IAM — GitHub OIDC provider",
        "public": False,
        "baseline_configuration": "Bootstrap module; trusts token.actions.githubusercontent.com; deploy role trust policy restricts sub to the repo. Read-only assessment IAM tracked as POAM-027.",
        "iiw_asset_type": "OIDC Identity Provider (IAM)",
    },
}


def apply_iiw_defaults(component):
    """Stamp IIW-mapped attribute keys onto a component per its type.

    These attributes carry the fields the FedRAMP Integrated Inventory
    Workbook (Appendix M) requires. They live in component.attributes
    because the schema treats attributes as free-form (additionalProperties),
    and projecting into IIW shape is a downstream concern that does not
    require a schema change.
    """
    defaults = IIW_DEFAULTS.get(component["type"])
    if defaults is None:
        return
    component.setdefault("attributes", {})
    for key, value in defaults.items():
        component["attributes"].setdefault(key, value)


def apply_mas_defaults(component):
    """Stamp security_category and information_flow onto a component per its type.

    The schema requires both fields on every component. The defaults table
    above is the system-level categorization decision; passing through here
    makes that decision explicit and auditable rather than implicit.
    """
    defaults = MAS_DEFAULTS.get(component["type"])
    if defaults is None:
        # Unknown type: assign conservative not-applicable / empty so the
        # signal still validates against the schema. The schema's enum on
        # component.type will catch genuinely unknown types upstream.
        component["security_category"] = {
            "confidentiality": "not-applicable",
            "integrity": "not-applicable",
            "availability": "not-applicable",
        }
        component["information_flow"] = []
        return
    component["security_category"] = dict(defaults["security_category"])
    component["information_flow"] = [dict(f) for f in defaults["information_flow"]]


# =============================================================================
# RESOURCE-LEVEL CLASSIFICATION TAGS (see docs/policies/resource-tagging-standard.md)
# =============================================================================
# The governed asset-tagging standard. Every component carries six tags from
# which the VDR PAIN classifier derives the CVSS Environmental requirements
# (CR/IR/AR), the internet-reachability axis (IRV), and the multi-agency scope
# flag (m). The tag is the single source of truth; the risk inputs are derived,
# not separately tagged.
#
# data_sensitivity is kept consistent with the MAS FIPS-199 confidentiality
# category above (low -> public, moderate -> internal) so the two cannot drift.
# This system holds no PII/CUI, so no resource uses those values. agency_scope
# is hardwired "single" (single operator, no agency data — m is always 0).
# owner is a governed ROLE label, never a personal identifier (public repo).
OPERATOR_ROLE = "platform-operator"

# data_sensitivity and mission_criticality are DERIVED from the component's
# FIPS-199 categorization (security_category, set by apply_mas_defaults) so they
# can never drift from it. data_sensitivity tracks confidentiality;
# mission_criticality is the high-water mark of integrity and availability.
_CONF_TO_SENSITIVITY = {"not-applicable": "public", "low": "public",
                        "moderate": "internal", "high": "cui"}
_CAT_ORDINAL = {"not-applicable": 0, "low": 0, "moderate": 1, "high": 2}
_ORDINAL_TO_CRITICALITY = {0: "low", 1: "moderate", 2: "high"}

# Per-component-TYPE baseline for the two axes that are NOT derivable from the
# FIPS-199 categorization: internet reachability and the role-lens archetype.
# internet_reachable here is the type default; the per-resource overrides below
# correct the cases that differ (notably the two Lambdas, which share the
# "function" type but differ on reachability).
CLASSIFICATION_DEFAULTS = {
    #                       internet_reachable  archetype
    "object_store":        (False,              "internal-tooling"),
    "cdn_distribution":    (True,               "public-edge"),
    "function":            (False,              "app-tier"),
    "npm_package":         (False,              "app-tier"),
    "pypi_package":        (False,              "app-tier"),
    "html_artifact":       (True,               "public-edge"),
    "dns_zone":            (True,               "platform-foundation"),
    "tls_certificate":     (False,              "platform-foundation"),
    "event_schedule":      (False,              "internal-tooling"),
    "iam_role":            (False,              "identity-secrets"),
    "iam_policy":          (False,              "identity-secrets"),
    "audit_log_trail":     (False,              "security-tooling"),
    "log_group":           (False,              "security-tooling"),
    "external_service":    (False,              "internal-tooling"),
    "api_gateway":         (True,               "public-edge"),
    "secrets_manager":     (False,              "identity-secrets"),
    "kms_key":             (False,              "identity-secrets"),
    "identity_provider":   (True,               "identity-secrets"),
}

# Per-RESOURCE overrides keyed by (component type, Terraform resource name).
# Keying on type as well as name matters: many resources share a tf_name (the
# Silk Reeling Lambda, API, Cognito pool, authorizer are all "silk_reeling"), so
# a name-only key would bleed one resource's override onto its siblings. These
# adjust only the non-derived axes (reachability, archetype) for asset-level
# exceptions a type default cannot express; they mirror exactly what real
# per-resource AWS tags will carry (PR-D). data_sensitivity / mission_criticality
# are never overridden here — they derive from the categorization, by design.
CLASSIFICATION_OVERRIDES = {
    # The public Silk Reeling app Lambda is reachable through its API Gateway;
    # the internal compliance Lambda (opa_compliance) is EventBridge-only and
    # stays not-reachable. Both are stated explicitly so neither relies on the
    # "function" type default by accident.
    ("function", "silk_reeling"):  {"internet_reachable": True},
    ("function", "opa_compliance"): {"internet_reachable": False, "archetype": "security-tooling"},
    # The log bucket is security-tooling by role, unlike the site bucket which
    # serves public content under the object_store default.
    ("object_store", "logs"): {"archetype": "security-tooling"},
}

# Conservative fail-safe for an untagged/unknown-type resource: assume the worst
# so it scores loudly and surfaces for classification (never lowers risk).
CLASSIFICATION_FAILSAFE = {
    "data_sensitivity": "cui",
    "mission_criticality": "high",
    "internet_reachable": True,
    "archetype": "unclassified",
}


def apply_classification_defaults(component):
    """Stamp the governed classification tags onto component.attributes.

    data_sensitivity and mission_criticality are derived from the component's
    FIPS-199 security_category (set by apply_mas_defaults) so they cannot drift.
    internet_reachable and archetype come from the per-type baseline, then any
    per-resource override keyed by attributes.tf_name. An unknown type resolves
    to the conservative fail-safe. agency_scope and owner are system-wide
    constants today. Lives under attributes (free-form by schema) — no schema
    change needed.
    """
    component.setdefault("attributes", {})
    base = CLASSIFICATION_DEFAULTS.get(component["type"])
    if base is None:
        classification = dict(CLASSIFICATION_FAILSAFE)
    else:
        cat = component.get("security_category") or {}
        conf = cat.get("confidentiality", "not-applicable")
        integ = _CAT_ORDINAL.get(cat.get("integrity", "not-applicable"), 0)
        avail = _CAT_ORDINAL.get(cat.get("availability", "not-applicable"), 0)
        internet_reachable, archetype = base
        classification = {
            "data_sensitivity": _CONF_TO_SENSITIVITY.get(conf, "cui"),
            "mission_criticality": _ORDINAL_TO_CRITICALITY[max(integ, avail)],
            "internet_reachable": internet_reachable,
            "archetype": archetype,
        }
        override = CLASSIFICATION_OVERRIDES.get(
            (component["type"], component["attributes"].get("tf_name")))
        if override:
            classification.update(override)
    # Hardwired for this system: single operator, no agency data (m == 0).
    classification["agency_scope"] = "single"
    classification["owner"] = OPERATOR_ROLE
    component["attributes"]["classification"] = classification


# =============================================================================
# HELPERS
# =============================================================================


def run_terraform(args):
    """Run a terraform subcommand and return parsed JSON, or None on failure."""
    try:
        result = subprocess.run(
            ["terraform", *args],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"warning: terraform {' '.join(args)} failed: {exc}", file=sys.stderr)
        return None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def component_id_for_cloud(tf_resource_name, normalized_type):
    return f"{CSP}::{normalized_type}::{tf_resource_name}"


def component_id_for_npm(name, version):
    return f"npm::{name}@{version}"


def npm_purl(name, version):
    """Build a canonical npm PURL per the package-url spec.

    A scoped package puts the scope in the namespace with the leading "@"
    percent-encoded, e.g. pkg:npm/%40smithy/is-array-buffer@2.2.0. This is what
    Syft, Trivy, and other tooling emit, so two tools naming the same package
    produce bit-identical PURLs and join cleanly. Emitting an unencoded "@"
    (pkg:npm/@smithy/...) is non-canonical and breaks that join.
    """
    if name.startswith("@") and "/" in name:
        scope, pkg = name.split("/", 1)
        return f"pkg:npm/{scope.replace('@', '%40')}/{pkg}@{version}"
    return f"pkg:npm/{name}@{version}"


def component_id_for_sbom(ecosystem, name, version):
    # Mirror component_id_for_npm's "<ecosystem>::<name>@<version>" shape, but
    # key on the purl's ecosystem (pypi, npm, ...) so PyPI and npm components
    # ingested from a CycloneDX SBOM stay addressable and don't collide.
    return f"{ecosystem}::{name}@{version}"


def purl_ecosystem(purl):
    """Return the ecosystem segment of a PURL, e.g. 'pypi' from 'pkg:pypi/numpy@1.0'.

    Returns None for anything that isn't a well-formed 'pkg:<ecosystem>/...' PURL.
    """
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    rest = purl[len("pkg:"):]
    eco = rest.split("/", 1)[0].strip()
    return eco or None


def component_id_for_html(rel_path):
    return f"html::{rel_path}"


# =============================================================================
# COMPONENT BUILDERS
# =============================================================================


def build_cloud_components(tf_state, tf_outputs):
    """Walk Terraform state into normalized cloud components.

    Resources with their own slot in the schema's type enum become components.
    Resources in ATTRIBUTE_PARENTS get folded into the parent's attributes so
    a portfolio consumer sees one bucket with encryption/versioning/etc., not
    five separate things to reconcile.
    """
    components_by_id = {}
    state_resources = []

    if tf_state and "values" in tf_state:
        root = tf_state["values"].get("root_module", {})
        state_resources = root.get("resources", [])
        # Recurse into child modules if any exist (this repo has none today).
        for child in root.get("child_modules", []) or []:
            state_resources.extend(child.get("resources", []))

    # First pass: create the primary components.
    for r in state_resources:
        tf_type = r.get("type")
        tf_name = r.get("name")
        if tf_type not in TYPE_BY_TF_TYPE:
            continue
        normalized = TYPE_BY_TF_TYPE[tf_type]
        cid = component_id_for_cloud(tf_name, normalized)
        values = r.get("values", {}) or {}

        attrs = {
            "tf_address": r.get("address"),
            "tf_type": tf_type,
            "tf_name": tf_name,
        }
        # Pull a few common, non-sensitive identifying attributes if present.
        for key in ("region", "runtime", "function_name", "id", "domain_name"):
            if key in values and values[key] is not None:
                attrs[key] = values[key]

        # Per-resource ARN first: each resource's identity comes from its OWN
        # state block (values["arn"]), never from a shared whole-stack output —
        # two Lambdas in the same state would otherwise both receive the single
        # `lambda_function_arn` output and collide on native_id. The output is
        # only a fallback when the state block carries no ARN, and conditional
        # outputs can hold sentinel strings ("Not created"), so anything that
        # does not look like an ARN is rejected outright.
        def _output_arn(name):
            v = (tf_outputs or {}).get(name, {}).get("value")
            return v if isinstance(v, str) and v.startswith("arn:") else None

        native_id = None
        if normalized == "object_store":
            native_id = values.get("arn") or _output_arn("s3_bucket_arn")
        elif normalized == "cdn_distribution":
            native_id = values.get("arn") or _output_arn("cloudfront_distribution_arn")
        elif normalized == "function":
            native_id = values.get("arn") or _output_arn("lambda_function_arn")
        elif normalized == "dns_zone":
            native_id = values.get("arn") or values.get("zone_id") or values.get("id")
        elif normalized == "iam_policy":
            # Managed policies (aws_iam_policy) carry their own ARN. Inline
            # policies (aws_iam_role_policy) do not — synthesize an ID from the
            # role-name plus policy-name pair so the component is addressable.
            if values.get("arn"):
                native_id = values["arn"]
            else:
                role_name = values.get("role") or values.get("role_name") or "unknown"
                policy_name = values.get("name") or "inline"
                native_id = f"iam-role-policy::{role_name}/{policy_name}"
        else:
            # Generic path for tls_certificate, event_schedule, iam_role,
            # audit_log_trail, log_group: most carry an `arn` attribute.
            native_id = values.get("arn") or values.get("id")

        # Sensitive-content hashing: IAM policy bodies are NOT included in the
        # canonical inventory directly; only their SHA-256 hash. The full body
        # is reviewable in infrastructure/main.tf for anyone with repo access.
        # Same treatment for IAM role trust policies.
        if normalized == "iam_role":
            trust_policy = values.get("assume_role_policy")
            if trust_policy is not None:
                body_str = trust_policy if isinstance(trust_policy, str) else json.dumps(trust_policy, sort_keys=True)
                attrs["trust_policy_sha256"] = hashlib.sha256(body_str.encode()).hexdigest()
            attrs["role_name"] = values.get("name")
        if normalized == "iam_policy":
            policy_body = values.get("policy")
            if policy_body is not None:
                body_str = policy_body if isinstance(policy_body, str) else json.dumps(policy_body, sort_keys=True)
                attrs["policy_document_sha256"] = hashlib.sha256(body_str.encode()).hexdigest()
            attrs["policy_name"] = values.get("name")
            attrs["attached_to_role"] = values.get("role") or values.get("role_name")

        component = {
            "component_id": cid,
            "type": normalized,
            "resource_type": CFN_TYPE_BY_NORMALIZED.get(normalized),
            "attributes": attrs,
        }
        if native_id:
            component["native_id"] = native_id
        apply_mas_defaults(component)
        apply_iiw_defaults(component)
        apply_classification_defaults(component)
        components_by_id[cid] = component

    # Second pass: fold attribute resources into their parent.
    for r in state_resources:
        tf_type = r.get("type")
        if tf_type not in ATTRIBUTE_PARENTS:
            continue
        parent_type = ATTRIBUTE_PARENTS[tf_type]
        # Find the matching parent. For this single-system site, name-matching
        # the bucket reference / distribution reference is sufficient; in a
        # larger system the parent reference would need explicit traversal.
        for cid, comp in components_by_id.items():
            if comp["type"] != parent_type:
                continue
            short_attr_key = tf_type.replace(f"aws_{parent_type.split('_')[0]}_", "")
            comp.setdefault("attributes", {}).setdefault("config", {})[short_attr_key] = (
                r.get("values", {})
            )
            break

    return list(components_by_id.values())


def build_bootstrap_components(bootstrap_dir="bootstrap"):
    """Inventory the CI/CD identity plane defined in infrastructure/bootstrap.

    The bootstrap module (GitHub OIDC provider, deploy + assessment roles, the
    operators IAM group, and their policies) lives in a SEPARATE Terraform state
    from the application module. These are the highest-privilege identities
    governing the production system, so they belong in the canonical inventory.

    Best-effort: reads the bootstrap state via `terraform -chdir=<dir> show
    -json` and reuses the same normalization as the application module. No-ops
    (returns []) when the bootstrap state is not available locally — the same
    bootstrap-before-state-backend chicken-and-egg the SBOM loaders tolerate —
    so a developer run without bootstrap access still produces a valid signal,
    while CI (which has the state) inventories them."""
    state = run_terraform([f"-chdir={bootstrap_dir}", "show", "-json"])
    if not state:
        print(f"info: no bootstrap state at {bootstrap_dir}/; CI/CD identity-plane "
              f"components not added this run", file=sys.stderr)
        return []
    comps = build_cloud_components(state, {})
    for c in comps:
        c.setdefault("attributes", {})["tf_module"] = "bootstrap"
    print(f"info: inventoried {len(comps)} bootstrap (CI/CD identity plane) components",
          file=sys.stderr)
    return comps


# System name prefix: in-boundary AWS resources are named with it. Keep in sync
# with SYSTEM_PREFIX in scripts/reconcile.py (the gate enumerates the same set).
SYSTEM_PREFIX = "samaydlette"


def build_live_log_groups(existing_components, region="us-east-2"):
    """Source in-boundary CloudWatch log groups from LIVE account state and emit
    any not already represented from Terraform.

    Lambda execution log groups are auto-created by the service, so they are not
    in Terraform state and the state walk misses them (e.g. the compliance
    Lambda's group). Deriving them from live state is what makes the inventory
    actually complete — and what the reconciliation gate's live deny-by-default
    check (invariant a) requires. No-ops gracefully when the AWS CLI is
    unavailable (local builds); CI runs with the deploy role's logs:Describe*.
    """
    try:
        out = subprocess.run(
            ["aws", "logs", "describe-log-groups", "--region", region, "--output", "json"],
            capture_output=True, text=True,
        )
        if out.returncode != 0:
            print(f"warning: live log-group enumeration skipped: {out.stderr.strip()}", file=sys.stderr)
            return []
        groups = (json.loads(out.stdout or "{}")).get("logGroups", [])
    except (OSError, json.JSONDecodeError) as exc:
        print(f"warning: live log-group enumeration skipped: {exc}", file=sys.stderr)
        return []

    have = {(c.get("native_id") or "").rstrip(":*") for c in existing_components}
    new = []
    for lg in groups:
        name = lg.get("logGroupName", "")
        if SYSTEM_PREFIX not in name.lower():
            continue
        native_id = (lg.get("arn") or "").rstrip(":*")
        if not native_id or native_id in have:
            continue
        short = name.rsplit("/", 1)[-1]
        if short.startswith(f"{SYSTEM_PREFIX}-com-"):
            short = short[len(f"{SYSTEM_PREFIX}-com-"):]
        cid = component_id_for_cloud(short.replace("-", "_"), "log_group")
        component = {
            "component_id": cid,
            "type": "log_group",
            "resource_type": CFN_TYPE_BY_NORMALIZED["log_group"],
            "native_id": native_id,
            "attributes": {
                "log_group_name": name,
                "retention_in_days": lg.get("retentionInDays"),
                "kms_key_id": lg.get("kmsKeyId"),
                "source": "live-describe",
            },
        }
        apply_mas_defaults(component)
        apply_iiw_defaults(component)
        apply_classification_defaults(component)
        new.append(component)
        have.add(native_id)
    return new


def build_npm_components(lock_path):
    """Read package-lock.json (lockfileVersion 3) and emit npm components."""
    if not lock_path.exists():
        return []
    try:
        lock = json.loads(lock_path.read_text())
    except json.JSONDecodeError:
        print(f"warning: could not parse {lock_path}", file=sys.stderr)
        return []
    components = []
    seen = set()
    for path, info in (lock.get("packages") or {}).items():
        if path == "":
            # The root package is the Lambda itself, not a dependency.
            continue
        # The package name is the FINAL node_modules segment. A nested dependency
        # lives at ".../node_modules/<scope>/<name>", so split on the LAST
        # "node_modules/" (rsplit), not the first — otherwise the parent path
        # leaks into the name and the PURL is malformed.
        name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
        version = info.get("version")
        if not name or not version:
            continue
        purl = npm_purl(name, version)
        if purl in seen:
            # The same package@version can be hoisted into several nesting paths;
            # the canonical inventory holds one component per unique PURL.
            continue
        seen.add(purl)
        component = {
            "component_id": component_id_for_npm(name, version),
            "type": "npm_package",
            "global_id": {"purl": purl},
            "attributes": {
                "name": name,
                "version": version,
                "lockfile_path": path,
                "integrity": info.get("integrity"),
            },
        }
        apply_mas_defaults(component)
        apply_iiw_defaults(component)
        apply_classification_defaults(component)
        components.append(component)
    return components


def build_sbom_components(sbom_path, existing_components=None):
    """Read a CycloneDX JSON SBOM and emit software components for the inventory.

    Used to ingest the Silk Reeling app's dependency trees — the Python (PyPI)
    Lambda deps (sbom-python.json) and the SPA's npm deps (sbom-js.json) — which
    the deploy workflow's Syft SCA step writes as CycloneDX into the same
    working directory this script runs from. Using the already-resolved SBOM as
    the source of truth means we don't re-resolve dependency trees here.

    Graceful like the other loaders: returns [] when the path is missing, empty,
    or not valid JSON, so this is a no-op when the Silk Reeling app wasn't built.

    Type choice: each component is typed by its PURL ecosystem -- 'pkg:pypi/...'
    becomes 'pypi_package', 'pkg:npm/...' becomes 'npm_package' -- and the IIW
    asset-type and function attributes are derived from the ecosystem and the
    source SBOM, so a PyPI dependency is not mislabeled as an npm package and an
    SPA dependency is not mislabeled as a Lambda runtime dependency. The ecosystem
    is also preserved in attributes.ecosystem and the PURL.

    De-duplicates by PURL against components already in `existing_components`
    (so the compliance Lambda's npm packages aren't double-counted on overlap)
    and against earlier entries in this same SBOM.
    """
    if not sbom_path.exists():
        return []
    raw = sbom_path.read_text()
    if not raw.strip():
        return []
    try:
        sbom = json.loads(raw)
    except json.JSONDecodeError:
        print(f"warning: could not parse {sbom_path}", file=sys.stderr)
        return []

    seen_purls = set()
    for c in (existing_components or []):
        purl = (c.get("global_id") or {}).get("purl")
        if purl:
            seen_purls.add(purl)

    components = []
    for entry in (sbom.get("components") or []):
        purl = entry.get("purl")
        if not purl:
            # CycloneDX entries without a PURL aren't addressable software
            # packages (e.g. file/operating-system components); skip them.
            continue
        if purl in seen_purls:
            continue
        seen_purls.add(purl)
        name = entry.get("name")
        version = entry.get("version")
        ecosystem = purl_ecosystem(purl) or "unknown"
        # Type by the PURL's actual ecosystem, and derive role-aware IIW facts so
        # the FedRAMP IIW (Appendix M) reports each package's real ecosystem and
        # role: an SPA npm dependency, a Silk Reeling PyPI dependency, and the
        # compliance-Lambda npm dependency must not read identically. These are
        # set before apply_iiw_defaults, which only fills missing keys.
        if ecosystem == "pypi":
            ptype, asset_type = "pypi_package", "Software Package (PyPI)"
            role = "Dependency of the Silk Reeling application Lambda (PyPI)"
        elif ecosystem == "npm":
            ptype, asset_type = "npm_package", "Software Package (npm)"
            role = "Dependency of the Silk Reeling single-page application (npm)"
        else:
            ptype, asset_type = "npm_package", f"Software Package ({ecosystem})"
            role = f"Dependency of the Silk Reeling application ({ecosystem})"
        component = {
            "component_id": component_id_for_sbom(ecosystem, name, version),
            "type": ptype,
            "global_id": {"purl": purl},
            "attributes": {
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
                "sbom_source": sbom_path.name,
                "iiw_asset_type": asset_type,
                "function": role,
            },
        }
        apply_mas_defaults(component)
        apply_iiw_defaults(component)
        apply_classification_defaults(component)
        components.append(component)
    return components


def build_external_components():
    """Emit synthetic components for external services in boundary per ROT #2.

    These services aren't in Terraform state (they're upstream public services
    or operator-account scaffolding); they're declared here so the canonical
    inventory matches the Authorization Boundary Diagram. Identifiers are the
    public service URLs where applicable; for Duo specifically the identifier
    is opaque (no tenant ID exposed).
    """
    services = [
        {
            "id": "ext::sigstore-fulcio",
            "native_id": "https://fulcio.sigstore.dev",
            "name": "Sigstore Fulcio",
            "purpose": "Issues short-lived X.509 signing certificates per CI run",
            "cia_impact": "signing-chain integrity",
            "verification": "OIDC token bound to GitHub Actions workflow identity",
            "fedramp_status": "external; no separate FedRAMP authorization",
        },
        {
            "id": "ext::sigstore-rekor",
            "native_id": "https://rekor.sigstore.dev",
            "name": "Sigstore Rekor",
            "purpose": "Append-only public transparency log of every signature",
            "cia_impact": "signing-chain integrity",
            "verification": "Inclusion proof checked by cosign verify-blob",
            "fedramp_status": "external; no separate FedRAMP authorization",
        },
        {
            "id": "ext::github-oidc",
            "native_id": "https://token.actions.githubusercontent.com",
            "name": "GitHub Actions OIDC token issuer",
            "purpose": "Issues per-workflow-run identity tokens consumed by Fulcio and AWS",
            "cia_impact": "identity / authentication",
            "verification": "JWT signature verification against the issuer's public JWKS",
            "fedramp_status": "external; no separate FedRAMP authorization",
        },
        {
            "id": "ext::github-repo",
            "native_id": "https://github.com/sam-aydlette/samaydlette.com",
            "name": "GitHub repository + Actions",
            "purpose": "Source of record; CI/CD orchestrator",
            "cia_impact": "deploy-chain integrity",
            "verification": "Branch protection on main, OPA gate, SCN tag validator, secret scanning with push protection",
            "fedramp_status": "external; no separate FedRAMP authorization",
        },
        {
            "id": "ext::duo-mfa",
            "native_id": "duo:operator-mfa",
            "name": "Duo (operator MFA)",
            "purpose": "Multi-factor authentication for AWS root and the GitHub account",
            "cia_impact": "privileged-account authentication",
            "verification": "Operator-side configuration; tenant identifier intentionally not published in this inventory.",
            "fedramp_status": "external; no separate FedRAMP authorization",
        },
        {
            "id": "ext::github-advisory-db",
            "native_id": "https://github.com/advisories",
            "name": "GitHub Advisory Database",
            "purpose": "Upstream vulnerability data for Dependabot",
            "cia_impact": "VDR ingest accuracy",
            "verification": "Public service; corroborated against CISA KEV",
            "fedramp_status": "external; no separate FedRAMP authorization",
        },
        {
            "id": "ext::cisa-kev",
            "native_id": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "name": "CISA Known Exploited Vulnerabilities catalog",
            "purpose": "Authoritative list of CVEs known to be actively exploited",
            "cia_impact": "VDR ingest accuracy",
            "verification": "U.S. federal government source",
            "fedramp_status": "external; U.S. federal government source",
        },
    ]
    components = []
    for svc in services:
        component = {
            "component_id": svc["id"],
            "type": "external_service",
            "native_id": svc["native_id"],
            "attributes": {
                "name": svc["name"],
                "purpose": svc["purpose"],
                "cia_impact": svc["cia_impact"],
                "verification_mechanism": svc["verification"],
                "fedramp_status": svc["fedramp_status"],
            },
        }
        apply_mas_defaults(component)
        apply_iiw_defaults(component)
        apply_classification_defaults(component)
        components.append(component)
    return components


def build_html_components(website_root):
    """Hash every HTML file under the website/ tree as an html_artifact."""
    if not website_root.is_dir():
        return []
    components = []
    for html_path in sorted(website_root.rglob("*.html")):
        rel = html_path.relative_to(website_root).as_posix()
        digest = sha256_file(html_path)
        component = {
            "component_id": component_id_for_html(rel),
            "type": "html_artifact",
            "global_id": {"sha256": digest},
            "attributes": {
                "path": rel,
                "size_bytes": html_path.stat().st_size,
            },
        }
        apply_mas_defaults(component)
        apply_iiw_defaults(component)
        apply_classification_defaults(component)
        components.append(component)
    return components


# =============================================================================
# VALIDATION JOINER
# =============================================================================


def build_validations(validations_doc, components):
    """Convert OPA results into schema-conformant validations[].

    Each result names the components it evaluated via component_refs. That join
    field is the entire point of the article-27 proposal: the validation result
    is no longer a per-system black box but composes across CSPs because every
    consumer can match on component_refs.
    """
    component_ids = {c["component_id"] for c in components}
    by_html_path = {
        c["attributes"]["path"]: c["component_id"]
        for c in components
        if c["type"] == "html_artifact"
    }
    by_cloud_name = {}
    for c in components:
        if c["type"] in {"object_store", "cdn_distribution", "function"}:
            tf_name = c.get("attributes", {}).get("tf_name")
            if tf_name:
                by_cloud_name[(c["type"], tf_name)] = c["component_id"]

    validations = []
    skipped = 0
    for idx, result in enumerate(validations_doc.get("results") or []):
        kind = result.get("kind")
        compliant = result.get("compliant")
        violations = result.get("violations") or []
        policy_version = result.get("policy_version") or "unknown"
        refs = []

        if kind == "infrastructure":
            tf_type = result.get("resource_type")
            tf_name = result.get("resource_name")
            normalized = TYPE_BY_TF_TYPE.get(tf_type)
            if normalized:
                cid = by_cloud_name.get((normalized, tf_name))
                if cid:
                    refs = [cid]
            # Resources outside the schema's component vocabulary (IAM, log
            # groups, attribute-only resources) are intentionally skipped.
            if not refs:
                skipped += 1
                continue
        elif kind == "accessibility":
            file_path = result.get("file_path") or ""
            # file_path is relative to the directory terraform-plan.sh ran in
            # (infrastructure/), pointing at ../website/<rel>. Normalize.
            normalized_path = file_path.split("website/", 1)[-1] if "website/" in file_path else file_path
            cid = by_html_path.get(normalized_path)
            if cid:
                refs = [cid]
            if not refs:
                skipped += 1
                continue
        else:
            skipped += 1
            continue

        # Sanity: refs must exist in this signal's components.
        refs = [r for r in refs if r in component_ids]
        if not refs:
            skipped += 1
            continue

        # result is derived from violations, not from the OPA `compliant` flag
        # alone: a "pass" with a non-empty violations[] is internally
        # contradictory (the schema documents violations as findings "when
        # result is 'fail'"). If the policy reported any violation for the
        # referenced components, the validation fails regardless of how
        # `compliant` was computed upstream. This makes the signal fail-safe
        # against an OPA/terraform-plan.sh mismatch rather than masking it.
        result = "pass" if (compliant and not violations) else "fail"
        validations.append({
            "validation_id": f"v-{idx:04d}",
            "policy": {
                "id": "terraform.compliance",
                "version": policy_version,
            },
            "result": result,
            "component_refs": refs,
            "violations": violations,
        })

    if skipped:
        print(f"info: skipped {skipped} OPA results that did not map to schema component types", file=sys.stderr)
    return validations


# KSI family (the middle token of KSI-XXX-YYY) → the inventory component types
# whose policy validations evidence that family's indicators. A consistent,
# catalog-derived rule for all in-scope KSIs (assessment Task 4): a KSI's status
# is the aggregate of the terraform.compliance validations covering the
# components in its family's domain. `None` means the whole inventory (policy &
# inventory KSIs); the empty set means no component evidence (documentation-only
# families such as cybersecurity education).
KSI_FAMILY_EVIDENCE_TYPES = {
    "CED": set(),  # education/training — evidenced by docs, not components
    "CMT": {"function", "object_store", "cdn_distribution"},
    "CNA": {"object_store", "cdn_distribution", "function", "api_gateway",
            "dns_zone", "tls_certificate", "secrets_manager", "identity_provider", "kms_key"},
    "IAM": {"iam_role", "iam_policy", "iam_group", "oidc_provider", "identity_provider", "secrets_manager"},
    "INR": {"log_group", "function"},
    "MLA": {"log_group", "function", "cdn_distribution"},
    "PIY": None,  # policy & inventory — whole inventory is the evidence
    "RPL": {"object_store"},
    "SCR": {"npm_package", "pypi_package", "external_service"},
    "SVC": {"object_store", "cdn_distribution", "function", "kms_key",
            "tls_certificate", "api_gateway", "secrets_manager", "event_schedule"},
}


def build_ksi_statuses(catalog, components, validations):
    """Emit a per-KSI status block for every in-scope (Moderate) indicator in
    the catalog, so a consumer can trace each KSI the SSP names to a live
    pass/fail backed by the validations and components that evidence it.

    Status is derived consistently from the catalog's KSI→family domain: a KSI
    is `fail` if any terraform.compliance validation over a component in its
    family's domain failed, else `pass`. `method` records how it was evidenced
    (policy-validation / inventory-attestation / documentation)."""
    by_type = {}
    for c in components:
        by_type.setdefault(c.get("type"), []).append(c.get("component_id"))
    all_ids = [c.get("component_id") for c in components]

    ksis = []
    for family_code, family in sorted((catalog.get("KSI") or {}).items()):
        evidence_types = KSI_FAMILY_EVIDENCE_TYPES.get(family_code, None)
        for ind in family.get("indicators", []) or []:
            if not (ind.get("impact") or {}).get("moderate"):
                continue  # out of scope for a Moderate system
            if evidence_types is None:
                comp_refs = list(all_ids)
            else:
                comp_refs = [cid for t in evidence_types for cid in by_type.get(t, [])]
            comp_set = set(comp_refs)
            rel_validations = [v for v in validations
                               if comp_set & set(v.get("component_refs") or [])]
            failed = [v["validation_id"] for v in rel_validations if v.get("result") == "fail"]
            if rel_validations:
                method = "policy-validation"
                status = "fail" if failed else "pass"
            elif comp_refs:
                method = "inventory-attestation"  # in inventory, no policy check fires for the domain
                status = "pass"
            else:
                method = "documentation"  # doc/training-based family (no component evidence)
                status = "pass"
            ksis.append({
                "id": ind["id"],
                "name": ind.get("name"),
                "family": family_code,
                "status": status,
                "impact": "moderate",
                "method": method,
                "controls": [c.get("control_id") for c in ind.get("controls", []) or []],
                "evidence": {
                    "validation_ids": [v["validation_id"] for v in rel_validations],
                    "failed_validation_ids": failed,
                    "component_refs": comp_refs,
                },
            })
    return ksis


# =============================================================================
# PROVENANCE
# =============================================================================


def build_provenance():
    """Read GITHUB_* env vars when running in Actions; fall back to local."""
    repo = os.environ.get("GITHUB_REPOSITORY")
    # GITHUB_WORKFLOW_REF is the fully-qualified workflow reference
    # (OWNER/REPO/.github/workflows/FILE@REF) and is exactly the Fulcio
    # certificate SAN. GITHUB_WORKFLOW (the display name, with spaces) is NOT a
    # valid SAN, so builder.id must be built from WORKFLOW_REF.
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF")
    run_id = os.environ.get("GITHUB_RUN_ID")
    sha = os.environ.get("GITHUB_SHA")
    ref = os.environ.get("GITHUB_REF")

    if repo and workflow_ref and sha:
        builder_id = f"https://github.com/{workflow_ref}"
        provenance = {
            "builder": {
                "id": builder_id,
                "run_id": run_id or "unknown",
                "version": "github-actions",
            },
            "source": {
                "repository": f"https://github.com/{repo}",
                "commit": sha,
                "ref": ref or "unknown",
            },
        }
        # When the CI deploy is going to sign this signal, pre-populate the
        # attestation reference *before* signing so the cosign signature
        # covers it. The bundle itself is published as a sidecar at this URL.
        # KSI_SIGN=1 is set by the CI step that runs cosign sign-blob; absent
        # locally so unsigned signals don't claim a bundle they don't have.
        if os.environ.get("KSI_SIGN") == "1":
            provenance["attestation"] = {
                "format": "sigstore-bundle",
                "url": "https://samaydlette.com/.well-known/ksi-signal.bundle",
                "verification": {
                    "tool": "cosign",
                    # Exact identity pin (no workflow wildcard): the bundle must be
                    # signed by THIS workflow at THIS ref, equal to builder.id. A
                    # `.+` here would accept a signature from any workflow in the repo.
                    "certificate_identity": builder_id,
                    "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
                },
            }
        return provenance

    # Local fallback. Try git for the commit; the rest is best-effort.
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        commit = "0000000"
    return {
        "builder": {
            "id": "local",
            "run_id": "local",
            "version": "local",
        },
        "source": {
            "repository": "https://github.com/sam-aydlette/samaydlette.com",
            "commit": commit,
            "ref": "local",
        },
    }


# =============================================================================
# MAIN
# =============================================================================


def main():
    cwd = Path.cwd()
    repo_root = cwd.parent
    website_root = repo_root / "website"
    lambda_lock = cwd / "lambda" / "package-lock.json"
    # CycloneDX SBOMs written by the deploy workflow's Syft SCA step (run from
    # this same infrastructure/ directory) for the Silk Reeling app's dependency
    # trees. Absent when that app wasn't built — build_sbom_components no-ops.
    sbom_python = cwd / "sbom-python.json"
    sbom_js = cwd / "sbom-js.json"
    validations_path = cwd / "validations.json"
    schema_id = "https://samaydlette.com/.well-known/ksi-signal.schema.json"
    output_path = cwd / "ksi-signal.json"

    # Single source of truth for system categorization (assessment F-2 /
    # Decision 1). Every generator reads impact_level from here; the
    # reconciliation gate fails closed if the artifacts ever disagree.
    system_profile = json.loads((repo_root / "data" / "system-profile.json").read_text())

    tf_outputs = run_terraform(["output", "-json"]) or {}
    tf_state = run_terraform(["show", "-json"]) or {}

    components = []
    components.extend(build_cloud_components(tf_state, tf_outputs))
    # CI/CD identity plane (bootstrap module, separate Terraform state): the
    # GitHub OIDC provider, deploy/assessment roles, and operators group. These
    # govern the production system and are inventoried, not excused (their
    # weaknesses are tracked as POAM-026/027). Best-effort: no-ops if the
    # bootstrap state isn't reachable from this run (CI has it).
    components.extend(build_bootstrap_components())
    # Supplement the Terraform-state walk with live-only in-boundary resources
    # (Lambda auto-creates execution log groups outside Terraform state). The
    # reconciliation gate's live completeness check enforces nothing else is
    # missed.
    components.extend(build_live_log_groups(components))
    components.extend(build_npm_components(lambda_lock))
    # Ingest the Silk Reeling app's resolved dependency trees from the Syft
    # CycloneDX SBOMs so the canonical inventory covers its Python (PyPI) and
    # SPA (npm) packages, not just the compliance Lambda's npm packages. Each
    # call dedupes by PURL against components already collected.
    components.extend(build_sbom_components(sbom_python, components))
    components.extend(build_sbom_components(sbom_js, components))
    components.extend(build_html_components(website_root))
    components.extend(build_external_components())

    # Final safety net: dedupe by PURL across the whole list so no software
    # component is double-counted regardless of which loader produced it.
    deduped = []
    seen_purls = set()
    for c in components:
        purl = (c.get("global_id") or {}).get("purl")
        if purl is not None:
            if purl in seen_purls:
                continue
            seen_purls.add(purl)
        deduped.append(c)
    components = deduped

    if validations_path.exists():
        validations_doc = json.loads(validations_path.read_text())
    else:
        print(f"warning: {validations_path} not found; emitting empty validations[]", file=sys.stderr)
        validations_doc = {"results": []}

    validations = build_validations(validations_doc, components)

    # Per-KSI status block: maps every in-scope FedRAMP 20x KSI to a live
    # pass/fail with the validations + components that evidence it, so the SSP's
    # named KSIs are machine-traceable to results in this signal (assessment
    # Task 4 — the SSP↔signal linkage gap).
    catalog_path = repo_root / "infrastructure" / "schemas" / "ksi-catalog.json"
    ksis = []
    if catalog_path.exists():
        catalog = json.loads(catalog_path.read_text())
        ksis = build_ksi_statuses(catalog, components, validations)
    else:
        print(f"warning: {catalog_path} not found; emitting empty ksis[]", file=sys.stderr)

    signal = {
        "$schema": schema_id,
        "signal_version": SIGNAL_VERSION,
        "signal_id": str(uuid.uuid4()),
        "emitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "emitter": "deploy",
        "csp": CSP,
        "system_id": SYSTEM_ID,
        "categorization": {
            "impact_level": system_profile["impact_level"],
            "fedramp_class": system_profile["fedramp_class"],
            "impact_level_canonical": system_profile["impact_level_canonical"],
            "fips_199": system_profile["fips_199"],
        },
        "provenance": build_provenance(),
        "components": components,
        "validations": validations,
        "ksis": ksis,
        "ownership": {
            "system_owner": "Sam Aydlette",
            "application_owner": "Sam Aydlette",
            "operator_contact": "sam.aydlette@gmail.com",
        },
        "disclosure": {
            "authorization_status": "self-attested-proof-of-concept",
            "fedramp_certified": False,
            "remarks": (
                "This system is not FedRAMP-certified. The artifacts published "
                "at /.well-known/ are self-attested by the operator and "
                "demonstrate an architectural pattern aligned with FedRAMP "
                "NTC-0009 (machine-readable authorization data, text-based "
                "equivalents, the five Balance Improvement Releases folding "
                "into default requirements). See "
                "https://samaydlette.com/research/the-plumbing.html for "
                "context and limitations."
            ),
            "related_artifacts": {
                "oscal_ssp": "https://samaydlette.com/.well-known/oscal-ssp.json",
                "oscal_poam": "https://samaydlette.com/.well-known/oscal-poam.json",
                "vdr_report": "https://samaydlette.com/.well-known/vdr-report.json",
                "iiw_csv": "https://samaydlette.com/.well-known/iiw.csv",
                "runtime_signal": "https://samaydlette.com/.well-known/ksi-signal-runtime.json",
                "boundary_diagram": "https://samaydlette.com/research/authorization-boundary.html",
                "research_paper": "https://samaydlette.com/research/the-plumbing.html",
            },
        },
    }

    output_path.write_text(json.dumps(signal, indent=2) + "\n")
    print(
        f"Wrote {output_path} "
        f"({len(components)} components, {len(validations)} validations, {len(ksis)} KSIs)"
    )


if __name__ == "__main__":
    main()
