# =============================================================================
# TERRAFORM CONFIGURATION: Website Infrastructure with OPA Compliance
# =============================================================================
# This file sets up AWS infrastructure for a static website with security
# compliance monitoring.
#
# What this creates:
# - References existing S3 bucket and CloudFront distribution
# - Adds security settings to existing resources
# - Creates a Lambda function to monitor compliance
# - Sets up automated compliance checking
# =============================================================================

# =============================================================================
# SECURITY-SCAN SUPPRESSIONS
# =============================================================================
# Checkov suppressions live in .checkov.yaml at the repo root. Top-of-file
# inline annotations are not honored by Checkov; centralized configuration
# is the supported path.
#
# tfsec exclusions live in .tfsec/config.yml at the repo root.
#
# Each suppression is tracked as a Risk-Accepted POA&M entry in
# docs/poam.md (POAM-003 through POAM-018) with full rationale.
# =============================================================================

# =============================================================================
# TERRAFORM REQUIREMENTS
# =============================================================================
# Specify which version of Terraform and which cloud providers to use
# =============================================================================
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

# =============================================================================
# AWS CONNECTION SETUP
# =============================================================================
# Tell Terraform how to connect to AWS in different regions
# =============================================================================

# =============================================================================
# Resource-level classification tags (docs/policies/resource-tagging-standard.md)
# =============================================================================
# Every taggable resource carries the six governed classification axes. The two
# system-wide constant axes (AgencyScope, OwnerRole) are applied to every
# resource via provider default_tags; the four varying axes are applied
# per-resource from local.cls below, matching the inventory's derived
# classification so the reconciliation gate (PR-D Part 2) can assert live tags ==
# inventory. The build-time OPA completeness rule (policies.rego) fails the build
# if any taggable resource is missing a classification key, so a new resource
# cannot ship unclassified. AgencyScope is hardwired single (single operator, no
# agency data); OwnerRole is a role label, never a personal identifier.
locals {
  classification_constant = {
    AgencyScope = "single"
    OwnerRole   = "platform-operator"
  }

  # Per-resource varying axes (data_sensitivity / mission_criticality /
  # internet_reachable / archetype). Keyed by a profile that mirrors a component's
  # derived classification in the canonical inventory.
  cls = {
    # KMS keys: low-confidentiality (public) control-plane key material.
    identity_secrets_public = { DataSensitivity = "public", MissionCriticality = "moderate", InternetReachable = "false", Archetype = "identity-secrets" }
    # IAM roles, Secrets Manager: moderate-confidentiality (internal) credentials.
    identity_secrets_internal = { DataSensitivity = "internal", MissionCriticality = "moderate", InternetReachable = "false", Archetype = "identity-secrets" }
    # Log groups, the log bucket, the internal compliance Lambda.
    security_tooling = { DataSensitivity = "public", MissionCriticality = "moderate", InternetReachable = "false", Archetype = "security-tooling" }
    # The compliance DLQ (not an inventory component; classified for completeness).
    security_tooling_internal = { DataSensitivity = "internal", MissionCriticality = "moderate", InternetReachable = "false", Archetype = "security-tooling" }
    # The public Silk Reeling app Lambda.
    app_tier = { DataSensitivity = "public", MissionCriticality = "moderate", InternetReachable = "true", Archetype = "app-tier" }
    # The public API Gateway (and its stage).
    public_edge = { DataSensitivity = "public", MissionCriticality = "moderate", InternetReachable = "true", Archetype = "public-edge" }
    # The daily EventBridge schedule.
    internal_tooling_low = { DataSensitivity = "public", MissionCriticality = "low", InternetReachable = "false", Archetype = "internal-tooling" }
    # The Cognito user pool: identity provider, reachable, holds credentials.
    identity_provider = { DataSensitivity = "internal", MissionCriticality = "moderate", InternetReachable = "true", Archetype = "identity-secrets" }
  }
}

# Main AWS connection for most resources
provider "aws" {
  region = var.aws_region
  default_tags {
    tags = local.classification_constant
  }
}

# Special connection for SSL certificates (they must be in us-east-1 for CloudFront)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  default_tags {
    tags = local.classification_constant
  }
}

# =============================================================================
# FIND EXISTING AWS RESOURCES
# =============================================================================
# These sections locate my existing AWS resources that were created manually,
# so Terraform can work with them without breaking anything
# =============================================================================

# Find my existing S3 bucket that holds the website files
data "aws_s3_bucket" "website" {
  bucket = var.domain_name
}

# Find my existing CloudFront distribution that serves the website
data "aws_cloudfront_distribution" "website" {
  id = var.existing_cloudfront_distribution_id
}

# Find my existing Route53 hosted zone for DNS (if you manage DNS)
data "aws_route53_zone" "website" {
  count = var.manage_dns ? 1 : 0
  name  = var.domain_name
}

# Find my existing SSL certificate for HTTPS
data "aws_acm_certificate" "website" {
  provider    = aws.us_east_1
  domain      = var.domain_name
  statuses    = ["ISSUED"]
  most_recent = true
}

# =============================================================================
# SECURE YOUR EXISTING S3 BUCKET
# =============================================================================
# Add security features to my existing S3 bucket without breaking it
# =============================================================================

# Turn on file versioning so you can recover deleted or changed files
resource "aws_s3_bucket_versioning" "website" {
  bucket = data.aws_s3_bucket.website.id

  versioning_configuration {
    status = "Enabled"
  }

  lifecycle {
    prevent_destroy = true # Don't accidentally delete this setting
  }
}

# Encrypt files stored in my S3 bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "website" {
  bucket = data.aws_s3_bucket.website.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # Use AWS's free encryption
    }
  }

  lifecycle {
    prevent_destroy = true # Don't accidentally remove encryption
  }
}

# Block public access to prevent accidental exposure
resource "aws_s3_bucket_public_access_block" "website" {
  bucket = data.aws_s3_bucket.website.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  lifecycle {
    prevent_destroy = true # Keep security settings safe
  }
}

# Lifecycle hygiene for the versioned website bucket (POAM-006, SI-12): clean up
# incomplete multipart uploads and old non-current versions so storage can't grow
# unbounded. Current object versions (the live site) are never expired.
resource "aws_s3_bucket_lifecycle_configuration" "website" {
  bucket = data.aws_s3_bucket.website.id

  rule {
    id     = "hygiene"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
    noncurrent_version_expiration { noncurrent_days = 90 }
  }
}

# =============================================================================
# CLOUDFRONT RESPONSE HEADERS POLICY
# =============================================================================
# Defines the security headers (HSTS, CSP, etc.) the CDN attaches to every
# response. The CloudFront distribution itself is managed outside of Terraform
# (referenced as a data source above), so this policy is created here and must
# then be attached to the distribution's default cache behavior — see the
# `cloudfront_response_headers_policy_id` output for the manual attach step.
#
# CSP note: script-src is strict 'self' — no third-party script origins and no
# inline scripts. KaTeX (math rendering on the eigenvalue research paper) is now
# self-hosted under /assets/vendor/katex/ instead of cdn.jsdelivr.net, and its
# init call lives in /assets/vendor/katex/katex-init.js rather than an inline
# onload handler, so no CDN or inline-script allowance is needed (SA-9 / KSI-3IR:
# removes a third-party supply-chain vector). style-src retains 'unsafe-inline'
# because KaTeX injects inline style="" attributes at render time for math layout;
# this is materially lower-risk than inline scripts and is the documented residual.
# media-src allows the operator's own podcast audio (ochelli.com) and frame-src
# allows embedded YouTube videos — the only remaining external origins, neither of
# which can execute script in this origin.
# =============================================================================
resource "aws_cloudfront_response_headers_policy" "website" {
  count = var.create_response_headers_policy ? 1 : 0

  name    = "${replace(var.domain_name, ".", "-")}-security-headers"
  comment = "Baseline security headers for ${var.domain_name}"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    content_security_policy {
      content_security_policy = join("; ", [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "media-src 'self' https://ochelli.com",
        "frame-src https://www.youtube.com https://www.youtube-nocookie.com",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
      ])
      override = true
    }

    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
  }
}

# Set up permissions so only CloudFront can access my S3 bucket
resource "aws_s3_bucket_policy" "website" {
  bucket     = data.aws_s3_bucket.website.id
  depends_on = [aws_s3_bucket_public_access_block.website]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipal"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${data.aws_s3_bucket.website.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = data.aws_cloudfront_distribution.website.arn
          }
        }
      },
      # Deny any request not made over TLS (SC-8 / SC-13; Prowler
      # s3_bucket_secure_transport_policy). Preventive guardrail, not detective.
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          data.aws_s3_bucket.website.arn,
          "${data.aws_s3_bucket.website.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}

# =============================================================================
# SET UP DNS MONITORING (OPTIONAL)
# =============================================================================
# These resources monitor my DNS queries if you want that information. These resources are only created if you enable DNS logging.
# =============================================================================

# Create a place to store DNS query logs
resource "aws_cloudwatch_log_group" "route53_query_log" {
  count             = var.manage_dns && var.enable_route53_logging ? 1 : 0
  name              = "/aws/route53/${var.domain_name}"
  retention_in_days = 365                     # 1-year retention (AU-11, POAM-017)
  kms_key_id        = aws_kms_key.at_rest.arn # customer-CMK at rest (POAM-018)

  tags = merge(local.cls.security_tooling, {
    Name               = "${var.domain_name}-route53-logs"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Public"
    Owner              = var.owner
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Actually start logging DNS queries
resource "aws_route53_query_log" "website" {
  count                    = var.manage_dns && var.enable_route53_logging ? 1 : 0
  depends_on               = [aws_cloudwatch_log_group.route53_query_log]
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.route53_query_log[0].arn
  zone_id                  = data.aws_route53_zone.website[0].zone_id
}

# =============================================================================
# PREPARE COMPLIANCE MONITORING FUNCTION
# =============================================================================
# Get the deployment package ready for the Lambda function
# =============================================================================

# Find the zip file containing the monitoring function code
data "local_file" "lambda_zip" {
  filename = "./opa-compliance.zip"
}

# =============================================================================
# CREATE PERMISSIONS FOR MONITORING FUNCTION
# =============================================================================
# Set up AWS permissions so the Lambda function can do its job
# =============================================================================

# Create a role that defines what the monitoring function is allowed to do
resource "aws_iam_role" "lambda_opa" {
  name = "${replace(var.domain_name, ".", "-")}-lambda-opa-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.cls.identity_secrets_internal, {
    Name               = "${var.domain_name}-lambda-opa-role"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  })
}

# Define the specific permissions the monitoring function needs
resource "aws_iam_role_policy" "lambda_opa" {
  name = "${replace(var.domain_name, ".", "-")}-lambda-opa-policy"
  role = aws_iam_role.lambda_opa.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:*:log-group:/aws/lambda/${replace(var.domain_name, ".", "-")}-opa-compliance:*"
      },
      {
        # Decrypt the Lambda's customer-CMK-encrypted environment variables
        # (POAM-011). kms:Decrypt only — the function never encrypts.
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [aws_kms_key.at_rest.arn]
      },
      {
        # Sign the runtime KSI signal and read the public key for publication
        # (POAM-002). Scoped to the asymmetric signing key only.
        Effect   = "Allow"
        Action   = ["kms:Sign", "kms:GetPublicKey"]
        Resource = [aws_kms_key.runtime_signing.arn]
      },
      {
        # Send failed async invocations to the dead-letter queue (POAM-013).
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = [aws_sqs_queue.compliance_dlq[0].arn]
      },
      {
        # Minimum read access the runtime KSI emitter needs to build the
        # {resource: {...}} input that policies.rego (compiled to Wasm)
        # evaluates. The actions match the bucket-attribute checks the Rego
        # rules look for: encryption, versioning, public-access-block, and
        # required tags. ListBucket is intentionally absent; the Lambda
        # enumerates nothing.
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetBucketVersioning",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketTagging"
        ]
        Resource = [
          data.aws_s3_bucket.website.arn,
          "${data.aws_s3_bucket.website.arn}/*"
        ]
      },
      {
        # The emitter re-validates every object_store component in the
        # canonical inventory, so it needs the same bucket-attribute reads on
        # the access-log bucket. Bucket-level configuration metadata only —
        # deliberately no s3:GetObject here, so the Lambda can never read the
        # access logs themselves.
        Effect = "Allow"
        Action = [
          "s3:GetBucketVersioning",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketTagging"
        ]
        Resource = [
          aws_s3_bucket.logs.arn
        ]
      },
      {
        # The runtime KSI emitter publishes its signal and signing public key back
        # to /.well-known/ on the same bucket. Scoped to exactly those two keys so
        # the Lambda cannot overwrite arbitrary site content.
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = [
          "${data.aws_s3_bucket.website.arn}/.well-known/ksi-signal-runtime.json",
          "${data.aws_s3_bucket.website.arn}/.well-known/runtime-signing-pubkey.pem"
        ]
      },
      {
        # Read-only config inspection of the one CloudFront distribution this
        # site uses. CloudFront supports resource-level permissions for these
        # specific Get* actions on a distribution ARN, so the Lambda cannot
        # read other distributions in the account.
        Effect = "Allow"
        Action = [
          "cloudfront:GetDistributionConfig",
          "cloudfront:GetDistribution"
        ]
        Resource = data.aws_cloudfront_distribution.website.arn
      },
      ],
      # SC-12 manual-rotation verification: the runtime emitter reads the app
      # secret's LastChangedDate to confirm it is within the annual rotation
      # cadence. DescribeSecret returns metadata only — no GetSecretValue, no
      # kms:Decrypt — so the monitor can never read the credential itself.
      # Scoped to exactly the Anthropic secret, and only when the app exists.
      var.create_silk_reeling ? [
        {
          Effect   = "Allow"
          Action   = ["secretsmanager:DescribeSecret"]
          Resource = [aws_secretsmanager_secret.silk_anthropic[0].arn]
        }
    ] : [])
  })
}

# =============================================================================
# CREATE COMPLIANCE MONITORING FUNCTION
# =============================================================================
# This function runs daily to check if my infrastructure is still secure
# =============================================================================

# Create the actual monitoring function
# =============================================================================
# AT-REST ENCRYPTION CMK (POAM-011 / POAM-018)
# =============================================================================
# Customer-managed key for the compliance Lambda's environment variables and
# its CloudWatch log group. The public website bucket stays on SSE-S3 (AES-256):
# verified it holds only public content — pose extraction is client-side and the
# app persists nothing, so there is no sensitive data at rest there; the only
# sensitive at-rest data (the two app secrets) is already on the silk-reeling
# CMK. ~$1/month; bucket-key not needed (no S3 KMS here).
resource "aws_kms_key" "at_rest" {
  description             = "Customer-managed key for at-rest encryption of the compliance Lambda env vars and logs"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          ArnLike = {
            # Scope the logs-service grant to exactly the two CMK-encrypted log
            # groups that use this key (compliance Lambda + route53 query logs).
            "kms:EncryptionContext:aws:logs:arn" = [
              "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${replace(var.domain_name, ".", "-")}-opa-compliance",
              "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/route53/${var.domain_name}",
            ]
          }
        }
      },
    ]
  })

  tags = merge(local.cls.identity_secrets_public, {
    Name               = "${var.domain_name}-at-rest"
    Environment        = var.environment
    DataClassification = "Internal"
    Owner              = var.owner
  })
}

resource "aws_kms_alias" "at_rest" {
  name          = "alias/${replace(var.domain_name, ".", "-")}-at-rest"
  target_key_id = aws_kms_key.at_rest.key_id
}

# Asymmetric signing key for the runtime KSI signal (POAM-002). The Lambda signs
# the canonical signal bytes so a consumer can verify the runtime signal against
# the published public key instead of trusting the well-known URL. ECC NIST P-256
# / SIGN_VERIFY; asymmetric keys do not support automatic rotation (rotation is a
# manual new-key + re-publish-pubkey operation, recorded as a residual in
# docs/poam.md). Key policy is root-enabled / IAM-governed; the Lambda role holds
# kms:Sign + kms:GetPublicKey (above).
resource "aws_kms_key" "runtime_signing" {
  description              = "Asymmetric key for signing the runtime KSI signal (POAM-002)"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
    ]
  })

  tags = merge(local.cls.identity_secrets_public, {
    Name               = "${var.domain_name}-runtime-signing"
    Environment        = var.environment
    DataClassification = "Internal"
    Owner              = var.owner
  })
}

resource "aws_kms_alias" "runtime_signing" {
  name          = "alias/${replace(var.domain_name, ".", "-")}-runtime-signing"
  target_key_id = aws_kms_key.runtime_signing.key_id
}

# =============================================================================
# DNSSEC (D-3)
# =============================================================================
# Signs the hosted zone so resolvers can authenticate DNS answers for the domain.
# Route 53 DNSSEC requires the key-signing key (KSK) to be a customer-managed
# asymmetric ECC_NIST_P256 key IN us-east-1, with a key policy that lets the
# Route 53 DNSSEC service use it. Enabling zone signing is safe without the parent
# DS record (validators treat the zone as unsigned until the DS is published); the
# DS record is emitted as an output and published at the registrar as a separate,
# operator-gated step. All gated on manage_dns.
resource "aws_kms_key" "dnssec_ksk" {
  count                    = var.manage_dns ? 1 : 0
  provider                 = aws.us_east_1
  description              = "DNSSEC key-signing key for ${var.domain_name} (D-3)"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowRoute53DNSSECService"
        Effect    = "Allow"
        Principal = { Service = "dnssec-route53.amazonaws.com" }
        Action    = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"]
        Resource  = "*"
      },
      {
        Sid       = "AllowRoute53DNSSECCreateGrant"
        Effect    = "Allow"
        Principal = { Service = "dnssec-route53.amazonaws.com" }
        Action    = "kms:CreateGrant"
        Resource  = "*"
        Condition = { Bool = { "kms:GrantIsForAWSResource" = "true" } }
      },
    ]
  })

  tags = merge(local.cls.identity_secrets_public, {
    Name               = "${var.domain_name}-dnssec-ksk"
    Environment        = var.environment
    DataClassification = "Internal"
    Owner              = var.owner
  })
}

resource "aws_kms_alias" "dnssec_ksk" {
  count         = var.manage_dns ? 1 : 0
  provider      = aws.us_east_1
  name          = "alias/${replace(var.domain_name, ".", "-")}-dnssec-ksk"
  target_key_id = aws_kms_key.dnssec_ksk[0].key_id
}

resource "aws_route53_key_signing_key" "this" {
  count                      = var.manage_dns ? 1 : 0
  hosted_zone_id             = data.aws_route53_zone.website[0].zone_id
  key_management_service_arn = aws_kms_key.dnssec_ksk[0].arn
  name                       = "${replace(var.domain_name, ".", "_")}_ksk"
  status                     = "ACTIVE"
}

# Turns on zone signing (ServeSignature = SIGNING). Safe without a parent DS
# record. To DISABLE later, remove the DS at the registrar first, wait the TTL,
# then disable signing — otherwise resolvers that cached the DS will fail.
resource "aws_route53_hosted_zone_dnssec" "this" {
  count          = var.manage_dns ? 1 : 0
  hosted_zone_id = data.aws_route53_zone.website[0].zone_id
  depends_on     = [aws_route53_key_signing_key.this]
}

# Explicit, customer-CMK-encrypted log group for the compliance Lambda (POAM-018)
# with an explicit Moderate retention. Lambda would otherwise auto-create this
# group unencrypted; it already exists, so the deploy imports it before apply.
resource "aws_cloudwatch_log_group" "opa_compliance" {
  count             = var.create_lambda_compliance ? 1 : 0
  name              = "/aws/lambda/${replace(var.domain_name, ".", "-")}-opa-compliance"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.at_rest.arn

  tags = merge(local.cls.security_tooling, {
    Name               = "${var.domain_name}-opa-compliance-logs"
    Environment        = var.environment
    DataClassification = "Internal"
    Owner              = var.owner
  })
}

# Dead-letter queue for the compliance Lambda's failed async invocations
# (POAM-013, SI-4). SSE-SQS managed encryption; 14-day retention so a failed
# daily run is retained for inspection.
resource "aws_sqs_queue" "compliance_dlq" {
  count                     = var.create_lambda_compliance ? 1 : 0
  name                      = "${replace(var.domain_name, ".", "-")}-opa-compliance-dlq"
  message_retention_seconds = 1209600 # 14 days
  sqs_managed_sse_enabled   = true

  tags = merge(local.cls.security_tooling_internal, {
    Name               = "${var.domain_name}-opa-compliance-dlq"
    Environment        = var.environment
    DataClassification = "Internal"
    Owner              = var.owner
  })
}

resource "aws_lambda_function" "opa_compliance" {
  count = var.create_lambda_compliance ? 1 : 0

  filename         = "./opa-compliance.zip"
  function_name    = "${replace(var.domain_name, ".", "-")}-opa-compliance"
  role             = aws_iam_role.lambda_opa.arn
  handler          = "index.handler"
  runtime          = "nodejs22.x"
  timeout          = 60
  source_code_hash = data.local_file.lambda_zip.content_base64sha256

  # Customer-CMK encryption of the environment variables (POAM-011).
  kms_key_arn = aws_kms_key.at_rest.arn

  # Dead-letter queue for failed async (EventBridge) invocations (POAM-013, SI-4):
  # a failed daily run is captured for inspection instead of being silently lost.
  dead_letter_config {
    target_arn = aws_sqs_queue.compliance_dlq[0].arn
  }

  # The deploy role's kms:Encrypt grant is scoped by alias, so the alias must
  # exist before this function's env is encrypted (otherwise a from-scratch
  # apply could race the Lambda update ahead of alias creation).
  depends_on = [aws_cloudwatch_log_group.opa_compliance, aws_kms_alias.at_rest]

  environment {
    variables = {
      # The runtime emitter derives the signing-key alias from S3_BUCKET
      # (alias/<domain-with-dashes>-runtime-signing); no separate key env var is
      # injected. The kms:Sign / kms:GetPublicKey grant on the role is scoped to
      # aws_kms_key.runtime_signing and authorizes use via that alias.
      S3_BUCKET = data.aws_s3_bucket.website.id
    }
  }

  tags = merge(local.cls.security_tooling, {
    Name               = "${var.domain_name}-opa-compliance"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  })
}

# =============================================================================
# SET UP AUTOMATIC COMPLIANCE CHECKING
# =============================================================================
# Schedule the monitoring function to run regularly
# =============================================================================

# Create a schedule that triggers compliance checks
resource "aws_cloudwatch_event_rule" "opa_compliance" {
  count = var.create_eventbridge_rules ? 1 : 0

  name                = "${replace(var.domain_name, ".", "-")}-opa-compliance"
  description         = "Trigger OPA compliance checks"
  schedule_expression = var.compliance_check_schedule

  tags = merge(local.cls.internal_tooling_low, {
    Name               = "${var.domain_name}-opa-compliance"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  })
}

# Connect the schedule to the monitoring function
resource "aws_cloudwatch_event_target" "lambda" {
  count = var.create_eventbridge_rules && var.create_lambda_compliance ? 1 : 0

  rule      = aws_cloudwatch_event_rule.opa_compliance[0].name
  target_id = "TriggerLambdaTarget"
  arn       = aws_lambda_function.opa_compliance[0].arn
}

# Give the schedule permission to run the monitoring function
resource "aws_lambda_permission" "allow_eventbridge" {
  count = var.create_eventbridge_rules && var.create_lambda_compliance ? 1 : 0

  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.opa_compliance[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.opa_compliance[0].arn
}