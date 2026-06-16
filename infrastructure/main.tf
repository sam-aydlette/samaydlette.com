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

# Main AWS connection for most resources
provider "aws" {
  region = var.aws_region
}

# Special connection for SSL certificates (they must be in us-east-1 for CloudFront)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
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

# =============================================================================
# CLOUDFRONT RESPONSE HEADERS POLICY
# =============================================================================
# Defines the security headers (HSTS, CSP, etc.) the CDN attaches to every
# response. The CloudFront distribution itself is managed outside of Terraform
# (referenced as a data source above), so this policy is created here and must
# then be attached to the distribution's default cache behavior — see the
# `cloudfront_response_headers_policy_id` output for the manual attach step.
#
# CSP note: 'unsafe-inline' is removed from both script-src and style-src.
# The theme-detection script lives in /assets/js/theme-init.js. Inline
# style="" attributes on the eigenvalue research paper were replaced with
# col-w-* utility classes in articles.css, and the donation page's <style>
# block was moved into /assets/css/support.css. The CSP is now strict-self
# for everything except img-src (which allows data: URIs).
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
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
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
      }
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
  retention_in_days = 7
  kms_key_id        = aws_kms_key.at_rest.arn # customer-CMK at rest (POAM-018)

  tags = {
    Name               = "${var.domain_name}-route53-logs"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Public"
    Owner              = var.owner
  }

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

  tags = {
    Name               = "${var.domain_name}-lambda-opa-role"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  }
}

# Define the specific permissions the monitoring function needs
resource "aws_iam_role_policy" "lambda_opa" {
  name = "${replace(var.domain_name, ".", "-")}-lambda-opa-policy"
  role = aws_iam_role.lambda_opa.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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
        # The runtime KSI emitter publishes its signal back to /.well-known/ on
        # the same bucket. Scoped to that single key prefix so the Lambda
        # cannot overwrite arbitrary site content.
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = [
          "${data.aws_s3_bucket.website.arn}/.well-known/ksi-signal-runtime.json"
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
    ]
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

  tags = {
    Name               = "${var.domain_name}-at-rest"
    Environment        = var.environment
    DataClassification = "Internal"
    Owner              = var.owner
  }
}

resource "aws_kms_alias" "at_rest" {
  name          = "alias/${replace(var.domain_name, ".", "-")}-at-rest"
  target_key_id = aws_kms_key.at_rest.key_id
}

# Explicit, customer-CMK-encrypted log group for the compliance Lambda (POAM-018)
# with an explicit Moderate retention. Lambda would otherwise auto-create this
# group unencrypted; it already exists, so the deploy imports it before apply.
resource "aws_cloudwatch_log_group" "opa_compliance" {
  count             = var.create_lambda_compliance ? 1 : 0
  name              = "/aws/lambda/${replace(var.domain_name, ".", "-")}-opa-compliance"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.at_rest.arn

  tags = {
    Name               = "${var.domain_name}-opa-compliance-logs"
    Environment        = var.environment
    DataClassification = "Internal"
    Owner              = var.owner
  }
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

  # The deploy role's kms:Encrypt grant is scoped by alias, so the alias must
  # exist before this function's env is encrypted (otherwise a from-scratch
  # apply could race the Lambda update ahead of alias creation).
  depends_on = [aws_cloudwatch_log_group.opa_compliance, aws_kms_alias.at_rest]

  environment {
    variables = {
      S3_BUCKET = data.aws_s3_bucket.website.id
    }
  }

  tags = {
    Name               = "${var.domain_name}-opa-compliance"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  }
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

  tags = {
    Name               = "${var.domain_name}-opa-compliance"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  }
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