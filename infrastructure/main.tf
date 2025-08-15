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
# SKIP EXPENSIVE SECURITY CHECKS FOR STATIC WEBSITES
# =============================================================================
# These comments tell security scanners to skip checks that don't make sense
# for a simple static website, avoiding unnecessary costs and complexity
# =============================================================================
#checkov:skip=CKV_AWS_144:Cross-region replication not cost-effective for static website
#checkov:skip=CKV_AWS_23:S3 event notifications not required for static content
#checkov:skip=CKV_AWS_18:S3 access logging generates additional costs and storage for static site
#checkov:skip=CKV_AWS_300:S3 lifecycle configuration not required for static website assets
#checkov:skip=CKV_AWS_68:CloudFront WAF adds ~$10/month cost, not justified for personal site
#checkov:skip=CKV_AWS_174:Log4j WAF rules not applicable to static HTML/CSS/JS content
#checkov:skip=CKV_AWS_86:CloudFront origin failover not needed for single S3 origin static site
#checkov:skip=CKV_AWS_310:CloudFront response headers policy adds complexity for basic static site
#checkov:skip=CKV_AWS_117:Lambda VPC configuration adds NAT Gateway costs (~$45/month)
#checkov:skip=CKV_AWS_173:Lambda environment encryption not needed for non-sensitive config
#checkov:skip=CKV_AWS_115:Lambda concurrent execution limits not required for low-traffic compliance checks
#checkov:skip=CKV_AWS_116:Lambda DLQ not cost-effective for simple compliance functions
#checkov:skip=CKV_AWS_73:Lambda X-Ray tracing adds costs for minimal benefit on compliance checks
#checkov:skip=CKV_AWS_50:Lambda code signing not required for basic compliance functions

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
# These sections locate your existing AWS resources that were created manually,
# so Terraform can work with them without breaking anything
# =============================================================================

# Find your existing S3 bucket that holds the website files
data "aws_s3_bucket" "website" {
  bucket = var.domain_name
}

# Find your existing CloudFront distribution that serves the website
data "aws_cloudfront_distribution" "website" {
  id = var.existing_cloudfront_distribution_id
}

# Find your existing Route53 hosted zone for DNS (if you manage DNS)
data "aws_route53_zone" "website" {
  count = var.manage_dns ? 1 : 0
  name  = var.domain_name
}

# Find your existing SSL certificate for HTTPS
data "aws_acm_certificate" "website" {
  provider = aws.us_east_1
  domain   = var.domain_name
  statuses = ["ISSUED"]
  most_recent = true
}

# =============================================================================
# SECURE YOUR EXISTING S3 BUCKET
# =============================================================================
# Add security features to your existing S3 bucket without breaking it
# =============================================================================

# Turn on file versioning so you can recover deleted or changed files
resource "aws_s3_bucket_versioning" "website" {
  bucket = data.aws_s3_bucket.website.id
  
  versioning_configuration {
    status = "Enabled"
  }

  lifecycle {
    prevent_destroy = true  # Don't accidentally delete this setting
  }
}

# Encrypt files stored in your S3 bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "website" {
  bucket = data.aws_s3_bucket.website.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"  # Use AWS's free encryption
    }
  }

  lifecycle {
    prevent_destroy = true  # Don't accidentally remove encryption
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
    prevent_destroy = true  # Keep security settings safe
  }
}

# Set up permissions so only CloudFront can access your S3 bucket
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
# These resources monitor your DNS queries if you want that information. These resources are only created if you enable DNS logging.
# =============================================================================

# Create a place to store DNS query logs
resource "aws_cloudwatch_log_group" "route53_query_log" {
  count             = var.manage_dns && var.enable_route53_logging ? 1 : 0
  name              = "/aws/route53/${var.domain_name}"
  retention_in_days = 7

  tags = {
    Name               = "${var.domain_name}-route53-logs"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Public"
    Owner              = var.owner_email
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Actually start logging DNS queries
resource "aws_route53_query_log" "website" {
  count                    = var.manage_dns && var.enable_route53_logging ? 1 : 0
  depends_on              = [aws_cloudwatch_log_group.route53_query_log]
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.route53_query_log[0].arn
  zone_id                 = data.aws_route53_zone.website[0].zone_id
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
    Owner              = var.owner_email
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
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          data.aws_s3_bucket.website.arn,
          "${data.aws_s3_bucket.website.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# CREATE COMPLIANCE MONITORING FUNCTION
# =============================================================================
# This function runs daily to check if your infrastructure is still secure
# =============================================================================

# Create the actual monitoring function
resource "aws_lambda_function" "opa_compliance" {
  count = var.create_lambda_compliance ? 1 : 0
  
  filename        = "./opa-compliance.zip"
  function_name   = "${replace(var.domain_name, ".", "-")}-opa-compliance"
  role            = aws_iam_role.lambda_opa.arn
  handler         = "index.handler"
  runtime         = "nodejs18.x"
  timeout         = 60
  source_code_hash = data.local_file.lambda_zip.content_base64sha256

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
    Owner              = var.owner_email
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
    Owner              = var.owner_email
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