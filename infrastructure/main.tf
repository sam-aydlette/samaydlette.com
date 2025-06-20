# main.tf - Terraform configuration for existing website with OPA compliance
# This configuration manages existing resources safely and adds new compliance functionality
# Suppress unnecessary/expensive checks for static website hosting
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

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Primary provider for main resources (us-east-2)
provider "aws" {
  region = var.aws_region
}

# Secondary provider for SSL certificates (required to be us-east-1 for CloudFront)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

# DATA SOURCES FOR EXISTING RESOURCES
# =================================

# Reference existing S3 bucket
data "aws_s3_bucket" "website" {
  bucket = var.domain_name
}

# Reference existing CloudFront distribution
data "aws_cloudfront_distribution" "website" {
  id = var.existing_cloudfront_distribution_id
}

# Reference existing Route53 hosted zone
data "aws_route53_zone" "website" {
  count = var.manage_dns ? 1 : 0
  name  = var.domain_name
}

# Reference existing SSL certificate
data "aws_acm_certificate" "website" {
  provider = aws.us_east_1
  domain   = var.domain_name
  statuses = ["ISSUED"]
}

# MANAGED RESOURCES (will be created/managed)
# ==========================================

# S3 bucket versioning - safe to manage on existing bucket
resource "aws_s3_bucket_versioning" "website" {
  bucket = data.aws_s3_bucket.website.id
  
  versioning_configuration {
    status = "Enabled"
  }

  lifecycle {
    # Prevent destruction if versioning is already enabled
    prevent_destroy = true
  }
}

# S3 bucket encryption - safe to manage on existing bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "website" {
  bucket = data.aws_s3_bucket.website.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }

  lifecycle {
    # Prevent destruction of encryption configuration
    prevent_destroy = true
  }
}

# S3 bucket public access block - safe to manage on existing bucket
resource "aws_s3_bucket_public_access_block" "website" {
  bucket = data.aws_s3_bucket.website.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  lifecycle {
    # Prevent destruction of security settings
    prevent_destroy = true
  }
}

# S3 bucket policy - manage policy on existing bucket
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

# CloudWatch Log Group for Route53 query logging - NEW RESOURCE
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
    # Only create if it doesn't exist
    create_before_destroy = true
  }
}

# Route53 query logging configuration - NEW RESOURCE
resource "aws_route53_query_log" "website" {
  count                    = var.manage_dns && var.enable_route53_logging ? 1 : 0
  depends_on              = [aws_cloudwatch_log_group.route53_query_log]
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.route53_query_log[0].arn
  zone_id                 = data.aws_route53_zone.website[0].zone_id
}

# Check if Lambda function already exists
data "aws_lambda_function" "existing_opa_compliance" {
  function_name = "${replace(var.domain_name, ".", "-")}-opa-compliance"
  
  # This will fail if function doesn't exist, which is what we want
  lifecycle {
    postcondition {
      condition     = self.function_name != null
      error_message = "Lambda function does not exist yet."
    }
  }
}

# Lambda function for OPA compliance checking - CREATE ONLY IF NOT EXISTS
resource "aws_lambda_function" "opa_compliance" {
  count = try(data.aws_lambda_function.existing_opa_compliance.function_name, null) == null ? 1 : 0
  
  filename      = "opa-compliance.zip"
  function_name = "${replace(var.domain_name, ".", "-")}-opa-compliance"
  role         = aws_iam_role.lambda_opa[0].arn
  handler      = "index.handler"
  runtime      = "nodejs18.x"
  timeout      = 60

  depends_on = [data.archive_file.opa_lambda_zip]

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

  lifecycle {
    create_before_destroy = true
  }
}

# Create zip file for Lambda function
data "archive_file" "opa_lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/opa-compliance.zip"
}

# Check if IAM role already exists
data "aws_iam_role" "existing_lambda_opa" {
  name = "${replace(var.domain_name, ".", "-")}-lambda-opa-role"
  
  lifecycle {
    postcondition {
      condition     = self.name != null
      error_message = "IAM role does not exist yet."
    }
  }
}

# IAM role for Lambda function - CREATE ONLY IF NOT EXISTS
resource "aws_iam_role" "lambda_opa" {
  count = try(data.aws_iam_role.existing_lambda_opa.name, null) == null ? 1 : 0
  
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

  lifecycle {
    create_before_destroy = true
  }
}

# IAM policy for Lambda function - ALWAYS MANAGE (policies can be updated)
resource "aws_iam_role_policy" "lambda_opa" {
  name = "${replace(var.domain_name, ".", "-")}-lambda-opa-policy"
  role = try(data.aws_iam_role.existing_lambda_opa.name, aws_iam_role.lambda_opa[0].id)

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
      }
    ]
  })
}

# Check if EventBridge rule already exists
data "aws_cloudwatch_event_rule" "existing_opa_compliance" {
  name = "${replace(var.domain_name, ".", "-")}-opa-compliance"
  
  lifecycle {
    postcondition {
      condition     = self.name != null
      error_message = "EventBridge rule does not exist yet."
    }
  }
}

# EventBridge rule to trigger compliance checks - CREATE ONLY IF NOT EXISTS
resource "aws_cloudwatch_event_rule" "opa_compliance" {
  count = try(data.aws_cloudwatch_event_rule.existing_opa_compliance.name, null) == null ? 1 : 0
  
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

  lifecycle {
    create_before_destroy = true
  }
}

# EventBridge target - MANAGE ONLY IF RULE EXISTS/IS CREATED
resource "aws_cloudwatch_event_target" "lambda" {
  count = try(data.aws_cloudwatch_event_rule.existing_opa_compliance.name, null) != null || length(aws_cloudwatch_event_rule.opa_compliance) > 0 ? 1 : 0
  
  rule      = try(data.aws_cloudwatch_event_rule.existing_opa_compliance.name, aws_cloudwatch_event_rule.opa_compliance[0].name)
  target_id = "TriggerLambdaTarget"
  arn       = try(data.aws_lambda_function.existing_opa_compliance.arn, aws_lambda_function.opa_compliance[0].arn)
}

# Lambda permission for EventBridge - MANAGE ONLY IF LAMBDA EXISTS/IS CREATED
resource "aws_lambda_permission" "allow_eventbridge" {
  count = try(data.aws_lambda_function.existing_opa_compliance.function_name, null) != null || length(aws_lambda_function.opa_compliance) > 0 ? 1 : 0
  
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = try(data.aws_lambda_function.existing_opa_compliance.function_name, aws_lambda_function.opa_compliance[0].function_name)
  principal     = "events.amazonaws.com"
  source_arn    = try(data.aws_cloudwatch_event_rule.existing_opa_compliance.arn, aws_cloudwatch_event_rule.opa_compliance[0].arn)
}