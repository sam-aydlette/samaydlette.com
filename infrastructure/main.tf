# main.tf - Complete Terraform configuration for existing website with OPA compliance
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

# S3 bucket for website hosting - EXISTING RESOURCE
resource "aws_s3_bucket" "website" {
  bucket = var.domain_name

  tags = {
    Name                = var.domain_name
    Environment         = var.environment
    CostCenter          = var.cost_center
    DataClassification  = "Public"
    ComplianceScope     = "Section508"
    Owner               = var.owner_email
    AutomationExempt    = "false"
  }
}

# S3 bucket versioning
resource "aws_s3_bucket_versioning" "website" {
  bucket = aws_s3_bucket.website.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "website" {
  bucket = aws_s3_bucket.website.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}

# S3 bucket public access block - FIXED: Block public access and use CloudFront OAC
resource "aws_s3_bucket_public_access_block" "website" {
  bucket = aws_s3_bucket.website.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 bucket policy - FIXED: Restrict to CloudFront OAC only
resource "aws_s3_bucket_policy" "website" {
  bucket = aws_s3_bucket.website.id
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
        Resource = "${aws_s3_bucket.website.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudfront::975050324277:distribution/EV1H3IU8N3K5S"
          }
        }
      }
    ]
  })
}

# S3 bucket website configuration
resource "aws_s3_bucket_website_configuration" "website" {
  bucket = aws_s3_bucket.website.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }
}

# SSL Certificate - Only create if requested
resource "aws_acm_certificate" "website" {
  count    = var.create_certificate ? 1 : 0
  provider = aws.us_east_1
  
  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name                = "${var.domain_name}-certificate"
    Environment         = var.environment
    CostCenter          = var.cost_center
    DataClassification  = "Public"
    Owner               = var.owner_email
  }
}

# Route53 hosted zone - EXISTING RESOURCE (only if managing DNS)
resource "aws_route53_zone" "website" {
  count = var.manage_dns ? 1 : 0
  name  = var.domain_name

  tags = {
    Name                = var.domain_name
    Environment         = var.environment
    CostCenter          = var.cost_center
    DataClassification  = "Public"
    Owner               = var.owner_email
  }
}

# CloudWatch Log Group for Route53 query logging
resource "aws_cloudwatch_log_group" "route53_query_log" {
  count             = var.manage_dns ? 1 : 0
  name              = "/aws/route53/${var.domain_name}"
  retention_in_days = 7  # Short retention to minimize costs

  tags = {
    Name                = "${var.domain_name}-route53-logs"
    Environment         = var.environment
    CostCenter          = var.cost_center
    DataClassification  = "Public"
    Owner               = var.owner_email
  }
}

# Route53 query logging configuration
resource "aws_route53_query_log" "website" {
  count                            = var.manage_dns ? 1 : 0
  depends_on                       = [aws_cloudwatch_log_group.route53_query_log]
  cloudwatch_log_group_arn         = aws_cloudwatch_log_group.route53_query_log[0].arn
  zone_id                          = aws_route53_zone.website[0].zone_id
}

# Route53 DNSSEC key-signing key
resource "aws_route53_key_signing_key" "website" {
  count                      = var.manage_dns ? 1 : 0
  hosted_zone_id             = aws_route53_zone.website[0].id
  key_management_service_arn = aws_kms_key.route53_dnssec[0].arn
  name                       = "dnssec_key"
}

# KMS key for Route53 DNSSEC
resource "aws_kms_key" "route53_dnssec" {
  count                   = var.manage_dns ? 1 : 0
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days = 7
  key_usage               = "SIGN_VERIFY"
  
  tags = {
    Name                = "${var.domain_name}-dnssec-key"
    Environment         = var.environment
    CostCenter          = var.cost_center
    DataClassification  = "Public"
    Owner               = var.owner_email
  }
}

# Enable DNSSEC signing
resource "aws_route53_hosted_zone_dnssec" "website" {
  count      = var.manage_dns ? 1 : 0
  depends_on = [aws_route53_key_signing_key.website]
  hosted_zone_id = aws_route53_key_signing_key.website[0].hosted_zone_id
}

# Route53 records for certificate validation (if managing DNS and creating certificate)  
resource "aws_route53_record" "cert_validation" {
  for_each = var.manage_dns && var.create_certificate ? {
    for dvo in aws_acm_certificate.website[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}
  
  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = aws_route53_zone.website[0].zone_id
}

# Certificate validation
resource "aws_acm_certificate_validation" "website" {
  provider = aws.us_east_1
  count    = var.manage_dns && var.create_certificate ? 1 : 0
  
  certificate_arn         = aws_acm_certificate.website[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]

  timeouts {
    create = "5m"
  }
}

# CloudFront Origin Access Control
resource "aws_cloudfront_origin_access_control" "website" {
  name                              = "${var.domain_name}-oac"
  description                       = "OAC for ${var.domain_name}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# CloudFront distribution - EXISTING RESOURCE with compliance fixes
resource "aws_cloudfront_distribution" "website" {
  aliases = [var.domain_name, "www.${var.domain_name}"]

  origin {
    domain_name              = aws_s3_bucket.website.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.website.id
    origin_id                = "S3-${var.domain_name}"
  }

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  price_class         = var.cloudfront_price_class

  default_cache_behavior {
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${var.domain_name}"
    compress               = true
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # Geo restriction (set to none but structure in place for compliance)
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    # Use existing certificate (since we're not creating a new one)
    acm_certificate_arn      = var.ssl_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  tags = {
    Name                = "${var.domain_name}-cdn"
    Environment         = var.environment
    CostCenter          = var.cost_center
    DataClassification  = "Public"
    ComplianceScope     = "Section508"
    Owner               = var.owner_email
  }
}

# Route53 A record for apex domain
resource "aws_route53_record" "website_apex" {
  count   = var.manage_dns ? 1 : 0
  zone_id = aws_route53_zone.website[0].zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.website.domain_name
    zone_id                = aws_cloudfront_distribution.website.hosted_zone_id
    evaluate_target_health = false
  }
}

# Route53 A record for www subdomain
resource "aws_route53_record" "website_www" {
  count   = var.manage_dns ? 1 : 0
  zone_id = aws_route53_zone.website[0].zone_id
  name    = "www.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.website.domain_name
    zone_id                = aws_cloudfront_distribution.website.hosted_zone_id
    evaluate_target_health = false
  }
}

# Lambda function for OPA compliance checking
resource "aws_lambda_function" "opa_compliance" {
  filename         = "opa-compliance.zip"
  function_name    = "${replace(var.domain_name, ".", "-")}-opa-compliance"
  role            = aws_iam_role.lambda_opa.arn
  handler         = "index.handler"
  runtime         = "nodejs18.x"
  timeout         = 60

  depends_on = [data.archive_file.opa_lambda_zip]

  environment {
    variables = {
      S3_BUCKET = aws_s3_bucket.website.id
    }
  }

  tags = {
    Name                = "${var.domain_name}-opa-compliance"
    Environment         = var.environment
    CostCenter          = var.cost_center
    DataClassification  = "Internal"
    Owner               = var.owner_email
  }
}

# Create zip file for Lambda function
data "archive_file" "opa_lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/opa-compliance.zip"
}

# IAM role for Lambda function
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
    Name                = "${var.domain_name}-lambda-opa-role"
    Environment         = var.environment
    CostCenter          = var.cost_center
    DataClassification  = "Internal"
    Owner               = var.owner_email
  }
}

# IAM policy for Lambda function
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
          aws_s3_bucket.website.arn,
          "${aws_s3_bucket.website.arn}/*"
        ]
      }
    ]
  })
}

# EventBridge rule to trigger compliance checks
resource "aws_cloudwatch_event_rule" "opa_compliance" {
  name                = "${replace(var.domain_name, ".", "-")}-opa-compliance"
  description         = "Trigger OPA compliance checks"
  schedule_expression = var.compliance_check_schedule

  tags = {
    Name                = "${var.domain_name}-opa-compliance"
    Environment         = var.environment
    CostCenter          = var.cost_center
    DataClassification  = "Internal"
    Owner               = var.owner_email
  }
}

# EventBridge target
resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.opa_compliance.name
  target_id = "TriggerLambdaTarget"
  arn       = aws_lambda_function.opa_compliance.arn
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.opa_compliance.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.opa_compliance.arn
}
