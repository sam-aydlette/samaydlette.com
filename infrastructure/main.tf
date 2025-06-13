# main.tf - Complete Terraform configuration for existing website with OPA compliance
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
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# S3 bucket public access block - ALLOW public access for website hosting
resource "aws_s3_bucket_public_access_block" "website" {
  bucket = aws_s3_bucket.website.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# S3 bucket policy for public website access
resource "aws_s3_bucket_policy" "website" {
  bucket = aws_s3_bucket.website.id
  depends_on = [aws_s3_bucket_public_access_block.website]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.website.arn}/*"
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

# CloudFront distribution - EXISTING RESOURCE
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
