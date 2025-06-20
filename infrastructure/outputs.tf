# outputs.tf - Outputs for existing infrastructure with new compliance features

# EXISTING RESOURCE OUTPUTS
# =========================

output "s3_bucket_name" {
  description = "Name of the existing S3 bucket"
  value       = data.aws_s3_bucket.website.id
}

output "s3_bucket_arn" {
  description = "ARN of the existing S3 bucket"
  value       = data.aws_s3_bucket.website.arn
}

output "cloudfront_distribution_id" {
  description = "ID of the existing CloudFront distribution"
  value       = data.aws_cloudfront_distribution.website.id
}

output "cloudfront_distribution_arn" {
  description = "ARN of the existing CloudFront distribution"
  value       = data.aws_cloudfront_distribution.website.arn
}

output "cloudfront_domain_name" {
  description = "Domain name of the existing CloudFront distribution"
  value       = data.aws_cloudfront_distribution.website.domain_name
}

output "route53_zone_id" {
  description = "Route53 hosted zone ID"
  value       = var.manage_dns ? data.aws_route53_zone.website[0].zone_id : "Not managed by Terraform"
}

output "route53_name_servers" {
  description = "Route53 name servers (if managing DNS)"
  value       = var.manage_dns ? data.aws_route53_zone.website[0].name_servers : []
}

output "ssl_certificate_arn" {
  description = "ARN of the existing SSL certificate"
  value       = data.aws_acm_certificate.website.arn
}

# NEW RESOURCE OUTPUTS
# ====================

output "lambda_function_name" {
  description = "Name of the OPA compliance Lambda function"
  value       = try(data.aws_lambda_function.existing_opa_compliance.function_name, aws_lambda_function.opa_compliance[0].function_name, "Not created")
}

output "lambda_function_arn" {
  description = "ARN of the OPA compliance Lambda function"
  value       = try(data.aws_lambda_function.existing_opa_compliance.arn, aws_lambda_function.opa_compliance[0].arn, "Not created")
}

output "iam_role_name" {
  description = "Name of the Lambda IAM role"
  value       = try(data.aws_iam_role.existing_lambda_opa.name, aws_iam_role.lambda_opa[0].name, "Not created")
}

output "iam_role_arn" {
  description = "ARN of the Lambda IAM role"
  value       = try(data.aws_iam_role.existing_lambda_opa.arn, aws_iam_role.lambda_opa[0].arn, "Not created")
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge compliance rule"
  value       = try(data.aws_cloudwatch_event_rule.existing_opa_compliance.name, aws_cloudwatch_event_rule.opa_compliance[0].name, "Not created")
}

output "route53_logging_enabled" {
  description = "Whether Route53 query logging is enabled"
  value       = var.manage_dns && var.enable_route53_logging
}

# WEBSITE ACCESS URLS
# ===================

output "website_urls" {
  description = "Website URLs"
  value = {
    cloudfront = "https://${data.aws_cloudfront_distribution.website.domain_name}"
    domain     = "https://${var.domain_name}"
    www_domain = "https://www.${var.domain_name}"
  }
}

# INFRASTRUCTURE STATUS
# =====================

output "infrastructure_status" {
  description = "Status of managed vs existing resources"
  value = {
    existing_resources = {
      s3_bucket            = "Referenced (existing)"
      cloudfront          = "Referenced (existing)"
      route53_zone        = var.manage_dns ? "Referenced (existing)" : "Not managed"
      ssl_certificate     = "Referenced (existing)"
    }
    managed_resources = {
      lambda_function     = try(data.aws_lambda_function.existing_opa_compliance.function_name, null) != null ? "Referenced (existing)" : length(aws_lambda_function.opa_compliance) > 0 ? "Created by Terraform" : "Not created"
      iam_role           = try(data.aws_iam_role.existing_lambda_opa.name, null) != null ? "Referenced (existing)" : length(aws_iam_role.lambda_opa) > 0 ? "Created by Terraform" : "Not created"
      eventbridge_rule   = try(data.aws_cloudwatch_event_rule.existing_opa_compliance.name, null) != null ? "Referenced (existing)" : length(aws_cloudwatch_event_rule.opa_compliance) > 0 ? "Created by Terraform" : "Not created"
      s3_bucket_policy   = "Managed by Terraform"
      s3_encryption      = "Managed by Terraform"
      s3_versioning      = "Managed by Terraform"
    }
  }
}

output "aws_region" {
  description = "AWS region where resources are deployed"
  value       = var.aws_region
}

output "compliance_features" {
  description = "Status of compliance features"
  value = {
    opa_lambda_enabled    = var.create_lambda_compliance
    eventbridge_enabled   = var.create_eventbridge_rules
    route53_logging       = var.enable_route53_logging
    compliance_schedule   = var.compliance_check_schedule
    section_508_level     = var.section_508_compliance_level
  }
}