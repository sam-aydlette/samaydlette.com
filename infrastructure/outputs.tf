# outputs-import.tf - Simplified outputs for import phase

output "s3_bucket_name" {
  description = "Name of the S3 bucket"
  value       = aws_s3_bucket.website.id
}

output "cloudfront_distribution_id" {
  description = "ID of the CloudFront distribution"
  value       = aws_cloudfront_distribution.website.id
}

output "cloudfront_domain_name" {
  description = "Domain name of the CloudFront distribution"
  value       = aws_cloudfront_distribution.website.domain_name
}

output "route53_zone_id" {
  description = "Route53 hosted zone ID"
  value       = var.manage_dns ? aws_route53_zone.website[0].zone_id : "Not managed by Terraform"
}

output "lambda_function_name" {
  description = "Name of the OPA compliance Lambda function"
  value       = aws_lambda_function.opa_compliance.function_name
}

output "ssl_certificate_arn" {
  description = "ARN of the SSL certificate (existing)"
  value       = var.ssl_certificate_arn
}

output "website_urls" {
  description = "Website URLs"
  value = {
    cloudfront = "https://${aws_cloudfront_distribution.website.domain_name}"
    domain     = "https://${var.domain_name}"
    www_domain = "https://www.${var.domain_name}"
  }
}

output "aws_region" {
  description = "AWS region where resources are deployed"
  value       = var.aws_region
}
