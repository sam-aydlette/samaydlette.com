# outputs.tf

output "s3_bucket_name" {
  description = "Name of the S3 bucket"
  value       = aws_s3_bucket.website.id
}

output "s3_bucket_website_endpoint" {
  description = "Website endpoint of the S3 bucket"
  value       = aws_s3_bucket_website_configuration.website.website_endpoint
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
  value       = var.manage_dns ? aws_route53_zone.website[0].zone_id : null
}

output "route53_name_servers" {
  description = "Route53 name servers"
  value       = var.manage_dns ? aws_route53_zone.website[0].name_servers : null
}

output "lambda_function_name" {
  description = "Name of the OPA compliance Lambda function"
  value       = aws_lambda_function.opa_compliance.function_name
}

output "lambda_function_arn" {
  description = "ARN of the OPA compliance Lambda function"
  value       = aws_lambda_function.opa_compliance.arn
}

output "ssl_certificate_arn" {
  description = "ARN of the SSL certificate"
  value       = var.create_certificate ? aws_acm_certificate.website.arn : var.ssl_certificate_arn
}

output "website_urls" {
  description = "Website URLs"
  value = {
    cloudfront = "https://${aws_cloudfront_distribution.website.domain_name}"
    domain     = var.manage_dns ? "https://${var.domain_name}" : null
    www_domain = var.manage_dns ? "https://www.${var.domain_name}" : null
  }
}

output "aws_region" {
  description = "AWS region where resources are deployed"
  value       = var.aws_region
}

output "certificate_region" {
  description = "AWS region where SSL certificate is created (always us-east-1)"
  value       = "us-east-1"
