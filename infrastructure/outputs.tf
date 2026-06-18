# =============================================================================
# TERRAFORM OUTPUTS: Information About Your Deployed Infrastructure
# =============================================================================
# This file defines what information Terraform shows me after deployment.
# Think of these as status reports that tell me important details about
# my infrastructure, like URLs, IDs, and whether features are enabled.
#
# When to use these outputs:
# - Troubleshooting deployment issues
# - Connecting to other systems that need AWS resource IDs
# - Verifying that everything was created correctly
# - Getting URLs and connection information
# =============================================================================

# =============================================================================
# EXISTING RESOURCE INFORMATION
# =============================================================================
# Details about my existing AWS resources that Terraform found and referenced
# =============================================================================

# The name of my S3 bucket that holds website files
output "s3_bucket_name" {
  description = "Name of the existing S3 bucket"
  value       = data.aws_s3_bucket.website.id
}

# The full AWS identifier for my S3 bucket (used by other AWS services)
output "s3_bucket_arn" {
  description = "ARN of the existing S3 bucket"
  value       = data.aws_s3_bucket.website.arn
}

# The ID of my CloudFront distribution that serves my website.
# Marked sensitive because var.existing_cloudfront_distribution_id is sensitive,
# and Terraform propagates that to the data source's `id` attribute.
output "cloudfront_distribution_id" {
  description = "ID of the existing CloudFront distribution"
  value       = data.aws_cloudfront_distribution.website.id
  sensitive   = true
}

# The full AWS identifier for my CloudFront distribution
output "cloudfront_distribution_arn" {
  description = "ARN of the existing CloudFront distribution"
  value       = data.aws_cloudfront_distribution.website.arn
}

# The CloudFront domain name that serves my website (looks like d123456.cloudfront.net)
output "cloudfront_domain_name" {
  description = "Domain name of the existing CloudFront distribution"
  value       = data.aws_cloudfront_distribution.website.domain_name
}

# Your Route53 hosted zone ID (only if I manage DNS with Terraform)
output "route53_zone_id" {
  description = "Route53 hosted zone ID"
  value       = var.manage_dns ? data.aws_route53_zone.website[0].zone_id : "Not managed by Terraform"
}

# The name servers for my domain (only if I manage DNS with Terraform)
output "route53_name_servers" {
  description = "Route53 name servers (if managing DNS)"
  value       = var.manage_dns ? data.aws_route53_zone.website[0].name_servers : []
}

# DNSSEC DS record to publish at the registrar (D-3). Until this is published in
# the parent (.com) zone, the zone is signed but resolvers do not validate it.
output "dnssec_ds_record" {
  description = "DS record to publish at the registrar to complete the DNSSEC chain of trust"
  value       = var.manage_dns ? aws_route53_key_signing_key.this[0].ds_record : "DNS not managed"
}

output "dnssec_ksk_details" {
  description = "Key-signing-key fields for the registrar's 'add DNSSEC key' form (flag, algorithm, public key)"
  value = var.manage_dns ? {
    flag                       = aws_route53_key_signing_key.this[0].flag
    signing_algorithm_mnemonic = aws_route53_key_signing_key.this[0].signing_algorithm_mnemonic
    digest_algorithm_mnemonic  = aws_route53_key_signing_key.this[0].digest_algorithm_mnemonic
    public_key                 = aws_route53_key_signing_key.this[0].public_key
    ds_record                  = aws_route53_key_signing_key.this[0].ds_record
  } : null
}

# Cognito identity provider for the Silk Reeling app (Task 3). Feeds the SPA
# build (VITE_COGNITO_*) and the Lambda's app-layer JWT validation.
output "cognito_user_pool_id" {
  description = "Silk Reeling Cognito user pool id"
  value       = var.create_silk_reeling ? aws_cognito_user_pool.silk_reeling[0].id : "Not created"
}

output "cognito_client_id" {
  description = "Silk Reeling Cognito app client id (public SPA client)"
  value       = var.create_silk_reeling ? aws_cognito_user_pool_client.silk_reeling[0].id : "Not created"
}

output "cognito_hosted_ui_domain" {
  description = "Cognito Hosted UI domain prefix (login page)"
  value       = var.create_silk_reeling ? "${aws_cognito_user_pool_domain.silk_reeling[0].domain}.auth.${var.aws_region}.amazoncognito.com" : "Not created"
}

output "cognito_issuer" {
  description = "Cognito JWT issuer URL (for the API Gateway authorizer + app-layer validation)"
  value       = var.create_silk_reeling ? "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.silk_reeling[0].id}" : "Not created"
}

# The SSL certificate that secures my website
output "ssl_certificate_arn" {
  description = "ARN of the existing SSL certificate"
  value       = data.aws_acm_certificate.website.arn
}

# Response headers policy ID. The CloudFront distribution is managed outside
# this Terraform config, so attach this policy to the distribution's default
# cache behavior manually:
#   aws cloudfront get-distribution-config --id <DIST_ID> > dist.json
#   # set DefaultCacheBehavior.ResponseHeadersPolicyId to this value, then:
#   aws cloudfront update-distribution --id <DIST_ID> --if-match <ETAG> \
#     --distribution-config file://dist.json
output "cloudfront_response_headers_policy_id" {
  description = "ID of the security-headers policy to attach to the CloudFront distribution"
  value       = var.create_response_headers_policy ? aws_cloudfront_response_headers_policy.website[0].id : "Not created (set create_response_headers_policy = true after granting IAM perms)"
}

# =============================================================================
# NEW COMPLIANCE RESOURCES
# =============================================================================
# Information about the compliance monitoring resources Terraform created
# =============================================================================

# The name of the Lambda function that monitors compliance
output "lambda_function_name" {
  description = "Name of the OPA compliance Lambda function"
  value       = var.create_lambda_compliance ? aws_lambda_function.opa_compliance[0].function_name : "Not created"
}

# The full AWS identifier for the compliance monitoring function
output "lambda_function_arn" {
  description = "ARN of the OPA compliance Lambda function"
  value       = var.create_lambda_compliance ? aws_lambda_function.opa_compliance[0].arn : "Not created"
}

# The IAM role that gives the Lambda function permission to do its job
output "iam_role_name" {
  description = "Name of the Lambda IAM role"
  value       = aws_iam_role.lambda_opa.name
}

# The full AWS identifier for the IAM role
output "iam_role_arn" {
  description = "ARN of the Lambda IAM role"
  value       = aws_iam_role.lambda_opa.arn
}

# The schedule that triggers automatic compliance checks
output "eventbridge_rule_name" {
  description = "Name of the EventBridge compliance rule"
  value       = var.create_eventbridge_rules ? aws_cloudwatch_event_rule.opa_compliance[0].name : "Not created"
}

# Whether DNS query logging is turned on (affects my AWS bill)
output "route53_logging_enabled" {
  description = "Whether Route53 query logging is enabled"
  value       = var.manage_dns && var.enable_route53_logging
}

# =============================================================================
# WEBSITE ACCESS INFORMATION
# =============================================================================
# The URLs where people can visit my website
# =============================================================================

# All the different ways people can access my website
output "website_urls" {
  description = "Website URLs"
  value = {
    cloudfront = "https://${data.aws_cloudfront_distribution.website.domain_name}" # Direct CloudFront URL
    domain     = "https://${var.domain_name}"                                      # Your custom domain
    www_domain = "https://www.${var.domain_name}"                                  # www version of my domain
  }
}

# =============================================================================
# SYSTEM STATUS SUMMARY
# =============================================================================
# High-level overview of what's managed vs. what's referenced
# =============================================================================

# Summary of which resources Terraform manages vs. just references
output "infrastructure_status" {
  description = "Status of managed vs existing resources"
  value = {
    existing_resources = {
      s3_bucket       = "Referenced (existing)"                                  # Terraform finds it but doesn't change it
      cloudfront      = "Referenced (existing)"                                  # Terraform finds it but doesn't change it
      route53_zone    = var.manage_dns ? "Referenced (existing)" : "Not managed" # May or may not be managed
      ssl_certificate = "Referenced (existing)"                                  # Terraform finds it but doesn't change it
    }
    managed_resources = {
      lambda_function  = var.create_lambda_compliance ? "Created by Terraform" : "Not created" # Terraform creates and manages
      iam_role         = "Created by Terraform"                                                # Terraform creates and manages
      eventbridge_rule = var.create_eventbridge_rules ? "Created by Terraform" : "Not created" # May or may not be created
      s3_bucket_policy = "Managed by Terraform"                                                # Terraform controls the security settings
      s3_encryption    = "Managed by Terraform"                                                # Terraform controls encryption settings
      s3_versioning    = "Managed by Terraform"                                                # Terraform controls versioning settings
    }
  }
}

# Which AWS region everything is deployed in
output "aws_region" {
  description = "AWS region where resources are deployed"
  value       = var.aws_region
}

# =============================================================================
# COMPLIANCE FEATURE STATUS
# =============================================================================
# Shows which compliance and monitoring features are active
# =============================================================================

# Summary of which compliance features are turned on or off
output "compliance_features" {
  description = "Status of compliance features"
  value = {
    opa_lambda_enabled  = var.create_lambda_compliance     # Whether compliance monitoring is running
    eventbridge_enabled = var.create_eventbridge_rules     # Whether automatic scheduling is active
    route53_logging     = var.enable_route53_logging       # Whether DNS query logging is active (costs money)
    compliance_schedule = var.compliance_check_schedule    # How often compliance checks run
    section_508_level   = var.section_508_compliance_level # What level of accessibility compliance is enforced
  }
}

# =============================================================================
# SILK REELING MIRROR (gated app)
# =============================================================================

# The API Gateway endpoint the CloudFront /silk-reeling/* behavior must point at.
output "silk_reeling_api_endpoint" {
  description = "API Gateway HTTP API endpoint for the gated app (CloudFront origin)"
  value       = var.create_silk_reeling ? aws_apigatewayv2_api.silk_reeling[0].api_endpoint : "Not created (set create_silk_reeling = true)"
}

# Secret ARNs whose VALUES must be set OUT OF BAND — never store values in
# Terraform:
#   aws secretsmanager put-secret-value --secret-id <arn> --secret-string 'user:pass'
#   aws secretsmanager put-secret-value --secret-id <arn> --secret-string '<anthropic-key>'
output "silk_reeling_secret_arns" {
  description = "Secret ARNs to populate out-of-band (basic-auth + Anthropic key)"
  value = var.create_silk_reeling ? {
    basic_auth    = aws_secretsmanager_secret.silk_basic_auth[0].arn
    anthropic_key = aws_secretsmanager_secret.silk_anthropic[0].arn
  } : {}
}

# Manual CloudFront wiring (post-deploy). The distribution is managed outside
# this config, so add the behavior by hand (same pattern as the response-headers
# policy). The app's Basic Auth is the gate; the API has no authorizer:
#   1. Publish the CloudFront Function infrastructure/cloudfront/silk-reeling-
#      strip-prefix.js (event type: viewer-request).
#   2. Add an origin = the API Gateway endpoint HOST (the value above, sans
#      https:// and trailing slash); custom origin, https-only.
#   3. Add a cache behavior: path pattern "/silk-reeling/*" -> that origin,
#      cache policy = Managed-CachingDisabled, an origin-request policy that
#      FORWARDS the Authorization header, viewer-protocol-policy =
#      redirect-to-https, and associate the strip-prefix function (viewer-request).
output "silk_reeling_cloudfront_setup" {
  description = "Pointer to the manual CloudFront wiring for /silk-reeling/*"
  value       = var.create_silk_reeling ? "API Gateway HTTP API (no authorizer; app Basic Auth gates it). Wire CloudFront: publish cloudfront/silk-reeling-strip-prefix.js (viewer-request), add origin (API endpoint host) + /silk-reeling/* behavior (CachingDisabled, forward Authorization, attach the function)." : "Not created"
}