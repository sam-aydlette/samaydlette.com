# =============================================================================
# TERRAFORM VARIABLES: Configuration Options for Website Infrastructure
# =============================================================================
# This file defines all the settings I can customize when deploying my
# website infrastructure. Think of these as the knobs and switches that
# control how my AWS resources get configured.
#
# How to use this:
# 1. Copy terraform.tfvars.example to terraform.tfvars
# 2. Set the values that match my specific setup
# 3. Run terraform with my custom settings
# =============================================================================

# =============================================================================
# BASIC WEBSITE INFORMATION
# =============================================================================
# Core settings that identify my website and where to deploy it
# =============================================================================

# My website's domain name (should match my S3 bucket name)
variable "domain_name" {
  description = "The domain name for the website"
  type        = string
  default     = "samaydlette.com"
}

# Which AWS region to put most of my resources in
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-2"
}

# What environment this is (helps with organization and cost tracking)
variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

# Which cost center gets billed for these resources
variable "cost_center" {
  description = "Cost center for billing purposes"
  type        = string
  default     = "website-ops"
}

# Who is responsible for managing these resources
variable "owner_email" {
  description = "Email of the resource owner"
  type        = string
  default     = "sam@samaydlette.com"
}

# =============================================================================
# EXISTING AWS RESOURCE IDENTIFIERS
# =============================================================================
# These tell Terraform where to find my existing AWS resources that were
# created manually. Terraform will work with these without changing them.
# =============================================================================

# The ID of my existing CloudFront distribution (looks like E1234567890123)
variable "existing_cloudfront_distribution_id" {
  description = "ID of the existing CloudFront distribution (e.g., E1234567890123)"
  type        = string
}

# Name of my existing S3 bucket (usually matches the domain name)
variable "existing_s3_bucket_name" {
  description = "Name of the existing S3 bucket (should match domain_name)"
  type        = string
  default     = ""
}

# The ID of my existing Route53 hosted zone (looks like Z1234567890123)
variable "existing_route53_zone_id" {
  description = "ID of the existing Route53 hosted zone (e.g., Z1234567890123)"
  type        = string
  default     = ""
}

# The ARN of my existing SSL certificate (must be in us-east-1 region)
variable "existing_ssl_certificate_arn" {
  description = "ARN of the existing SSL certificate in us-east-1"
  type        = string
  default     = ""
}

# =============================================================================
# CLOUDFRONT CONFIGURATION
# =============================================================================
# Settings that control my content delivery network costs and performance
# =============================================================================

# How widely I want CloudFront to distribute my content (affects cost)
variable "cloudfront_price_class" {
  description = "CloudFront price class"
  type        = string
  default     = "PriceClass_100"  # Cheapest option, covers US and Europe
  
  # Make sure only valid options are used
  validation {
    condition = contains([
      "PriceClass_All",    # Most expensive, worldwide coverage
      "PriceClass_200",    # Medium cost, US, Europe, Asia, Middle East
      "PriceClass_100"     # Cheapest, US and Europe only
    ], var.cloudfront_price_class)
    error_message = "CloudFront price class must be PriceClass_All, PriceClass_200, or PriceClass_100."
  }
}

# =============================================================================
# DNS MANAGEMENT OPTIONS
# =============================================================================
# Whether to manage DNS settings and logging (affects costs)
# =============================================================================

# Whether Terraform should work with my Route53 DNS settings
variable "manage_dns" {
  description = "Whether to manage DNS with Route53 (set to true if I have an existing hosted zone)"
  type        = bool
  default     = true
}

# Whether to log DNS queries (costs about $84/year but provides useful data)
variable "enable_route53_logging" {
  description = "Whether to enable Route53 query logging (adds CloudWatch costs)"
  type        = bool
  default     = false
}

# =============================================================================
# COMPLIANCE MONITORING SETTINGS
# =============================================================================
# How often to check security and when to run compliance scans
# =============================================================================

# How often the compliance monitoring function should run
variable "compliance_check_schedule" {
  description = "Schedule expression for compliance checks (CloudWatch Events)"
  type        = string
  default     = "rate(1 day)"  # Check once per day
}

# What level of accessibility compliance to enforce on my website
variable "section_508_compliance_level" {
  description = "Section 508 compliance level to check (A, AA, AAA)"
  type        = string
  default     = "AA"  # Most common standard for government websites
  
  # Make sure only valid compliance levels are used
  validation {
    condition = contains([
      "A",     # Basic accessibility compliance
      "AA",    # Standard compliance (recommended)
      "AAA"    # Highest compliance level
    ], var.section_508_compliance_level)
    error_message = "Section 508 compliance level must be A, AA, or AAA."
  }
}

# =============================================================================
# FEATURE TOGGLE SWITCHES
# =============================================================================
# Turn optional features on or off to control costs and complexity
# =============================================================================

# Whether to create the Lambda function that monitors compliance
variable "create_lambda_compliance" {
  description = "Whether to create the OPA compliance Lambda function"
  type        = bool
  default     = true
}

# Whether to create automatic schedules for compliance monitoring
variable "create_eventbridge_rules" {
  description = "Whether to create EventBridge rules for compliance monitoring"
  type        = bool
  default     = true
}