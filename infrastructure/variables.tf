# variables.tf

variable "domain_name" {
  description = "The domain name for the website"
  type        = string
  default     = "samaydlette.com"
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-2"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "cost_center" {
  description = "Cost center for billing purposes"
  type        = string
  default     = "website-ops"
}

variable "owner_email" {
  description = "Email of the resource owner"
  type        = string
  default     = "sam@samaydlette.com"
}

# EXISTING RESOURCE IDENTIFIERS
# =============================

variable "existing_cloudfront_distribution_id" {
  description = "ID of the existing CloudFront distribution (e.g., E1234567890123)"
  type        = string
}

variable "existing_s3_bucket_name" {
  description = "Name of the existing S3 bucket (should match domain_name)"
  type        = string
  default     = ""
  
  validation {
    condition = var.existing_s3_bucket_name == "" || var.existing_s3_bucket_name == var.domain_name
    error_message = "If provided, existing_s3_bucket_name must match domain_name."
  }
}

variable "existing_route53_zone_id" {
  description = "ID of the existing Route53 hosted zone (e.g., Z1234567890123)"
  type        = string
  default     = ""
}

variable "existing_ssl_certificate_arn" {
  description = "ARN of the existing SSL certificate in us-east-1"
  type        = string
  default     = ""
}

# OPTIONAL FEATURES
# =================

variable "cloudfront_price_class" {
  description = "CloudFront price class"
  type        = string
  default     = "PriceClass_100"
  
  validation {
    condition = contains([
      "PriceClass_All",
      "PriceClass_200", 
      "PriceClass_100"
    ], var.cloudfront_price_class)
    error_message = "CloudFront price class must be PriceClass_All, PriceClass_200, or PriceClass_100."
  }
}

variable "manage_dns" {
  description = "Whether to manage DNS with Route53 (set to true if you have an existing hosted zone)"
  type        = bool
  default     = true
}

variable "enable_route53_logging" {
  description = "Whether to enable Route53 query logging (adds CloudWatch costs)"
  type        = bool
  default     = false
}

variable "compliance_check_schedule" {
  description = "Schedule expression for compliance checks (CloudWatch Events)"
  type        = string
  default     = "rate(1 day)"
}

variable "section_508_compliance_level" {
  description = "Section 508 compliance level to check (A, AA, AAA)"
  type        = string
  default     = "AA"
  
  validation {
    condition = contains([
      "A",
      "AA", 
      "AAA"
    ], var.section_508_compliance_level)
    error_message = "Section 508 compliance level must be A, AA, or AAA."
  }
}

# FEATURE FLAGS
# =============

variable "create_lambda_compliance" {
  description = "Whether to create the OPA compliance Lambda function"
  type        = bool
  default     = true
}

variable "create_eventbridge_rules" {
  description = "Whether to create EventBridge rules for compliance monitoring"
  type        = bool
  default     = true
}