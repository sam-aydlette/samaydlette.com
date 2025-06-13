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

variable "ssl_certificate_arn" {
  description = "ARN of the SSL certificate for CloudFront (must be in us-east-1). Leave empty if create_certificate is true."
  type        = string
  default     = ""
}

variable "create_certificate" {
  description = "Whether to create a new SSL certificate. If false, ssl_certificate_arn must be provided."
  type        = bool
  default     = true
}

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
  description = "Whether to manage DNS with Route53"
  type        = bool
  default     = true
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
