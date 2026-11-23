# =============================================================================
# ACCOUNT-LEVEL GUARDRAILS
# =============================================================================
# Settings that apply to the whole account rather than to one resource, so a
# resource created later (by Terraform or by hand) inherits them. They live in
# the bootstrap stack because the operator applies it: the deploy role is not
# given the account-wide write permissions they need.
# =============================================================================

# Security Hub S3.1. Every bucket already blocks public access on its own
# (aws_s3_bucket_public_access_block in the application stack); the site is
# served through CloudFront's origin access control, never as a public bucket.
# This makes the block the account default, so a new bucket cannot be public.
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Security Hub EC2.7. No EBS volume exists today; any created later in this
# region is encrypted at rest by default (AWS-managed key).
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}
