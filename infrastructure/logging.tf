# =============================================================================
# ACCESS-LOG DESTINATION BUCKET (POAM-005, C-3)
# =============================================================================
# Dedicated, locked-down bucket that receives S3 server access logs for the
# website bucket (POAM-005) and, via the out-of-band CloudFront standard-logging
# delivery, CloudFront access logs (C-3). Kept separate from the website bucket
# so logging never recurses into the bucket being logged.
# =============================================================================

resource "aws_s3_bucket" "logs" {
  # checkov:skip=CKV_AWS_18:This IS the access-log destination bucket; enabling server access logging on it would recurse into itself. Otherwise locked down (BPA, ownership-enforced, encrypted, lifecycle).
  # checkov:skip=CKV_AWS_145:SSE-S3 (AES256) is deliberate, consistent with the public website bucket — these are low-sensitivity access logs about public-facing resources, and SSE-S3 is the reliably-supported encryption for S3 server-access-log delivery targets. A customer CMK would require granting the AWS log-delivery services key access for no sensitivity benefit.
  # checkov:skip=CKV2_AWS_62:No event-driven workflow consumes these logs (same rationale as POAM-004 for the website bucket); retention is handled by the lifecycle rule.
  bucket = "${replace(var.domain_name, ".", "-")}-logs"
  tags = merge(local.cls.security_tooling, {
    Name               = "${var.domain_name}-logs"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  })
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ACLs disabled — the log-delivery services write owner-enforced objects
# authorized by the bucket policy below (the modern, ACL-free path).
resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

# Retain logs ~13 months then expire (AU-11: > 1 year), and clean up old
# versions and incomplete uploads so the bucket can't grow unbounded.
resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {}
    expiration { days = 400 }
    noncurrent_version_expiration { noncurrent_days = 30 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

# Allow the AWS log-delivery services to write to their respective prefixes,
# constrained to this account (and, for S3 server access logs, the website
# bucket as the source).
resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "S3ServerAccessLogsWrite"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/s3-access/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
          ArnLike      = { "aws:SourceArn" = data.aws_s3_bucket.website.arn }
        }
      },
      {
        Sid       = "CloudFrontStandardLogDelivery"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/cloudfront/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
      # Deny any request not made over TLS (SC-8 / SC-13; Prowler
      # s3_bucket_secure_transport_policy). Preventive guardrail, not detective.
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}

# Turn on S3 server access logging for the website bucket (POAM-005).
resource "aws_s3_bucket_logging" "website" {
  bucket        = data.aws_s3_bucket.website.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/"

  depends_on = [aws_s3_bucket_policy.logs]
}
