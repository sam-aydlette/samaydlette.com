# =============================================================================
# CLOUDTRAIL MANAGEMENT-EVENTS TRAIL (AU-2/AU-3/AU-11/AU-12; KSI-MLA-OSM)
# =============================================================================
# Durable, validated account-level API audit. Until this trail existed, the
# only control-plane record was the default CloudTrail Event History (90 days,
# not durable, console-only) while the SSP's AU statements assumed CloudTrail
# coverage. Management events only — the first copy is free of charge; the
# cost is S3 storage (negligible at this account's activity level).
#
# Retention (AU-11 / OMB M-21-31 tiering): 12 months in S3 Standard, then
# Glacier Deep Archive to 30 months, then expire.
# =============================================================================

resource "aws_s3_bucket" "cloudtrail" {
  # checkov:skip=CKV_AWS_18:This is the audit-log sink itself; S3 server access logging on it is declined for the same log-recursion reason as the access-log bucket (POAM-028 pattern). It is BPA-blocked, TLS-only, versioned, lifecycle-managed, and writable only by the CloudTrail service scoped to this account's trail.
  # checkov:skip=CKV_AWS_145:SSE-S3 (AES256) is deliberate, consistent with POAM-029: control-plane audit records about this account's own public-resource infrastructure, written by the CloudTrail service. A customer CMK adds key-sprawl without a confidentiality benefit here.
  # checkov:skip=CKV_AWS_144:Cross-region replication declined — single-account PoC; durability is S3's 11 nines plus versioning, and the trail is multi-region so a regional console outage does not lose capture.
  # checkov:skip=CKV2_AWS_62:No event-driven workflow consumes these objects; retention is handled by the lifecycle rule (same rationale as the access-log bucket).
  bucket = "${replace(var.domain_name, ".", "-")}-cloudtrail"
  tags = merge(local.cls.security_tooling, {
    Name               = "${var.domain_name}-cloudtrail"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  })
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration { status = "Enabled" }
}

# AU-11 tiering: 12 months active, then Deep Archive cold storage to 30
# months total, then expire. Noncurrent versions and failed uploads cleaned.
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    id     = "audit-retention-tiering"
    status = "Enabled"
    filter {}
    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }
    expiration { days = 913 }
    noncurrent_version_expiration { noncurrent_days = 30 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

# CloudTrail's canonical two-statement delivery policy, both scoped to this
# account's trail ARN, plus the standing DenyNonTLS guardrail.
resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${replace(var.domain_name, ".", "-")}-management"
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${replace(var.domain_name, ".", "-")}-management"
          }
        }
      },
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}

resource "aws_cloudtrail" "management" {
  # checkov:skip=CKV_AWS_35:Trail log-file SSE-KMS declined for the same POAM-029 rationale as the delivery bucket — SSE-S3 on control-plane records about this account's own infrastructure; a CMK adds key-sprawl and a decrypt dependency for every consumer without a confidentiality benefit.
  # checkov:skip=CKV2_AWS_10:CloudWatch Logs integration declined — it duplicates every event into paid log-group storage to enable metric filters this single-operator system reviews quarterly instead (KSI-MLA-RVL). Log-file validation plus the TLS-only versioned bucket carry the integrity requirement.
  # checkov:skip=CKV_AWS_252:SNS delivery notifications declined — no consumer exists for a per-delivery notification; the quarterly review reads the bucket directly.
  name                          = "${replace(var.domain_name, ".", "-")}-management"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  # security_tooling_internal, not security_tooling: the inventory derives the
  # trail's data_sensitivity as internal (control-plane audit records), and
  # reconcile invariant (i) requires live tags == projected classification.
  tags = merge(local.cls.security_tooling_internal, {
    Name               = "${var.domain_name}-management-trail"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  })

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}
