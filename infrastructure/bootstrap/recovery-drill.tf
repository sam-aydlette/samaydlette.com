# =============================================================================
# BOOTSTRAP: the Chaos Gremlin restore drill's scratch bucket (KSI-RPL-TRC, KSI-RPL-RRO)
# =============================================================================
# Operator-applied (not CI), like everything else in this stack.
#
# Once a month the evidence nightly (scripts/hold-chaos-gremlin.py) copies a
# sample of the deployed site, fetched from the public site, into this bucket;
# the Chaos Gremlin (simulated) deletes and overwrites some of it; and the
# nightly restores them from S3 object versions, the restore
# docs/recovery-plan.md names for site content, timing it against the recovery
# objectives in data/recovery-objectives.json.
#
# THE TRADE. The nightly role gains its first write outside .well-known/vdr-*
# and its first delete. Both are confined to this bucket, which holds nothing
# but copies of public pages and expires everything after seven days: the
# production bucket stays out of reach (no write, no delete), and the nightly
# cannot delete an object version, so the history a restore relies on cannot
# be purged by it. The deploy reads the grant and compares it with the Secure
# Configuration Guide (ci-roles.nightly-recovery-drill-scope), so a deploy
# stops before the SDR is built while this file is not applied.
# =============================================================================

locals {
  recovery_drill_bucket = "${local.domain_dashed}-recovery-drill"
}

resource "aws_s3_bucket" "recovery_drill" {
  bucket = local.recovery_drill_bucket

  # Copies of public pages, expired after seven days; same at-rest posture as
  # the state bucket (SSE-S3, DEC-029, which names this bucket). Server access
  # logs go to the access-log bucket (below), and no event-notification
  # consumer exists (DEC-004, which names this bucket).
  # checkov:skip=CKV_AWS_145:SSE-S3/AES256 at rest for short-lived copies of public pages; CMK declined (DEC-029).
  # checkov:skip=CKV2_AWS_62:S3 event notifications are an integration feature, not an audit control; none is configured (DEC-004).

  tags = merge(local.bootstrap_tags, local.bootstrap_cls.recovery_drill, { Name = local.recovery_drill_bucket })
}

# S3 server access logs to the access-log bucket (infrastructure/logging.tf,
# whose policy names this bucket as a source), beside the website bucket's.
resource "aws_s3_bucket_logging" "recovery_drill" {
  bucket        = aws_s3_bucket.recovery_drill.id
  target_bucket = "${local.domain_dashed}-logs"
  target_prefix = "s3-access/recovery-drill/"
}

resource "aws_s3_bucket_versioning" "recovery_drill" {
  bucket = aws_s3_bucket.recovery_drill.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "recovery_drill" {
  bucket = aws_s3_bucket.recovery_drill.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "recovery_drill" {
  bucket                  = aws_s3_bucket.recovery_drill.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "recovery_drill" {
  bucket = aws_s3_bucket.recovery_drill.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Everything expires: current objects and old versions after seven days, delete
# markers once nothing is left behind them, unfinished uploads after one day.
resource "aws_s3_bucket_lifecycle_configuration" "recovery_drill" {
  bucket = aws_s3_bucket.recovery_drill.id
  rule {
    id     = "recovery-drill-expiry"
    status = "Enabled"
    filter {}
    expiration {
      days = 7
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
  rule {
    id     = "recovery-drill-delete-markers"
    status = "Enabled"
    filter {}
    expiration {
      expired_object_delete_marker = true
    }
  }

  depends_on = [aws_s3_bucket_versioning.recovery_drill]
}

resource "aws_s3_bucket_policy" "recovery_drill" {
  bucket = aws_s3_bucket.recovery_drill.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonTLS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.recovery_drill.arn, "${aws_s3_bucket.recovery_drill.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# The nightly's drill grant: this bucket only. No s3:DeleteObjectVersion, no
# bucket configuration write.
data "aws_iam_policy_document" "evidence_nightly_recovery_drill" {
  statement {
    sid       = "ListDrillVersions"
    effect    = "Allow"
    actions   = ["s3:ListBucketVersions"]
    resources = [aws_s3_bucket.recovery_drill.arn]
  }
  statement {
    sid       = "DrillObjects"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.recovery_drill.arn}/*"]
  }
}

resource "aws_iam_role_policy" "evidence_nightly_recovery_drill" {
  name   = "evidence-nightly-recovery-drill"
  role   = aws_iam_role.evidence_nightly.id
  policy = data.aws_iam_policy_document.evidence_nightly_recovery_drill.json
}
