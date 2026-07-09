# =============================================================================
# Remote Terraform backend for the per-deploy infrastructure/ stack
# (Task 16, Phase A — provisioning only)
# =============================================================================
# Today the per-deploy stack keeps NO remote state and rebuilds it by
# `terraform import`-ing every live resource on every run (~8.5 min/deploy).
# This provisions a persistent S3 state bucket + a DynamoDB lock table, and
# grants the deploy role least-privilege access. NOTHING consumes this yet —
# the infrastructure/ stack switches to `backend "s3"` in Phase C.
#
# It lives in bootstrap (local state, applied by the operator) because a stack
# cannot manage the backend it stores its own state in. These two resources are
# the irreducible new infrastructure for remote state; no new CMK is added (the
# bucket uses SSE-S3, see below). Correctness after the cutover is unchanged:
# reconcile.py --live still verifies live AWS == inventory regardless of how
# state is built.

locals {
  tfstate_bucket = "${local.domain_dashed}-tfstate"
  tfstate_key    = "infrastructure/terraform.tfstate"
  tflock_table   = "${local.domain_dashed}-tflock"
}

resource "aws_s3_bucket" "tfstate" {
  bucket = local.tfstate_bucket

  # At-rest encryption is SSE-S3 (AES256), not a customer CMK: the bucket is
  # private, TLS-only, and reachable only by the deploy role and operator, so a
  # CMK is defense-in-depth rather than required, and is declined to avoid an
  # extra key to manage. SC-28 at-rest encryption is met by AES256. Tracked as
  # POAM-029 (same posture as the log bucket). Access logging and event
  # notifications are likewise dispositioned (POAM-028 / POAM-004): a private
  # internal state bucket needs no S3 access-log target (deploy-role access is in
  # account CloudTrail) and no event-notification consumer exists.
  # checkov:skip=CKV_AWS_145:SSE-S3/AES256 at rest by design; CMK declined given strict access controls (POAM-029).
  # checkov:skip=CKV_AWS_18:Internal state bucket; deploy-role access is captured by account CloudTrail, no separate S3 access-log target (POAM-028).
  # checkov:skip=CKV2_AWS_62:S3 event notifications are an integration feature, not an audit control; none is configured (POAM-004).

  # The state bucket must never be destroyed by a plan — losing it means losing
  # the ability to manage the stack in place.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle: abort incomplete multipart uploads and expire non-current state
# versions (live versions are never expired — they are the rollback history).
resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    id = "tfstate-housekeeping"
    filter {} # apply to the whole bucket; explicit per provider requirement
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# Deny any non-TLS access, consistent with the other buckets in this account.
resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonTLS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.tfstate.arn,
        "${aws_s3_bucket.tfstate.arn}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

# State lock table. TF 1.5 has no native S3 lockfile (that is >= 1.10, deferred
# to Phase D), so a DynamoDB lock is used; on-demand billing keeps it to pennies.
resource "aws_dynamodb_table" "tflock" {
  # The table holds only lock metadata (no secrets), so DynamoDB's default
  # at-rest encryption (AWS-managed) is sufficient; a customer CMK is declined
  # for the same reason as the state bucket (POAM-029).
  # checkov:skip=CKV_AWS_119:Lock metadata only, no secrets; default at-rest encryption is sufficient, CMK declined (POAM-029).
  name         = local.tflock_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}

# Least-privilege access for the deploy role: read/write its own state object and
# take/release the lock. Scoped to the single state key and lock table.
resource "aws_iam_role_policy" "tfstate_backend" {
  name = "tfstate-backend-access"
  role = aws_iam_role.deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "StateBucketList"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.tfstate.arn
      },
      {
        Sid      = "StateObject"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.tfstate.arn}/${local.tfstate_key}"
      },
      {
        Sid      = "StateLock"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
        Resource = aws_dynamodb_table.tflock.arn
      },
    ]
  })
}

# Outputs consumed by the Phase C backend configuration.
output "tfstate_bucket" {
  description = "S3 bucket holding the per-deploy stack's remote state"
  value       = aws_s3_bucket.tfstate.id
}

output "tfstate_key" {
  description = "State object key within the bucket"
  value       = local.tfstate_key
}

output "tflock_table" {
  description = "DynamoDB table used for state locking"
  value       = aws_dynamodb_table.tflock.name
}
