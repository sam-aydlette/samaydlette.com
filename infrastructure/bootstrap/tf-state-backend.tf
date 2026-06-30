# =============================================================================
# Remote Terraform backend for the per-deploy infrastructure/ stack
# (Task 16, Phase A — provisioning only)
# =============================================================================
# Today the per-deploy stack keeps NO remote state and rebuilds it by
# `terraform import`-ing every live resource on every run (~8.5 min/deploy).
# This provisions a persistent S3 state bucket + DynamoDB lock + a dedicated CMK,
# and grants the deploy role least-privilege access to them. NOTHING consumes
# this yet — the infrastructure/ stack switches to `backend "s3"` in Phase C.
#
# It lives in bootstrap (local state, applied by the operator) because a stack
# cannot manage the backend it stores its own state in. Correctness after the
# cutover is unchanged: the reconciliation gate (reconcile.py --live) still
# verifies live AWS == inventory regardless of how state is built.

locals {
  tfstate_bucket = "${local.domain_dashed}-tfstate"
  tfstate_key    = "infrastructure/terraform.tfstate"
  tflock_table   = "${local.domain_dashed}-tflock"
}

# Dedicated CMK: terraform state can contain secret material (generated
# passwords, etc.), so the state bucket is encrypted with a customer-managed key
# rather than SSE-S3 — consistent with the repo's "default to SSE-KMS for
# sensitive data" posture. (~$1/month; flagged in the PR.)
resource "aws_kms_key" "tfstate" {
  description             = "Encrypts the per-deploy Terraform state bucket"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "tfstate" {
  name          = "alias/${local.domain_dashed}-tfstate"
  target_key_id = aws_kms_key.tfstate.key_id
}

resource "aws_s3_bucket" "tfstate" {
  bucket = local.tfstate_bucket

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
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.tfstate.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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

# State lock table. TF 1.5 has no native S3 lockfile (that is >= 1.10), so a
# DynamoDB lock is used; on-demand billing keeps it to pennies. Holds only lock
# metadata (no secrets), so DynamoDB's default at-rest encryption is sufficient.
resource "aws_dynamodb_table" "tflock" {
  name         = local.tflock_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}

# Least-privilege access for the deploy role: read/write its own state object,
# take/release the lock, and use the state CMK. Scoped to the single state key
# and lock table.
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
      {
        Sid      = "StateCmk"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.tfstate.arn
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

output "tfstate_kms_alias" {
  description = "Alias of the CMK encrypting the state bucket"
  value       = aws_kms_alias.tfstate.name
}
