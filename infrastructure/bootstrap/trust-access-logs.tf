# =============================================================================
# Trust-center access logging (CDS-TRC-ACL), with the operator's privacy limits
# =============================================================================
# CloudFront standard logging (v2: CloudWatch vended-log delivery) for the
# distribution in cloudfront.tf, written to the existing access-log bucket that
# the per-deploy stack owns (../logging.tf: "<domain>-logs", SSE-S3, public
# access blocked, owner-enforced, a 90-day expiry on the CloudFront prefixes).
#
# Privacy limits (operator's condition, 2026-11-05):
# - The record carries only the fields below. No client IP, X-Forwarded-For,
#   client port, cookies, query string, user agent or referrer is ever logged:
#   CloudFront v2 field selection drops them at the edge, so they never reach
#   storage. Country (c-country) is the finest location kept.
# - CloudFront cannot limit logging to a path, so every request is logged with
#   those fields; the deploy's summarizer (scripts/build-access-summary.py)
#   counts only /.well-known/ and /trust/ and discards the rest, and only
#   aggregate counts are ever published.
# - Raw records expire after 90 days (../logging.tf). Monthly aggregate
#   summaries are kept for 13 months in the published access summary.
#
# The deploy fails when this delivery is absent or logs a field outside the
# allowlist (scripts/check-edge-access-logging.py, step "Check edge access
# logging and build the access summary"), so the trust center never claims
# logging that is not configured. Operator-applied, like the rest of bootstrap.
# The delivery's record_fields list and ALLOWED_FIELDS in that script are the
# same list; tests/test_edge_access_logging.py holds them equal.
# =============================================================================

locals {
  edge_access_log_name = "${local.domain_dashed}-edge-access"
  # The existing access-log bucket, owned by the per-deploy stack (../logging.tf
  # aws_s3_bucket.logs, already inventoried there); named, not read, here.
  access_log_bucket_arn = "arn:aws:s3:::${local.domain_dashed}-logs"
  edge_access_log_fields = [
    "date",
    "time",
    "x-edge-location",
    "c-country",
    "cs-method",
    "cs-uri-stem",
    "sc-status",
    "sc-bytes",
    "x-edge-result-type",
  ]
}


resource "aws_cloudwatch_log_delivery_source" "edge_access" {
  provider     = aws.us_east_1
  name         = local.edge_access_log_name
  log_type     = "ACCESS_LOGS"
  resource_arn = aws_cloudfront_distribution.website.arn
}

resource "aws_cloudwatch_log_delivery_destination" "edge_access" {
  provider      = aws.us_east_1
  name          = local.edge_access_log_name
  output_format = "json"

  delivery_destination_configuration {
    destination_resource_arn = "${local.access_log_bucket_arn}/cloudfront"
  }
}

resource "aws_cloudwatch_log_delivery" "edge_access" {
  provider                 = aws.us_east_1
  delivery_source_name     = aws_cloudwatch_log_delivery_source.edge_access.name
  delivery_destination_arn = aws_cloudwatch_log_delivery_destination.edge_access.arn
  record_fields            = local.edge_access_log_fields

  s3_delivery_configuration {
    suffix_path                 = "{DistributionId}/{yyyy}/{MM}/{dd}/{HH}"
    enable_hive_compatible_path = false
  }
}

# The deploy reads the delivery's configuration (to fail when it is absent or
# logs a forbidden field) and the CloudFront records (to build the aggregate
# summary). Read-only. Describe/Get on deliveries are account-level calls with
# no resource-level scoping for DescribeDeliveries; the Get* calls are scoped
# to this delivery's resources. The object read is limited to the two prefixes
# CloudFront delivery may write under.
data "aws_iam_policy_document" "edge_access_logs_read" {
  # checkov:skip=CKV_AWS_356:logs:DescribeDeliveries is an account-level enumeration action that cannot be resource-scoped; read-only. Documented exception.
  statement {
    sid       = "DescribeDeliveries"
    actions   = ["logs:DescribeDeliveries"]
    resources = ["*"]
  }
  statement {
    sid = "ReadEdgeAccessDelivery"
    actions = [
      "logs:GetDelivery",
      "logs:GetDeliverySource",
      "logs:GetDeliveryDestination",
    ]
    resources = [
      "arn:aws:logs:us-east-1:${data.aws_caller_identity.current.account_id}:delivery:*",
      aws_cloudwatch_log_delivery_source.edge_access.arn,
      aws_cloudwatch_log_delivery_destination.edge_access.arn,
    ]
  }
  statement {
    sid       = "ListEdgeAccessRecords"
    actions   = ["s3:ListBucket"]
    resources = [local.access_log_bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["cloudfront/*", "AWSLogs/${data.aws_caller_identity.current.account_id}/CloudFront/*"]
    }
  }
  statement {
    sid     = "ReadEdgeAccessRecords"
    actions = ["s3:GetObject"]
    resources = [
      "${local.access_log_bucket_arn}/cloudfront/*",
      "${local.access_log_bucket_arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/CloudFront/*",
    ]
  }
}

resource "aws_iam_role_policy" "edge_access_logs_read" {
  # checkov:skip=CKV_AWS_356:logs:DescribeDeliveries cannot be resource-scoped; read-only. Documented exception.
  name   = "edge-access-logs-read"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.edge_access_logs_read.json
}
