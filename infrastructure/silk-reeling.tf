# =============================================================================
# SILK REELING MIRROR — gated app deployment (DRAFT / proposal)
# =============================================================================
# Adds a small Python API Lambda that serves the gated "Silk Reeling Mirror"
# app (static SPA + /api). Pose extraction runs in the browser, so this Lambda
# only does the numpy comparison and the Anthropic call — a small zip, no
# OpenCV/MediaPipe, no container.
#
# Access control (two layers):
#   1. Edge — the CloudFront distribution (managed OUTSIDE this config, see the
#      data source in main.tf) routes /silk-reeling/* to this Lambda's Function
#      URL via Origin Access Control (SigV4-signed). The Function URL is AWS_IAM
#      auth, so it cannot be invoked directly/publicly — only the OAC-signed
#      distribution can. Manual wiring steps are in outputs.tf.
#   2. App — HTTP Basic Auth inside the Lambda (operator-set username/password,
#      constant-time compare). A customer-responsibility control, risk-accepted
#      (POAM-021); SAML federation to a customer IdP is the recommended upgrade.
#
# Secrets (the basic-auth credential and the Anthropic API key) live in Secrets
# Manager, encrypted with a customer-managed KMS key, read at runtime via
# least-privilege IAM. Secret VALUES are injected OUT OF BAND (CI
# `put-secret-value` from a GitHub secret); this config creates only the secret
# containers, so plaintext never enters Terraform state.
#
# Everything here is gated by var.create_silk_reeling (default false), inert
# until explicitly enabled — matching the repo's feature-flag pattern.
# =============================================================================

locals {
  silk_name   = "${replace(var.domain_name, ".", "-")}-silk-reeling"
  silk_create = var.create_silk_reeling ? 1 : 0
  silk_tags = {
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  }
}

# -----------------------------------------------------------------------------
# Customer-managed KMS key for the app's secrets (rotation enabled).
# -----------------------------------------------------------------------------
resource "aws_kms_key" "silk_reeling" {
  count                   = local.silk_create
  description             = "CMK for ${local.silk_name} secrets (basic-auth, Anthropic key)"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(local.silk_tags, { Name = "${var.domain_name}-silk-reeling-cmk" })
}

resource "aws_kms_alias" "silk_reeling" {
  count         = local.silk_create
  name          = "alias/${local.silk_name}"
  target_key_id = aws_kms_key.silk_reeling[0].key_id
}

# -----------------------------------------------------------------------------
# Secrets (containers only; values set out-of-band — see header).
# -----------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "silk_basic_auth" {
  count       = local.silk_create
  name        = "${local.silk_name}-basic-auth"
  description = "Operator-set HTTP Basic Auth credential (user:pass) gating the app"
  kms_key_id  = aws_kms_key.silk_reeling[0].arn

  tags = merge(local.silk_tags, { Name = "${var.domain_name}-silk-reeling-basic-auth" })
}

resource "aws_secretsmanager_secret" "silk_anthropic" {
  count       = local.silk_create
  name        = "${local.silk_name}-anthropic-api-key"
  description = "Anthropic API key used by the app Lambda for feedback generation"
  kms_key_id  = aws_kms_key.silk_reeling[0].arn

  tags = merge(local.silk_tags, { Name = "${var.domain_name}-silk-reeling-anthropic" })
}

# Placeholder versions so the secrets are non-empty. Real values are injected
# out-of-band (`aws secretsmanager put-secret-value ...` in CI from a GitHub
# secret); ignore_changes keeps that real value from drifting and keeps
# plaintext out of Terraform state/config.
resource "aws_secretsmanager_secret_version" "silk_basic_auth" {
  count         = local.silk_create
  secret_id     = aws_secretsmanager_secret.silk_basic_auth[0].id
  secret_string = "SET_OUT_OF_BAND"

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret_version" "silk_anthropic" {
  count         = local.silk_create
  secret_id     = aws_secretsmanager_secret.silk_anthropic[0].id
  secret_string = "SET_OUT_OF_BAND"

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# -----------------------------------------------------------------------------
# IAM role for the app Lambda — least privilege.
# -----------------------------------------------------------------------------
resource "aws_iam_role" "silk_reeling" {
  count = local.silk_create
  name  = "${local.silk_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = merge(local.silk_tags, { Name = "${var.domain_name}-silk-reeling-role" })
}

resource "aws_iam_role_policy" "silk_reeling" {
  count = local.silk_create
  name  = "${local.silk_name}-policy"
  role  = aws_iam_role.silk_reeling[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:*:log-group:/aws/lambda/${local.silk_name}:*"
      },
      {
        # Read ONLY the two app secrets.
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [
          aws_secretsmanager_secret.silk_basic_auth[0].arn,
          aws_secretsmanager_secret.silk_anthropic[0].arn,
        ]
      },
      {
        # Decrypt those secrets with the app CMK only.
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [aws_kms_key.silk_reeling[0].arn]
      },
    ]
  })
}

# -----------------------------------------------------------------------------
# CloudWatch log group (explicit, so retention + tags are managed).
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "silk_reeling" {
  count             = local.silk_create
  name              = "/aws/lambda/${local.silk_name}"
  retention_in_days = 7

  tags = merge(local.silk_tags, { Name = "${var.domain_name}-silk-reeling-logs" })
}

# -----------------------------------------------------------------------------
# The app Lambda. Small Python zip (numpy + anthropic); the browser does the ML.
# The package is built and supplied by CI at var.silk_reeling_package_path.
# -----------------------------------------------------------------------------
resource "aws_lambda_function" "silk_reeling" {
  count = local.silk_create

  filename         = var.silk_reeling_package_path
  function_name    = local.silk_name
  role             = aws_iam_role.silk_reeling[0].arn
  handler          = "lambda_handler.handler"
  runtime          = "python3.13"
  timeout          = 30
  memory_size      = 1024
  source_code_hash = filebase64sha256(var.silk_reeling_package_path)

  # Cap blast radius / cost of a network-facing endpoint. Passes CKV_AWS_115 on
  # its own rather than leaning on the global suppression (POAM-012).
  reserved_concurrent_executions = var.silk_reeling_max_concurrency

  environment {
    variables = {
      # Non-sensitive config only — secret ARNs, never values (POAM-011).
      SRM_BASIC_AUTH_SECRET_ARN = aws_secretsmanager_secret.silk_basic_auth[0].arn
      SRM_ANTHROPIC_SECRET_ARN  = aws_secretsmanager_secret.silk_anthropic[0].arn
      SRM_ALLOWED_ORIGIN        = "https://${var.domain_name}"
    }
  }

  depends_on = [aws_cloudwatch_log_group.silk_reeling]

  tags = merge(local.silk_tags, { Name = "${var.domain_name}-silk-reeling" })
}

# -----------------------------------------------------------------------------
# Function URL — AWS_IAM auth so only the CloudFront OAC (SigV4) can invoke it;
# direct public calls are denied. The app still enforces Basic Auth on top.
# -----------------------------------------------------------------------------
resource "aws_lambda_function_url" "silk_reeling" {
  count              = local.silk_create
  function_name      = aws_lambda_function.silk_reeling[0].function_name
  authorization_type = "AWS_IAM"
}

# Allow the site's CloudFront distribution to invoke the Function URL.
# source_arn scopes the grant to this one distribution.
resource "aws_lambda_permission" "silk_reeling_cloudfront" {
  count                  = local.silk_create
  statement_id           = "AllowCloudFrontInvoke"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.silk_reeling[0].function_name
  principal              = "cloudfront.amazonaws.com"
  source_arn             = data.aws_cloudfront_distribution.website.arn
  function_url_auth_type = "AWS_IAM"
}
