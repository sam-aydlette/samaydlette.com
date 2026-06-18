# =============================================================================
# SILK REELING MIRROR — gated app deployment (DRAFT / proposal)
# =============================================================================
# Adds a small Python API Lambda that serves the gated "Silk Reeling Mirror"
# app (static SPA + /api). Pose extraction runs in the browser, so this Lambda
# only does the numpy comparison and the Anthropic call — a small zip, no
# OpenCV/MediaPipe, no container.
#
# Access control:
#   App-layer HTTP Basic Auth inside the Lambda (operator-set username/password,
#   constant-time compare) gates EVERY request. An API Gateway HTTP API (no
#   authorizer) fronts the Lambda and passes the viewer's Authorization header
#   through unchanged; the app rejects anything without valid credentials.
#   (API Gateway replaces a Lambda Function URL, which this account blocks for
#   public access. No-authorizer is accepted in POAM-022.) The CloudFront
#   distribution (managed OUTSIDE this config) fronts it for the /silk-reeling/*
#   path, no-cache, forwarding `Authorization`, with a prefix-strip function —
#   manual wiring in outputs.tf. Basic Auth is a customer-responsibility control
#   (POAM-021); SAML federation to a customer IdP is the recommended upgrade.
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

# Account id for the KMS key policy (root-enables-IAM statement).
data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------
# Customer-managed KMS key for the app's secrets (rotation enabled).
# -----------------------------------------------------------------------------
resource "aws_kms_key" "silk_reeling" {
  count                   = local.silk_create
  description             = "CMK for ${local.silk_name} secrets (basic-auth, Anthropic key)"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  # Explicit key policy (CKV2_AWS_64): re-enable IAM-governed access for the
  # account, and allow Secrets Manager to use the key only via the Secrets
  # Manager service in this region. The Lambda's kms:Decrypt is governed by its
  # IAM policy under the root-enable statement.
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "${local.silk_name}-cmk"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowSecretsManagerUse"
        Effect    = "Allow"
        Principal = { Service = "secretsmanager.amazonaws.com" }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com"
          }
        }
      },
      {
        # Allow CloudWatch Logs to encrypt this app's log groups at rest with this
        # CMK (POAM-018). Scoped via EncryptionContext to exactly the silk-reeling
        # Lambda + API Gateway access log groups, so the grant cannot be used for
        # any other log group.
        Sid       = "AllowCloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = [
              "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.silk_name}",
              "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/apigateway/${local.silk_name}",
            ]
          }
        }
      },
    ]
  })

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
# (The HTTP Basic Auth secret was removed in Task 3 — access control is now
# Cognito, enforced by the API Gateway JWT authorizer + app-layer validation.)

resource "aws_secretsmanager_secret" "silk_anthropic" {
  count       = local.silk_create
  name        = "${local.silk_name}-anthropic-api-key"
  description = "Anthropic API key used by the app Lambda for feedback generation"
  kms_key_id  = aws_kms_key.silk_reeling[0].arn

  tags = merge(local.silk_tags, { Name = "${var.domain_name}-silk-reeling-anthropic" })
}

# Secret VALUES are injected out-of-band by the deploy's "Seed Silk Reeling
# secrets" step (`aws secretsmanager put-secret-value` from GitHub secrets).
# Terraform manages only the secret containers — it never sees or sets the
# value, so a re-deploy can't clobber the seeded credential.

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
        # Read ONLY the Anthropic API-key secret (the basic-auth secret was
        # removed in Task 3; auth is now Cognito).
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [aws_secretsmanager_secret.silk_anthropic[0].arn]
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
  retention_in_days = 365                             # 1-year retention (AU-11, POAM-017)
  kms_key_id        = aws_kms_key.silk_reeling[0].arn # customer-CMK at rest (POAM-018)

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

  # Reserved concurrency is NOT set: the account's total concurrency limit is
  # low, and reserving any would push unreserved below AWS's minimum of 10.
  # CKV_AWS_115 (no reserved concurrency) is therefore covered by the global
  # suppression (POAM-012). var.silk_reeling_max_concurrency is retained for when
  # the account limit is raised.

  # Encrypt the environment block at rest with the app's customer-managed CMK
  # (POAM-011). The contents are non-sensitive (secret ARNs + config, never
  # secret values), but customer-CMK encryption is applied for consistency with
  # the rest of the system; the function's role already holds kms:Decrypt on
  # this key for its Secrets Manager reads, so no IAM change is needed.
  kms_key_arn = aws_kms_key.silk_reeling[0].arn

  environment {
    variables = {
      # Non-sensitive config only — secret ARNs, never values (POAM-011).
      SRM_ANTHROPIC_SECRET_ARN = aws_secretsmanager_secret.silk_anthropic[0].arn
      SRM_ALLOWED_ORIGIN       = "https://${var.domain_name}"
      # Cognito for app-layer JWT validation (Task 3). The API Gateway JWT
      # authorizer is the boundary control; the app validates too so it stays
      # standalone-deployable.
      SRM_COGNITO_ISSUER    = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.silk_reeling[0].id}"
      SRM_COGNITO_CLIENT_ID = aws_cognito_user_pool_client.silk_reeling[0].id
      # Built SPA bundled into the Lambda package at /var/task/spa (see the CI
      # packaging step). The app serves it from "/"; /api/* is gated.
      SRM_SPA_DIR = "/var/task/spa"
    }
  }

  # Alias must exist before the env is encrypted — the deploy role's kms:Encrypt
  # grant is scoped by alias (see bootstrap compliance-kms-encrypt).
  depends_on = [aws_cloudwatch_log_group.silk_reeling, aws_kms_alias.silk_reeling]

  tags = merge(local.silk_tags, { Name = "${var.domain_name}-silk-reeling" })
}

# -----------------------------------------------------------------------------
# API Gateway HTTP API in front of the Lambda (replaces the Function URL, which
# this account blocks for public/NONE access). Access control is enforced at the
# APPLICATION layer (in-app HTTP Basic Auth): the API has NO authorizer, the
# viewer's Authorization header passes through unchanged, and the app rejects
# any request lacking valid credentials. CloudFront fronts it for /silk-reeling/*
# (no-cache, forward Authorization, prefix-strip). No-authorizer is accepted in
# POAM-022; brute-force hardening (rate-limit/WAF) is POAM-023.
# -----------------------------------------------------------------------------
resource "aws_apigatewayv2_api" "silk_reeling" {
  count         = local.silk_create
  name          = local.silk_name
  protocol_type = "HTTP"

  tags = merge(local.silk_tags, { Name = "${var.domain_name}-silk-reeling-api" })
}

resource "aws_apigatewayv2_integration" "silk_reeling" {
  count                  = local.silk_create
  api_id                 = aws_apigatewayv2_api.silk_reeling[0].id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.silk_reeling[0].invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

# Catch-all route → serves the SPA (and the OAuth callback at /). No authorizer,
# so the login page can load.
resource "aws_apigatewayv2_route" "silk_reeling" {
  count     = local.silk_create
  api_id    = aws_apigatewayv2_api.silk_reeling[0].id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.silk_reeling[0].id}"
}

# Cognito JWT authorizer (POAM-022). For Cognito access tokens the authorizer
# matches the configured audience against the token's client_id.
resource "aws_apigatewayv2_authorizer" "silk_reeling" {
  count            = local.silk_create
  api_id           = aws_apigatewayv2_api.silk_reeling[0].id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "${local.silk_name}-cognito"

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.silk_reeling[0].id]
    issuer   = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.silk_reeling[0].id}"
  }
}

# The API routes (/api/*) require a valid Cognito JWT at the gateway (POAM-022).
resource "aws_apigatewayv2_route" "silk_reeling_api" {
  count              = local.silk_create
  api_id             = aws_apigatewayv2_api.silk_reeling[0].id
  route_key          = "ANY /api/{proxy+}"
  target             = "integrations/${aws_apigatewayv2_integration.silk_reeling[0].id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.silk_reeling[0].id
}

# Access-log group for the HTTP API stage (POAM-024). CMK-encrypted + 1-year
# retention, consistent with the rest of the system.
resource "aws_cloudwatch_log_group" "silk_apigw" {
  count             = local.silk_create
  name              = "/aws/apigateway/${local.silk_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.silk_reeling[0].arn

  tags = merge(local.silk_tags, { Name = "${var.domain_name}-silk-reeling-apigw-logs" })
}

# HTTP API access logging delivers to CloudWatch Logs via the logs delivery
# service, which requires an account log-resource-policy granting it write access
# to the destination group. Scoped to exactly this access-log group.
resource "aws_cloudwatch_log_resource_policy" "silk_apigw" {
  count       = local.silk_create
  policy_name = "${local.silk_name}-apigw-access-logs"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = ["delivery.logs.amazonaws.com", "apigateway.amazonaws.com"] }
        Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource  = "${aws_cloudwatch_log_group.silk_apigw[0].arn}:*"
        Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
      },
    ]
  })
}

resource "aws_apigatewayv2_stage" "silk_reeling" {
  count       = local.silk_create
  api_id      = aws_apigatewayv2_api.silk_reeling[0].id
  name        = "$default"
  auto_deploy = true

  # Rate limiting / brute-force protection (POAM-023, AC-7/SC-5). Sized for a
  # single-operator app; bounds request floods at the managed edge (no WAF).
  default_route_settings {
    throttling_rate_limit  = 20
    throttling_burst_limit = 10
  }

  # Access logging (POAM-024): one JSON line per request to the CMK-encrypted
  # access-log group. depends_on the resource policy so the delivery service is
  # authorized before the stage starts emitting.
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.silk_apigw[0].arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }

  depends_on = [aws_cloudwatch_log_resource_policy.silk_apigw]

  tags = merge(local.silk_tags, { Name = "${var.domain_name}-silk-reeling-api-stage" })
}

resource "aws_lambda_permission" "silk_reeling_apigw" {
  count         = local.silk_create
  statement_id  = "AllowApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.silk_reeling[0].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.silk_reeling[0].execution_arn}/*/*"
}
