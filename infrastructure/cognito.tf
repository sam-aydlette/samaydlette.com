# =============================================================================
# COGNITO — authentication for the Silk Reeling app (POAM-021/022/023)
# =============================================================================
# Replaces the shared HTTP Basic Auth credential with a real identity provider:
# per-user accounts, required TOTP MFA, and a Hosted UI login. The API Gateway
# JWT authorizer (silk-reeling.tf) validates the Cognito token at the boundary;
# the app also validates it (so the app stays standalone-deployable). Gated on
# create_silk_reeling, like the rest of the app.
# =============================================================================

resource "aws_cognito_user_pool" "silk_reeling" {
  count = local.silk_create
  name  = "${local.silk_name}-users"

  # Operator-managed accounts only — no open self-registration.
  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  # Required multi-factor auth via authenticator-app TOTP (free; no SMS cost).
  mfa_configuration = "ON"
  software_token_mfa_configuration {
    enabled = true
  }

  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 7
  }

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  tags = merge(local.silk_tags, { Name = "${var.domain_name}-silk-reeling-users" })
}

# Hosted UI login page (Cognito-prefix domain; free). Must be globally unique.
resource "aws_cognito_user_pool_domain" "silk_reeling" {
  count        = local.silk_create
  domain       = local.silk_name
  user_pool_id = aws_cognito_user_pool.silk_reeling[0].id
}

# Public SPA client (no secret) using the OAuth2 authorization-code + PKCE flow.
resource "aws_cognito_user_pool_client" "silk_reeling" {
  count        = local.silk_create
  name         = "${local.silk_name}-spa"
  user_pool_id = aws_cognito_user_pool.silk_reeling[0].id

  generate_secret = false

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  supported_identity_providers         = ["COGNITO"]

  callback_urls = ["https://${var.domain_name}/silk-reeling/"]
  logout_urls   = ["https://${var.domain_name}/silk-reeling/"]

  explicit_auth_flows = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

  prevent_user_existence_errors = "ENABLED"
  enable_token_revocation       = true

  access_token_validity  = 60
  id_token_validity      = 60
  refresh_token_validity = 30
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }
}
