# =============================================================================
# BOOTSTRAP: GitHub OIDC deploy role  (assessment POAM-001, Task 2)
# =============================================================================
# Operator-applied (not CI). Replaces the long-lived github-actions-deploy IAM
# user/access-key with a role the workflow assumes via GitHub OIDC. See README.md.
# =============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "us-east-2"
}

variable "github_repo" {
  type        = string
  description = "owner/repo allowed to assume the deploy role"
  default     = "sam-aydlette/samaydlette.com"
}

variable "deploy_environment" {
  type        = string
  description = "GitHub Environment the Deploy Infrastructure job runs in (its OIDC sub is environment-scoped)."
  default     = "prod"
}

# The legacy IAM user's managed policies — reattached to the role so the deploy
# keeps the exact same scope at cutover (no regression). Consolidating these
# into one least-privilege policy is a tracked follow-up.
variable "legacy_deploy_policy_names" {
  type = list(string)
  default = [
    "GitHubActions-TerraformDataSources",
    "GitHubActions-SilkReeling",
    "github-actions-deploy",
    "github_policy_3",
    "github_actions_3",
    "github_actions_read_write",
    "github_action_read_2",
  ]
}

variable "domain_name" {
  type        = string
  default     = "samaydlette.com"
  description = "Site domain; used to build the log-group ARNs and CMK alias names the deploy role manages."
}

data "aws_caller_identity" "current" {}

# GitHub's OIDC identity provider. AWS validates the token against its own trust
# store; the thumbprint is still required by the API.
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

# Trust policy: only this repo's main-branch pushes and pull requests may assume
# the role — NOT a wildcard. PRs are included because the compliance-check job
# (terraform plan + OPA) runs on pull_request and also needs AWS read access.
data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        # main-branch pushes / schedule (compliance-check job; no environment),
        "repo:${var.github_repo}:ref:refs/heads/main",
        # pull requests (compliance-check job on PRs),
        "repo:${var.github_repo}:pull_request",
        # the Deploy Infrastructure job runs in a GitHub Environment, so its
        # OIDC sub is environment-scoped rather than ref-scoped.
        "repo:${var.github_repo}:environment:${var.deploy_environment}",
      ]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name                 = "github-actions-deploy-oidc"
  description          = "CI deploy role assumed via GitHub OIDC (POAM-001). Trust restricted to this repo's main + PRs."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
}

# Reattach the legacy user's managed policies to the role (same scope).
resource "aws_iam_role_policy_attachment" "legacy" {
  for_each   = toset(var.legacy_deploy_policy_names)
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${each.value}"
}

# Reconciliation-gate read permissions (the live-state enumeration the gate runs
# during deploy). Mirrors the reconcile-gate-readonly inline policy that was on
# the legacy user. Read-only; metadata only (no secretsmanager:GetSecretValue).
data "aws_iam_policy_document" "reconcile_reads" {
  # checkov:skip=CKV_AWS_356:Read-only account-enumeration actions (List*/Describe*/apigateway:GET) cannot be resource-scoped; the Action list is explicit and read-only, no write or admin. Documented false positive.
  statement {
    effect = "Allow"
    actions = [
      "lambda:ListFunctions",
      "apigateway:GET",
      "secretsmanager:ListSecrets",
      "kms:ListKeys",
      "kms:ListAliases",
      "kms:DescribeKey",
      "s3:ListAllMyBuckets",
      "logs:DescribeLogGroups",
    ]
    # Resource "*" is required: these are account-wide enumeration actions
    # (List*/Describe*/apigateway:GET) that do not support resource-level
    # scoping. The Action list is explicit and read-only — no wildcard action,
    # no write or admin permission. (CodeGuard iac-security: reviewed exception.)
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "reconcile_reads" {
  # checkov:skip=CKV_AWS_356:Read-only account-enumeration actions cannot be resource-scoped; explicit read-only Action list, no write or admin. Documented false positive.
  name   = "reconcile-gate-readonly"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.reconcile_reads.json
}

# Task 6 (POAM-011/018): permissions the deploy role needs to manage the at-rest
# CMK-encrypted log groups and to encrypt the Lambda env blocks. Added here (not
# in the main state) because this is the deploy identity itself; applied live and
# recorded here so live and IaC stay in sync. Mirrors the inline policies on the
# role: compliance-logs-management and compliance-kms-encrypt.
locals {
  domain_dashed = replace(var.domain_name, ".", "-")
}

# Manage the compliance Lambda + route53 query log groups (tags, retention, KMS
# association). Scoped to exactly those two log-group ARNs — least privilege.
data "aws_iam_policy_document" "compliance_logs" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:PutRetentionPolicy",
      "logs:DeleteRetentionPolicy",
      "logs:AssociateKmsKey",
      "logs:DisassociateKmsKey",
      "logs:ListTagsForResource",
      "logs:TagResource",
      "logs:UntagResource",
      "logs:TagLogGroup",
      "logs:UntagLogGroup",
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.domain_dashed}-opa-compliance*",
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/route53/${var.domain_name}*",
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.domain_dashed}-silk-reeling*",
    ]
  }
}

resource "aws_iam_role_policy" "compliance_logs" {
  name   = "compliance-logs-management"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.compliance_logs.json
}

# Encrypt the Lambda environment blocks with the app CMKs. KMS alias-based
# scoping requires Resource "*" plus a kms:ResourceAliases condition that limits
# the grant to exactly the two app keys (at-rest + silk-reeling) — this is the
# AWS-recommended pattern for alias-scoped access and avoids embedding rotation-
# unstable key IDs in IaC.
data "aws_iam_policy_document" "compliance_kms" {
  # checkov:skip=CKV_AWS_356:KMS alias-based scoping requires Resource "*"; the kms:ResourceAliases condition restricts the grant to two specific app-key aliases. No write to key policy, no admin. Documented exception.
  statement {
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant",
    ]
    resources = ["*"]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values = [
        "alias/${local.domain_dashed}-at-rest",
        "alias/${local.domain_dashed}-silk-reeling",
      ]
    }
  }
}

resource "aws_iam_role_policy" "compliance_kms" {
  # checkov:skip=CKV_AWS_356:KMS alias-scoped grant; Resource "*" is constrained by the kms:ResourceAliases condition to two specific app keys. Documented exception.
  name   = "compliance-kms-encrypt"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.compliance_kms.json
}

output "github_actions_role_arn" {
  value       = aws_iam_role.deploy.arn
  description = "Set as the workflow's aws-actions/configure-aws-credentials role-to-assume."
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.github.arn
}
