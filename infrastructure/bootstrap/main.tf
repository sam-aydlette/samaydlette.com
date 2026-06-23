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
  # checkov:skip=CKV_AWS_356:logs:PutResourcePolicy/DescribeResourcePolicies are account-level actions that do not support resource-level scoping; the log-group management statement is ARN-scoped. Documented exception.
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
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/apigateway/${local.domain_dashed}-silk-reeling*",
    ]
  }
  statement {
    # HTTP API (and CloudFront) access logging deliver through the CloudWatch Logs
    # vended-logs path, so the deploy role needs the log-resource-policy + the
    # log-delivery actions. All are account-level and do not support resource
    # scoping.
    sid    = "ManageVendedLogDelivery"
    effect = "Allow"
    actions = [
      "logs:PutResourcePolicy", "logs:DeleteResourcePolicy", "logs:DescribeResourcePolicies",
      "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery", "logs:ListLogDeliveries",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "compliance_logs" {
  # checkov:skip=CKV_AWS_356:logs:PutResourcePolicy is account-level and cannot be resource-scoped; log-group actions are ARN-scoped. Documented exception.
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

# Route 53 DNSSEC management for the deploy role (Task 5 PR B / D-3): create the
# key-signing key and enable/disable zone signing. KMS create/manage for the KSK
# is already covered by the role's account-wide kms:CreateKey/PutKeyPolicy grant.
data "aws_iam_policy_document" "dnssec_management" {
  statement {
    sid    = "ManageZoneDNSSEC"
    effect = "Allow"
    actions = [
      "route53:CreateKeySigningKey",
      "route53:DeleteKeySigningKey",
      "route53:ActivateKeySigningKey",
      "route53:DeactivateKeySigningKey",
      "route53:GetDNSSEC",
      "route53:EnableHostedZoneDNSSEC",
      "route53:DisableHostedZoneDNSSEC",
    ]
    resources = ["arn:aws:route53:::hostedzone/*"]
  }
  statement {
    # Provider polls change status after enabling/disabling signing.
    # GetChange supports the change resource type, so scope it rather than "*".
    sid       = "ReadChangeStatus"
    effect    = "Allow"
    actions   = ["route53:GetChange"]
    resources = ["arn:aws:route53:::change/*"]
  }
  statement {
    # CreateKeySigningKey requires the *caller* (not just the key policy) to hold
    # these KMS actions on the KSK. Scoped to us-east-1 KMS keys, where Route 53
    # DNSSEC keys must live and the only SIGN_VERIFY key is the DNSSEC KSK.
    sid    = "UseKskForDNSSEC"
    effect = "Allow"
    actions = [
      "kms:DescribeKey",
      "kms:GetPublicKey",
      "kms:Sign",
      "kms:CreateGrant",
    ]
    resources = ["arn:aws:kms:us-east-1:${data.aws_caller_identity.current.account_id}:key/*"]
  }
}

resource "aws_iam_role_policy" "dnssec_management" {
  name   = "dnssec-management"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.dnssec_management.json
}

# Task 7 (POAM-005): permissions to create and configure the access-log bucket
# and to turn on server access logging for the website bucket. Scoped to those
# two buckets.
data "aws_iam_policy_document" "log_bucket_management" {
  statement {
    # Create + configure the log bucket. The aws_s3_bucket Read refreshes ~18
    # bucket sub-configs (CORS, website, replication, object-lock, ...), so the
    # read side uses s3:Get* scoped to this one bucket rather than enumerating
    # every Get action (and risking a missed one). Writes are explicit.
    sid    = "ManageLogBucket"
    effect = "Allow"
    actions = [
      "s3:CreateBucket", "s3:Get*", "s3:ListBucket",
      "s3:PutBucketPublicAccessBlock", "s3:PutBucketOwnershipControls",
      "s3:PutEncryptionConfiguration", "s3:PutBucketVersioning", "s3:PutLifecycleConfiguration",
      "s3:PutBucketPolicy", "s3:PutBucketTagging",
    ]
    resources = ["arn:aws:s3:::${local.domain_dashed}-logs"]
  }
  statement {
    sid    = "WebsiteBucketConfig"
    effect = "Allow"
    actions = [
      "s3:PutBucketLogging", "s3:GetBucketLogging",
      "s3:PutLifecycleConfiguration", "s3:GetLifecycleConfiguration",
    ]
    resources = ["arn:aws:s3:::${var.domain_name}"]
  }
}

# Task 8b (POAM-013): manage the compliance Lambda's dead-letter queue.
data "aws_iam_policy_document" "compliance_dlq" {
  statement {
    sid    = "ManageComplianceDlq"
    effect = "Allow"
    actions = [
      "sqs:CreateQueue", "sqs:DeleteQueue", "sqs:GetQueueAttributes",
      "sqs:SetQueueAttributes", "sqs:GetQueueUrl", "sqs:TagQueue",
      "sqs:UntagQueue", "sqs:ListQueueTags",
    ]
    resources = ["arn:aws:sqs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${local.domain_dashed}-opa-compliance-dlq"]
  }
}

resource "aws_iam_role_policy" "compliance_dlq" {
  name   = "compliance-dlq-management"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.compliance_dlq.json
}

# Task 3 (POAM-021/022/023): manage the Silk Reeling Cognito user pool, client,
# and Hosted UI domain.
data "aws_iam_policy_document" "cognito_management" {
  # checkov:skip=CKV_AWS_356:cognito-idp:CreateUserPool/CreateUserPoolDomain/DescribeUserPoolDomain are account-level (a new pool/global domain has no pre-existing ARN); the pool/client management actions are scoped to userpool/*. Documented exception.
  statement {
    sid    = "ManageUserPool"
    effect = "Allow"
    actions = [
      "cognito-idp:DescribeUserPool", "cognito-idp:UpdateUserPool", "cognito-idp:DeleteUserPool",
      "cognito-idp:SetUserPoolMfaConfig", "cognito-idp:GetUserPoolMfaConfig",
      "cognito-idp:CreateUserPoolClient", "cognito-idp:DescribeUserPoolClient",
      "cognito-idp:UpdateUserPoolClient", "cognito-idp:DeleteUserPoolClient",
      "cognito-idp:ListUserPoolClients",
      "cognito-idp:CreateUserPoolDomain", "cognito-idp:DeleteUserPoolDomain",
      "cognito-idp:TagResource", "cognito-idp:UntagResource", "cognito-idp:ListTagsForResource",
    ]
    resources = ["arn:aws:cognito-idp:${var.aws_region}:${data.aws_caller_identity.current.account_id}:userpool/*"]
  }
  statement {
    # Account-level (no pre-existing resource ARN) or global-domain actions.
    sid    = "CreateAndDescribeGlobal"
    effect = "Allow"
    actions = [
      "cognito-idp:CreateUserPool",
      "cognito-idp:DescribeUserPoolDomain",
      "cognito-idp:ListUserPools",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "cognito_management" {
  # checkov:skip=CKV_AWS_356:CreateUserPool + DescribeUserPoolDomain are account/global-level and cannot be resource-scoped; pool/client actions are scoped to userpool/*. Documented exception.
  name   = "cognito-management"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.cognito_management.json
}

resource "aws_iam_role_policy" "log_bucket_management" {
  name   = "log-bucket-management"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.log_bucket_management.json
}

output "github_actions_role_arn" {
  value       = aws_iam_role.deploy.arn
  description = "Set as the workflow's aws-actions/configure-aws-credentials role-to-assume."
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.github.arn
}

# =============================================================================
# ACCOUNT IAM HYGIENE  (Prowler 2026-06-22 triage; AWS FSBP / FedRAMP best practice)
# =============================================================================
# Applied LIVE during the Prowler triage; codified here for repeatability. These
# are account-level governance, so they live in bootstrap (operator-applied), not
# the CI deploy. They already exist live — IMPORT before the next apply (else
# EntityAlreadyExists), see README / PR body for the exact `terraform import` ids.

# AWS Foundational Security Best Practices password policy (AC-2(1), IA-5(1);
# clears the Prowler iam_password_policy_* findings).
resource "aws_iam_account_password_policy" "fsbp" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

# Operators group. IAM best practice attaches policies to a group, not directly to
# a user (AC-2(1)/AC-6; clears Prowler iam_policy_attached_only_to_group_or_roles).
# NOTE: these reuse the operator's existing privilege as-is (relocated from the
# user, not broadened). Scoping the *FullAccess set down to least privilege is a
# tracked follow-up (Task 12-adjacent), same posture as legacy_deploy_policy_names.
resource "aws_iam_group" "operators" {
  name = "operators"
}

locals {
  operators_managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonRoute53FullAccess",
    "arn:aws:iam::aws:policy/CloudFrontFullAccess",
    "arn:aws:iam::aws:policy/AWSCertificateManagerFullAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/AmazonEventBridgeFullAccess",
    "arn:aws:iam::aws:policy/AWSLambda_FullAccess",
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/SteampipeS3ReadOnly",
  ]
}

resource "aws_iam_group_policy_attachment" "operators" {
  for_each   = toset(local.operators_managed_policy_arns)
  group      = aws_iam_group.operators.name
  policy_arn = each.value
}

# The two former user-inline policies, relocated to the group (same documents).
resource "aws_iam_group_policy" "operators_assessment_readonly" {
  name  = "assessment-readonly-2026-06"
  group = aws_iam_group.operators.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AssessmentReadOnly"
      Effect = "Allow"
      Action = [
        "apigateway:GET",
        "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy",
        "cognito-idp:List*", "cognito-idp:Describe*", "cognito-idp:Get*",
        "kms:List*", "kms:Describe*", "kms:GetPublicKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus",
        "sqs:ListQueues", "sqs:GetQueueAttributes", "sqs:GetQueueUrl", "sqs:ListQueueTags",
        "signer:ListSigningProfiles", "signer:GetSigningProfile", "signer:ListSigningJobs", "signer:DescribeSigningJob",
        "bedrock:ListFoundationModels", "bedrock:GetFoundationModel", "bedrock:GetFoundationModelAvailability",
        "bedrock:ListFoundationModelAgreementOffers", "bedrock:GetUseCaseForModelAccess",
        "resource-explorer-2:ListIndexes", "resource-explorer-2:Search", "resource-explorer-2:ListViews", "resource-explorer-2:GetView"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_group_policy" "operators_s3_bucket" {
  name  = "s3-bucket-policy"
  group = aws_iam_group.operators.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = ["arn:aws:s3:::${var.domain_name}", "arn:aws:s3:::${var.domain_name}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ListAllMyBuckets", "s3:GetBucketLocation"]
        Resource = "*"
      }
    ]
  })
}

variable "operator_user_name" {
  type        = string
  default     = "saydlette-dev"
  description = "The human operator's IAM user, made a member of the operators group."
}

resource "aws_iam_user_group_membership" "operator" {
  user   = var.operator_user_name
  groups = [aws_iam_group.operators.name]
}
