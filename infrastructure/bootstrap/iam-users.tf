# =============================================================================
# IAM USERS
# =============================================================================
# Every IAM user in the account is declared here, so the inventory lists each
# one and a user created outside Terraform stands out. The users existed before
# they were managed here and were adopted into state on 2026-11-20 (#596).
#
# Permissions live on groups, never on users (AC-2(1)/AC-6), as with the
# operators and read-only groups in main.tf.
#
# Access keys are deliberately not managed here: an aws_iam_access_key puts its
# secret in Terraform state. Keys are created and rotated by the operator.
# Managing tags here also replaces the key-description tags the console adds.
# =============================================================================

# The human operator: a member of the operators group
# (aws_iam_user_group_membership.operator in main.tf).
resource "aws_iam_user" "operator" {
  # checkov:skip=CKV_AWS_273:IAM users rather than Identity Center (no AWS Organizations); risk-accepted, DEC-042
  name = var.operator_user_name
  tags = merge(local.bootstrap_tags, local.bootstrap_cls.identity_secrets_internal, { Name = var.operator_user_name })
}

# A read-only machine user: an access key, no console password, a member of
# the read-only group.
resource "aws_iam_user" "read_only" {
  # checkov:skip=CKV_AWS_273:IAM users rather than Identity Center (no AWS Organizations); risk-accepted, DEC-042
  name = "readonly"
  tags = merge(local.bootstrap_tags, local.bootstrap_cls.identity_secrets_internal, { Name = "readonly" })
}

resource "aws_iam_user_group_membership" "read_only" {
  user   = aws_iam_user.read_only.name
  groups = [aws_iam_group.read_only.name]
}

# -----------------------------------------------------------------------------
# Independent corroboration collector
# -----------------------------------------------------------------------------
# The machine user the independent corroboration tool (docs/boundary/
# corroboration.json) collects the live account with: read-only, an access key,
# no console password. Its permissions used to be attached to the user; they
# are on this group now.
resource "aws_iam_user" "corroboration_collector" {
  # checkov:skip=CKV_AWS_273:IAM users rather than Identity Center (no AWS Organizations); risk-accepted, DEC-042
  name = "tap-samsite-collector"
  tags = merge(local.bootstrap_tags, local.bootstrap_cls.identity_secrets_internal, { Name = "tap-samsite-collector" })
}

resource "aws_iam_group" "corroboration" {
  name = "corroboration-collector"
}

resource "aws_iam_group_policy_attachment" "corroboration" {
  group      = aws_iam_group.corroboration.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# What SecurityAudit leaves out and the collector reads: metadata only (no
# secret values, no decryption, no object or message contents).
resource "aws_iam_group_policy" "corroboration_supplement" {
  # checkov:skip=CKV_AWS_355:List/Describe/Get metadata reads across services
  # cannot be resource-scoped; no write, secret-value or decrypt action is granted.
  # checkov:skip=CKV_AWS_287:Metadata-only reads, no credential retrieval; false positive, DEC-027
  name  = "corroboration-readonly-supplement"
  group = aws_iam_group.corroboration.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
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
          "resource-explorer-2:ListIndexes", "resource-explorer-2:Search", "resource-explorer-2:ListViews",
          "resource-explorer-2:GetView",
        ]
        Resource = "*"
      },
      {
        Sid      = "CollectorSupplement"
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity", "cloudwatch:GetMetricData", "cloudwatch:ListMetrics", "cloudwatch:GetMetricStatistics"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_user_group_membership" "corroboration" {
  user   = aws_iam_user.corroboration_collector.name
  groups = [aws_iam_group.corroboration.name]
}
