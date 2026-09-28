# CI plan role: what the compliance-check job needs, and nothing it doesn't.
#
# The compliance-check job (terraform plan + the OPA gate) runs on every pull
# request and on pushes to main. It used to assume the deploy role, whose trust
# therefore had to include `pull_request`: any PR run received the full deploy
# permission set (including iam:PutRolePolicy/PassRole on a Lambda role and
# Lambda code updates) without passing the `prod` environment approval that
# gates the deploy job. Fork PRs cannot mint OIDC tokens on a public repo, so the
# exposure was limited to people with write access, but the approval gate is
# only meaningful if nothing reaches deploy credentials around it.
#
# This role is the plan-only half:
#   - reads the live account (terraform plan refreshes every managed resource),
#   - reads the one state object and takes/releases the state lock,
#   - cannot read data it has no use for (object contents, log events, secret
#     values, queue messages) — explicit denies over ReadOnlyAccess, and
#   - cannot write anything except the lock table's lock item.
#
# Cutover order (each step verifiable before the next):
#   1. apply this role; set the repo variable AWS_PLAN_ROLE_ARN;
#   2. switch compliance-check to AWS_PLAN_ROLE_ARN (its own PR run proves it);
#   3. narrow the deploy role's trust to environment:prod only.

data "aws_iam_policy_document" "plan_trust" {
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
        # compliance-check on pull requests,
        "repo:${var.github_repo}:pull_request",
        # and on pushes to main (no environment, so the sub is ref-scoped).
        "repo:${var.github_repo}:ref:refs/heads/main",
      ]
    }
  }
}

resource "aws_iam_role" "plan" {
  name                 = "github-actions-plan-oidc"
  description          = "CI plan role (compliance-check): read-only account access plus the Terraform state lock. No deploy permissions."
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600

  tags = merge(local.bootstrap_tags, local.bootstrap_cls.identity_secrets_internal, { Name = "github-actions-plan-oidc" })
}

# terraform plan refreshes every resource in the main stack (S3, CloudFront,
# Lambda, API Gateway, Cognito, KMS, Route 53 DNSSEC, IAM, SNS, CloudWatch,
# CloudTrail, SQS, Secrets Manager metadata). ReadOnlyAccess covers all of those
# Get/Describe/List calls; the deny below removes its data-plane reads.
resource "aws_iam_role_policy_attachment" "plan_read_only" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "plan_access" {
  statement {
    sid       = "StateBucketList"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.tfstate.arn]
  }

  statement {
    sid       = "StateObjectRead"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.tfstate.arn}/${local.tfstate_key}"]
  }

  statement {
    sid       = "StateLock"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
    resources = [aws_dynamodb_table.tflock.arn]
  }

  # Planning never needs object contents other than the state file.
  statement {
    sid           = "DenyObjectReadsOutsideState"
    effect        = "Deny"
    actions       = ["s3:GetObject", "s3:GetObjectVersion"]
    not_resources = ["${aws_s3_bucket.tfstate.arn}/${local.tfstate_key}"]
  }

  # Planning never needs table contents other than the lock item.
  statement {
    sid           = "DenyTableReadsOutsideLock"
    effect        = "Deny"
    actions       = ["dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan"]
    not_resources = [aws_dynamodb_table.tflock.arn]
  }

  # Data-plane reads ReadOnlyAccess would otherwise allow. Receiving from the
  # compliance DLQ would also consume its messages.
  statement {
    sid    = "DenyDataPlaneReads"
    effect = "Deny"
    actions = [
      "logs:GetLogEvents",
      "logs:FilterLogEvents",
      "logs:StartQuery",
      "logs:GetQueryResults",
      "secretsmanager:GetSecretValue",
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
      "sqs:ReceiveMessage",
      "kms:Decrypt",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "plan_access" {
  # checkov:skip=CKV_AWS_356:The only "*" resources are Deny statements over data-plane read actions; every Allow is scoped to the state object or lock table.
  name   = "plan-state-and-data-denies"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.plan_access.json
}

output "plan_role_arn" {
  description = "Set as the repository variable AWS_PLAN_ROLE_ARN for the compliance-check job"
  value       = aws_iam_role.plan.arn
}
