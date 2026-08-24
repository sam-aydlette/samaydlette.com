# =============================================================================
# BOOTSTRAP: GitHub OIDC role for the unattended nightly evidence refresh
# =============================================================================
# Operator-applied (not CI), like everything else in this stack.
#
# WHY A SECOND ROLE AT ALL. The published compliance reporting has to be under
# 24 hours old, and the deploy role cannot do that job: the deploy job is bound
# to the `prod` GitHub Environment behind a human reviewer, precisely because it
# runs `terraform apply` over the whole stack. Something has to be able to
# refresh the vulnerability report while nobody is awake.
#
# THE TRADE THIS ENCODES. `.github/workflows/evidence-nightly.yml` runs in a
# GitHub Environment with NO required reviewer — an unattended production write.
# What makes that acceptable is the size of it: this role replaces "unattended
# `terraform apply` over every resource in the account" with "unattended
# PutObject under one S3 key prefix". It cannot apply Terraform (it has no
# Terraform state access and no resource-mutating permission of any kind), it
# cannot sync the website, and it cannot write a single object outside
# `.well-known/vdr-*`. Everything else it can do is read-only.
#
# The scope below is the whole permission set, and it is short on purpose. If a
# future change to the nightly workflow needs a permission that is not here,
# that is a signal to re-examine whether the work belongs on the unattended path
# at all — not to widen this policy.
# =============================================================================

variable "evidence_nightly_environment" {
  type        = string
  description = "GitHub Environment the nightly evidence refresh runs in. Deliberately has no required reviewer; the role it grants is scoped to a single S3 prefix."
  default     = "evidence-nightly"
}

# -----------------------------------------------------------------------------
# TRUST: this repository, this GitHub Environment, nothing else
# -----------------------------------------------------------------------------
# Narrower than the deploy role's trust policy, which also admits main-branch
# refs and pull requests. This one admits exactly one subject: a job running in
# the evidence-nightly environment. A pull request cannot assume it, and neither
# can a workflow that forgets to declare the environment.
data "aws_iam_policy_document" "evidence_nightly_trust" {
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
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:environment:${var.evidence_nightly_environment}"]
    }
  }
}

resource "aws_iam_role" "evidence_nightly" {
  name                 = "github-actions-evidence-nightly-oidc"
  description          = "Unattended nightly VDR refresh. PutObject under .well-known/vdr-* plus read-only reconciliation reads. No Terraform, no website sync."
  assume_role_policy   = data.aws_iam_policy_document.evidence_nightly_trust.json
  max_session_duration = 3600
}

# -----------------------------------------------------------------------------
# WRITE: five objects under one prefix, and nothing else in the bucket
# -----------------------------------------------------------------------------
# The published set the nightly refreshes is vdr-report.json, vdr-report.bundle,
# vdr-report.md, vdr-trend.json and vdr-trend.bundle. The resource pattern is
# the prefix rather than five literal keys so that adding a vdr-* artifact does
# not need an IAM change, while the KSI signal, the OSCAL SSP and POA&M, the
# IIW, the SCuBA bundle, the provenance attestations and every byte of website
# content stay out of reach.
#
# No s3:DeleteObject: an unattended job should never be able to unpublish
# evidence. No s3:GetObject either — the workflow verifies its own publish by
# fetching the public URL through CloudFront, which is both a stronger check
# (it proves what a third party would actually receive) and one less grant.
# The bucket default-encrypts with SSE-S3, so no KMS permission is involved.
data "aws_iam_policy_document" "evidence_nightly_publish" {
  statement {
    sid     = "PublishVdrArtifactsOnly"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "arn:aws:s3:::${var.domain_name}/.well-known/vdr-*",
    ]
  }
}

resource "aws_iam_role_policy" "evidence_nightly_publish" {
  name   = "evidence-nightly-publish"
  role   = aws_iam_role.evidence_nightly.id
  policy = data.aws_iam_policy_document.evidence_nightly_publish.json
}

# -----------------------------------------------------------------------------
# CDN: invalidate the paths it just wrote
# -----------------------------------------------------------------------------
# CreateInvalidation only. Deliberately not GetInvalidation: the workflow polls
# the public edge for the bytes it published instead of asking the CDN control
# plane whether it believes it has finished, which needs no permission and
# verifies the thing that actually matters.
data "aws_iam_policy_document" "evidence_nightly_cdn" {
  statement {
    sid       = "InvalidateRefreshedPaths"
    effect    = "Allow"
    actions   = ["cloudfront:CreateInvalidation"]
    resources = [aws_cloudfront_distribution.website.arn]
  }
}

resource "aws_iam_role_policy" "evidence_nightly_cdn" {
  name   = "evidence-nightly-cdn"
  role   = aws_iam_role.evidence_nightly.id
  policy = data.aws_iam_policy_document.evidence_nightly_cdn.json
}

# -----------------------------------------------------------------------------
# READ: exactly what the reconciliation gate's --live sweep calls
# -----------------------------------------------------------------------------
# Invariant (a) enumerates live in-boundary resources and fails if any is absent
# from the canonical inventory; invariant (i) reads their tags and fails if the
# values disagree with the inventory's classification. Both are read-only and
# metadata-only — no secretsmanager:GetSecretValue, no object reads, no writes.
#
# This mirrors the deploy role's reconcile-gate-readonly policy action for
# action. It must stay in step with enumerate_live_arns() and
# enumerate_live_tags() in scripts/reconcile.py: the gate raises on any CLI
# failure rather than treating a denied call as "no drift", so a missing grant
# fails the nightly closed rather than silently weakening the check. The one
# exception is tag:GetResources, which the gate degrades on with a loud warning.
data "aws_iam_policy_document" "evidence_nightly_reconcile_reads" {
  # checkov:skip=CKV_AWS_356:Read-only account-enumeration actions (List*/Describe*/apigateway:GET) cannot be resource-scoped; the Action list is explicit and read-only, no write or admin. Same documented exception as the deploy role's reconcile-gate-readonly policy.
  statement {
    sid    = "ReconciliationGateReads"
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
      "tag:GetResources",
    ]
    # Resource "*" is required: these are account-wide enumeration actions that
    # do not support resource-level scoping. The Action list is explicit and
    # read-only — no wildcard action, no write, no admin.
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "evidence_nightly_reconcile_reads" {
  # checkov:skip=CKV_AWS_356:Read-only account-enumeration actions cannot be resource-scoped; explicit read-only Action list, no write or admin. Documented false positive.
  name   = "evidence-nightly-reconcile-readonly"
  role   = aws_iam_role.evidence_nightly.id
  policy = data.aws_iam_policy_document.evidence_nightly_reconcile_reads.json
}

output "evidence_nightly_role_arn" {
  value       = aws_iam_role.evidence_nightly.arn
  description = "Set as the repository variable AWS_EVIDENCE_NIGHTLY_ROLE_ARN, which evidence-nightly.yml passes to configure-aws-credentials."
}
