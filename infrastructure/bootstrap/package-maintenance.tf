# =============================================================================
# BOOTSTRAP: GitHub OIDC role for unattended certification package maintenance
# =============================================================================
# Operator-applied (not CI), like everything else in this stack.
#
# WHY A ROLE OF ITS OWN. CPO-CSX-CPM (Class C) requires the certification
# package to be up to date at least every two weeks, and SDR-CSX-KMT wants a
# metric point for every day; the quarterly Ongoing Certification Report must
# be issued and the package snapshotted on its calendar date (CCM-OCR-SOR,
# CDS-CSO-HAD). The deploy role sits behind the `prod` reviewer and cannot keep
# any of those dates, and the evidence nightly's role is scoped to
# `.well-known/vdr-*` on purpose. `.github/workflows/package-maintenance.yml`
# runs daily in its own GitHub Environment with no required reviewer, rebuilds
# the CPO, SDR and OCR at the deployed commit from the published, signature-
# verified inputs, and assumes this role to publish them.
#
# THE WHOLE PERMISSION SET: PutObject on the named package objects and the
# quarterly issue and review prefixes, and a CDN invalidation. No delete (an unattended job
# never unpublishes evidence), no read of any kind (the workflow verifies through
# the public URL), no Terraform state, no website sync, no other object. The
# bucket default-encrypts with SSE-S3, so no KMS grant is involved. If a future
# change needs more, re-examine whether that work belongs on the unattended path
# before widening this. The incident-reports role (incident-reports.tf) has the
# same shape; the two could be merged later if the operator prefers one.
# =============================================================================

variable "package_maintenance_environment" {
  type        = string
  description = "GitHub Environment the package maintenance workflow runs in. No required reviewer; the role it grants writes only the certification package objects."
  default     = "package-maintenance"
}

locals {
  # Exactly what package-maintenance.yml publishes. tests/test_certification_cycle.py
  # holds this list equal to the workflow's publish step.
  package_maintenance_keys = [
    ".well-known/security-decision-record.json",
    ".well-known/security-decision-record.bundle",
    ".well-known/security-decision-record.md",
    ".well-known/security-decision-record.view.md",
    ".well-known/security-decision-record.json.intoto.jsonl",
    ".well-known/certification-package-overview.json",
    ".well-known/certification-package-overview.bundle",
    ".well-known/certification-package-overview.md",
    ".well-known/certification-package-overview.view.md",
    ".well-known/ongoing-certification-report.json",
    ".well-known/ongoing-certification-report.bundle",
    ".well-known/ongoing-certification-report.md",
    ".well-known/ongoing-certification-report.view.md",
    ".well-known/quarterly-review.ics",
    ".well-known/ocr-issues.json",
    ".well-known/ocr-issues.view.md",
    ".well-known/ocr-issues.bundle",
    ".well-known/ocr-issue-*",
    ".well-known/quarterly-reviews.json",
    ".well-known/quarterly-reviews.view.md",
    ".well-known/quarterly-reviews.bundle",
    ".well-known/quarterly-review-*",
    ".well-known/snapshot-*",
    ".well-known/snapshots/*",
  ]
}

# TRUST: this repository, this GitHub Environment, nothing else. A pull request
# cannot assume it, and neither can a workflow that does not declare the
# environment.
data "aws_iam_policy_document" "package_maintenance_trust" {
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
      values   = ["repo:${var.github_repo}:environment:${var.package_maintenance_environment}"]
    }
  }
}

resource "aws_iam_role" "package_maintenance" {
  name                 = "github-actions-package-maintenance-oidc"
  description          = "Unattended certification package maintenance (CPO-CSX-CPM). PutObject on the CPO, SDR, OCR, quarterly issue and review objects, and a CDN invalidation; nothing else."
  assume_role_policy   = data.aws_iam_policy_document.package_maintenance_trust.json
  max_session_duration = 3600

  tags = merge(local.bootstrap_tags, local.bootstrap_cls.identity_secrets_internal, { Name = "github-actions-package-maintenance-oidc" })
}

data "aws_iam_policy_document" "package_maintenance_publish" {
  statement {
    sid       = "PublishCertificationPackageOnly"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = [for k in local.package_maintenance_keys : "arn:aws:s3:::${var.domain_name}/${k}"]
  }
}

resource "aws_iam_role_policy" "package_maintenance_publish" {
  name   = "package-maintenance-publish"
  role   = aws_iam_role.package_maintenance.id
  policy = data.aws_iam_policy_document.package_maintenance_publish.json
}

data "aws_iam_policy_document" "package_maintenance_cdn" {
  statement {
    sid       = "InvalidatePackagePaths"
    effect    = "Allow"
    actions   = ["cloudfront:CreateInvalidation"]
    resources = [aws_cloudfront_distribution.website.arn]
  }
}

resource "aws_iam_role_policy" "package_maintenance_cdn" {
  name   = "package-maintenance-cdn"
  role   = aws_iam_role.package_maintenance.id
  policy = data.aws_iam_policy_document.package_maintenance_cdn.json
}

output "package_maintenance_role_arn" {
  value       = aws_iam_role.package_maintenance.arn
  description = "Set as the repository variable AWS_PACKAGE_MAINTENANCE_ROLE_ARN, which package-maintenance.yml passes to configure-aws-credentials."
}
