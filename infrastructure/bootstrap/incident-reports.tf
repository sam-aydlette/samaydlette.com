# =============================================================================
# BOOTSTRAP: GitHub OIDC role for unattended incident reporting (IEC-CSO-AIR)
# =============================================================================
# Operator-applied (not CI), like everything else in this stack.
#
# WHY A ROLE OF ITS OWN. FedRAMP's Class C incident report clocks are hours (an
# Initial Incident Report within one hour for N3-N5, an Ongoing report every
# six). The deploy role sits behind the `prod` reviewer and cannot keep them,
# and the evidence nightly's role is scoped to `.well-known/vdr-*` on purpose:
# widening it to carry incident reports would make the VDR refresh's grant
# about something else. `.github/workflows/incident-reports.yml` runs in its
# own GitHub Environment with no required reviewer and assumes this role.
#
# THE WHOLE PERMISSION SET: PutObject under `.well-known/incident-*` and a CDN
# invalidation. No delete (an unattended job never unpublishes evidence), no
# read of any kind (the workflow verifies its publish through the public URL),
# no Terraform state, no website sync. The bucket default-encrypts with SSE-S3,
# so no KMS grant is involved. If a future change needs more, re-examine
# whether that work belongs on the unattended path before widening this.
# =============================================================================

variable "incident_reports_environment" {
  type        = string
  description = "GitHub Environment the incident reports workflow runs in. No required reviewer; the role it grants is scoped to .well-known/incident-*."
  default     = "incident-reports"
}

# TRUST: this repository, two GitHub Environments, nothing else. A pull request
# cannot assume it, and neither can a workflow that does not declare one of
# them. The second is the reviewer-gated deploy environment: every deploy
# assumes this role before it builds the SDR (scripts/check-incident-role.py),
# so a deploy cannot publish records claiming a publisher whose role does not
# work. That adds no privilege: the deploy role can already write the bucket.
data "aws_iam_policy_document" "incident_reports_trust" {
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
      values = [
        "repo:${var.github_repo}:environment:${var.incident_reports_environment}",
        "repo:${var.github_repo}:environment:${var.deploy_environment}",
      ]
    }
  }
}

resource "aws_iam_role" "incident_reports" {
  name                 = "github-actions-incident-reports-oidc"
  description          = "Unattended incident reporting (IEC-CSO-AIR). PutObject under .well-known/incident-* and a CDN invalidation; nothing else."
  assume_role_policy   = data.aws_iam_policy_document.incident_reports_trust.json
  max_session_duration = 3600

  tags = merge(local.bootstrap_tags, local.bootstrap_cls.identity_secrets_internal, { Name = "github-actions-incident-reports-oidc" })
}

data "aws_iam_policy_document" "incident_reports_publish" {
  statement {
    sid       = "PublishIncidentReportsOnly"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${var.domain_name}/.well-known/incident-*"]
  }
}

resource "aws_iam_role_policy" "incident_reports_publish" {
  name   = "incident-reports-publish"
  role   = aws_iam_role.incident_reports.id
  policy = data.aws_iam_policy_document.incident_reports_publish.json
}

data "aws_iam_policy_document" "incident_reports_cdn" {
  statement {
    sid       = "InvalidateIncidentPaths"
    effect    = "Allow"
    actions   = ["cloudfront:CreateInvalidation"]
    resources = [aws_cloudfront_distribution.website.arn]
  }
}

resource "aws_iam_role_policy" "incident_reports_cdn" {
  name   = "incident-reports-cdn"
  role   = aws_iam_role.incident_reports.id
  policy = data.aws_iam_policy_document.incident_reports_cdn.json
}

output "incident_reports_role_arn" {
  value       = aws_iam_role.incident_reports.arn
  description = "Set as the repository variable AWS_INCIDENT_REPORTS_ROLE_ARN, which incident-reports.yml passes to configure-aws-credentials."
}
