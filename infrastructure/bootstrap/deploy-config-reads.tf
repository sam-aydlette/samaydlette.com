# =============================================================================
# Secure-configuration reads for the deploy role (SCG-ENH-CMP / SCG-ENH-EXP)
# =============================================================================
# scripts/check-secure-config.py runs in the deploy, before the Security
# Decision Record is built, and compares the live settings of the top-level and
# privileged accounts with the Secure Configuration Guide's recommended defaults
# (data/secure-configuration.json). These are the read-only calls it makes that
# the deploy role does not already hold. Every action is a read; none returns a
# secret value or credential (list-access-keys returns key metadata only, never
# a secret key). Until this is applied, the check fails with AccessDenied and
# the deploy stops before publishing, which is the intended fail-closed path.
# Operator-applied with the rest of infrastructure/bootstrap.
# =============================================================================

data "aws_iam_policy_document" "deploy_config_reads" {
  # checkov:skip=CKV_AWS_356:GetAccountSummary, GetAccountPasswordPolicy, ListUsers, ListVirtualMFADevices and s3:GetAccountPublicAccessBlock are account-level reads that do not support resource-level scoping; the user, group and role reads are scoped by ARN. Read-only; documented exception.
  statement {
    sid    = "AccountLevelReads"
    effect = "Allow"
    actions = [
      "iam:GetAccountSummary",
      "iam:GetAccountPasswordPolicy",
      "iam:ListUsers",
      "iam:ListVirtualMFADevices",
      "s3:GetAccountPublicAccessBlock",
    ]
    resources = ["*"]
  }
  statement {
    sid    = "UserAndGroupReads"
    effect = "Allow"
    actions = [
      "iam:ListGroupsForUser",
      "iam:ListAttachedUserPolicies",
      "iam:ListUserPolicies",
      "iam:GetUserPolicy",
      "iam:GetLoginProfile",
      "iam:ListMFADevices",
      "iam:ListAccessKeys",
      "iam:ListAttachedGroupPolicies",
      "iam:ListGroupPolicies",
      "iam:GetGroupPolicy",
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:group/*",
    ]
  }
  statement {
    sid     = "CiRoleTrustReads"
    effect  = "Allow"
    actions = ["iam:GetRole"]
    resources = [
      aws_iam_role.deploy.arn,
      aws_iam_role.plan.arn,
      aws_iam_role.evidence_nightly.arn,
      aws_iam_role.package_maintenance.arn,
      aws_iam_role.incident_reports.arn,
    ]
  }
  # The package maintainer's write scope (ci-roles.maintenance-publish-scope):
  # its one publish policy, read to confirm it covers every object the workflow
  # puts. And the nightly's audit-log read (ci-roles.nightly-audit-reads): its
  # cloudtrail:LookupEvents policy. Until these are applied, the comparison
  # fails the deploy before the SDR is built.
  statement {
    sid       = "MaintainerScopeRead"
    effect    = "Allow"
    actions   = ["iam:GetRolePolicy"]
    resources = [aws_iam_role.package_maintenance.arn, aws_iam_role.evidence_nightly.arn]
  }
}

resource "aws_iam_role_policy" "deploy_config_reads" {
  # checkov:skip=CKV_AWS_356:Account-level IAM and S3 reads cannot be resource-scoped; user, group and role reads are ARN-scoped. Read-only; documented exception.
  name   = "secure-configuration-reads"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy_config_reads.json
}
