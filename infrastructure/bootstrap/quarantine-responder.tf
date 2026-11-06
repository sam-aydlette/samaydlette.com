# =============================================================================
# BOOTSTRAP: the quarantine responder (KSI-IAM-SUS; AC-2(3), AC-2(13), IR-4)
# =============================================================================
# Operator-applied (not CI), like everything else in this stack.
#
# WHAT IT DOES. The nightly audit-log review (scripts/audit-log-review.py)
# evaluates unexpected CloudTrail writes; when one is evaluated a possible
# FedRAMP Reportable Incident and names an IAM user or role, the responder
# (scripts/_quarantine.py) attaches AWS's managed deny-all policy to that
# principal and pages the operator. Every night it also drills the response
# against the permissionless stand-in role below: attach, read back, detach,
# read back.
#
# WHY A MANAGED POLICY, NOT AN INLINE ONE. IAM has no condition key for an
# inline policy's name or document. A role allowed iam:PutRolePolicy could
# write any inline policy, including an Allow of everything, on any role it
# reaches: an administrator in all but name. Attach and detach can be
# conditioned on iam:PolicyARN, so this role can attach exactly one policy,
# AWS's AWSDenyAll, which only ever takes permissions away. AWS owns that
# policy's document; nothing in this account can change it.
#
# WHAT IT CAN NEVER DO. Touch itself or the CI/CD trust root (explicit Deny),
# touch a group or anything that is not a role or user (explicit Deny with
# NotResource), write any policy document, assume another role, or read or
# write data. Its blast radius is denial of service: it can switch off a
# non-trust-root role or user, which is the point. A person removes a real
# quarantine (docs/incident-response.md).
#
# WHO CAN USE IT. Only a job in the evidence-nightly GitHub Environment (no PR,
# no other workflow environment), with the session name the nightly's audit-log
# step uses. GitHub's OIDC subject carries the environment, not the step: that
# only the audit-log step assumes it is the workflow's own (reviewed) code, and
# the session name is a label the caller chooses, which makes the step's
# CloudTrail records attributable rather than adding a security boundary. The
# role writes its credentials to a named profile that the step deletes.
#
# The deploy reads this role's trust and policy and compares them with the
# Secure Configuration Guide (ci-roles.responder-trust, ci-roles.responder-
# scope, ci-roles.quarantine-target-trust), so a deploy stops before the SDR is
# built while this file is not applied.
# =============================================================================

locals {
  quarantine_policy_arn  = "arn:aws:iam::aws:policy/AWSDenyAll"
  quarantine_actions     = ["iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:AttachUserPolicy", "iam:DetachUserPolicy"]
  quarantine_alert_topic = "arn:aws:sns:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${local.domain_dashed}-evidence-alerts"
}

data "aws_iam_policy_document" "quarantine_responder_trust" {
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

    condition {
      test     = "StringEquals"
      variable = "sts:RoleSessionName"
      values   = ["audit-log-quarantine-responder"]
    }
  }
}

resource "aws_iam_role" "quarantine_responder" {
  name                 = "github-actions-quarantine-responder-oidc"
  description          = "Nightly audit-log review's quarantine responder: attaches or detaches AWSDenyAll on a role or user, never on itself or the CI/CD trust root."
  assume_role_policy   = data.aws_iam_policy_document.quarantine_responder_trust.json
  max_session_duration = 3600

  tags = merge(local.bootstrap_tags, local.bootstrap_cls.identity_secrets_internal, { Name = "github-actions-quarantine-responder-oidc" })
}

data "aws_iam_policy_document" "quarantine_responder" {
  # Attach or detach exactly AWSDenyAll, on a role or a user.
  statement {
    sid       = "QuarantineWithDenyAllOnly"
    effect    = "Allow"
    actions   = local.quarantine_actions
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*", "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]

    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"
      values   = [local.quarantine_policy_arn]
    }
  }

  # Read the attachment back (the drill's verify, and a real quarantine's).
  statement {
    sid       = "ReadQuarantineBack"
    effect    = "Allow"
    actions   = ["iam:ListAttachedRolePolicies", "iam:ListAttachedUserPolicies"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*", "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]
  }

  # Page the operator on the evidence-alerts topic (infrastructure/watchdog.tf),
  # which is encrypted with the at-rest CMK: data keys only through SNS, only
  # for that topic.
  statement {
    sid       = "PageOperator"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [local.quarantine_alert_topic]
  }

  statement {
    sid       = "PageThroughEncryptedTopic"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["arn:aws:kms:${var.aws_region}:${data.aws_caller_identity.current.account_id}:key/*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["sns.${var.aws_region}.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:sns:topicArn"
      values   = [local.quarantine_alert_topic]
    }
  }

  # Never itself, never the CI/CD trust root.
  statement {
    sid     = "NeverTheTrustRoot"
    effect  = "Deny"
    actions = local.quarantine_actions
    resources = [
      aws_iam_role.quarantine_responder.arn,
      aws_iam_role.deploy.arn,
      aws_iam_role.plan.arn,
      aws_iam_role.evidence_nightly.arn,
      aws_iam_role.package_maintenance.arn,
      aws_iam_role.incident_reports.arn,
    ]
  }

  # Nothing that is not a role or a user.
  statement {
    sid           = "OnlyRolesAndUsers"
    effect        = "Deny"
    actions       = local.quarantine_actions
    not_resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*", "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]
  }
}

resource "aws_iam_role_policy" "quarantine_responder" {
  name   = "quarantine-responder"
  role   = aws_iam_role.quarantine_responder.name
  policy = data.aws_iam_policy_document.quarantine_responder.json
}

# The drill's stand-in principal. No permissions at all, and the only principal
# its trust names is the responder, which holds no sts:AssumeRole: nobody can
# assume it. The responder quarantines and releases it every night.
data "aws_iam_policy_document" "quarantine_target_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.quarantine_responder.arn]
    }
  }
}

resource "aws_iam_role" "quarantine_target" {
  name                 = "${local.domain_dashed}-quarantine-target"
  description          = "Stand-in principal for the nightly quarantine drill. No permissions; nobody can assume it."
  assume_role_policy   = data.aws_iam_policy_document.quarantine_target_trust.json
  max_session_duration = 3600

  tags = merge(local.bootstrap_tags, local.bootstrap_cls.identity_secrets_internal, { Name = "${local.domain_dashed}-quarantine-target" })
}

output "quarantine_responder_role_arn" {
  value       = aws_iam_role.quarantine_responder.arn
  description = "Set as the repository variable AWS_QUARANTINE_RESPONDER_ROLE_ARN, which evidence-nightly.yml passes to configure-aws-credentials (profile only)."
}
