# =============================================================================
# EVIDENCE SLA WATCHDOG  (CA-7, SI-4, IR-6)
# =============================================================================
# Published compliance reporting must be under 24 hours old. From 2026-09-09 to
# 2026-09-24 the unattended nightly refresh failed every night, and the only
# signal was a GitHub issue sitting in a notifications tab. This pages the
# operator by email instead, from AWS's clock rather than GitHub's, so it also
# catches the case the nightly cannot see from the inside: its cron being
# disabled.
#
#   hourly EventBridge rule -> watchdog Lambda
#     reads vdr-report.json, ksi-signal-runtime.json and the nightly's status
#     beacon (vdr-status.json) straight from the site bucket
#     -> CloudWatch metrics (Samaydlette/Evidence)
#     -> three alarms -> SNS topic (CMK-encrypted) -> operator email
#
# The Lambda makes AWS API calls only. It has no internet egress, so the
# "Lambda egress is to AWS APIs only" statements in the SSP and the POAM-010
# rationale stay true.
#
# The email subscription is deliberately NOT managed here: an address in
# Terraform lands in state and in the uploaded plan artifact of a public repo.
# It is created once, out of band (docs/runbooks/evidence-sla-alarm.md).
#
# Cost: three standard alarms plus three custom metrics, roughly $0.80/month.
# SNS email at this volume and 720 short invocations a month are within free
# tiers.
# =============================================================================

locals {
  watchdog_enabled   = var.create_evidence_watchdog && var.create_lambda_compliance
  watchdog_name      = "${replace(var.domain_name, ".", "-")}-evidence-watchdog"
  watchdog_namespace = "Samaydlette/Evidence"
  watchdog_alerts    = "${replace(var.domain_name, ".", "-")}-evidence-alerts"
  watchdog_runbook   = "https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/runbooks/evidence-sla-alarm.md"

  watchdog_tags = {
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  }

  # Each alarm pages when its metric breaches in 2 of the last 3 hourly periods.
  # Missing data counts as breaching, so a dead watchdog pages too.
  watchdog_alarms = {
    "vdr-age" = {
      metric    = "VdrAgeHours"
      threshold = 24
      summary   = "The published vulnerability report (VDR) is more than 24 hours old: the reporting policy is breached."
    }
    "runtime-age" = {
      metric    = "RuntimeSignalAgeHours"
      threshold = 26
      summary   = "The daily runtime check has not published a signal in more than 26 hours."
    }
    "nightly-failed" = {
      metric    = "NightlyFailed"
      threshold = 0
      summary   = "The evidence nightly failed, or has not reported in more than 26 hours. The alert issue on GitHub names the gate and the findings."
    }
  }
}

data "archive_file" "evidence_watchdog" {
  count       = local.watchdog_enabled ? 1 : 0
  type        = "zip"
  source_dir  = "${path.module}/watchdog"
  output_path = "${path.module}/evidence-watchdog.zip"
}

resource "aws_iam_role" "evidence_watchdog" {
  count = local.watchdog_enabled ? 1 : 0
  name  = "${local.watchdog_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = merge(local.cls.identity_secrets_internal, local.watchdog_tags, {
    Name = "${local.watchdog_name}-role"
  })
}

# Least privilege: read three named objects, write metrics to one namespace,
# write its own logs, decrypt its own env, and dead-letter a failed invocation.
resource "aws_iam_role_policy" "evidence_watchdog" {
  count = local.watchdog_enabled ? 1 : 0
  name  = "${local.watchdog_name}-policy"
  role  = aws_iam_role.evidence_watchdog[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteOwnLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.evidence_watchdog[0].arn}:*"
      },
      {
        Sid    = "ReadPublishedEvidence"
        Effect = "Allow"
        Action = "s3:GetObject"
        Resource = [
          "${data.aws_s3_bucket.website.arn}/.well-known/vdr-report.json",
          "${data.aws_s3_bucket.website.arn}/.well-known/ksi-signal-runtime.json",
          "${data.aws_s3_bucket.website.arn}/.well-known/vdr-status.json",
        ]
      },
      {
        # PutMetricData has no resource-level scoping; the namespace condition is
        # the scope AWS offers for it.
        Sid       = "PublishEvidenceMetrics"
        Effect    = "Allow"
        Action    = "cloudwatch:PutMetricData"
        Resource  = "*"
        Condition = { StringEquals = { "cloudwatch:namespace" = local.watchdog_namespace } }
      },
      {
        Sid      = "DecryptOwnEnvironment"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.at_rest.arn
      },
      {
        Sid      = "DeadLetterFailedRuns"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.compliance_dlq[0].arn
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "evidence_watchdog" {
  count             = local.watchdog_enabled ? 1 : 0
  name              = "/aws/lambda/${local.watchdog_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.at_rest.arn

  tags = merge(local.cls.security_tooling, local.watchdog_tags, {
    Name = "${var.domain_name}-evidence-watchdog-logs"
  })
}

resource "aws_lambda_function" "evidence_watchdog" {
  count = local.watchdog_enabled ? 1 : 0

  filename         = data.archive_file.evidence_watchdog[0].output_path
  source_code_hash = data.archive_file.evidence_watchdog[0].output_base64sha256
  function_name    = local.watchdog_name
  role             = aws_iam_role.evidence_watchdog[0].arn
  handler          = "index.handler"
  runtime          = "nodejs22.x"
  timeout          = 30
  memory_size      = 128

  # Same controls as the compliance Lambda: CMK-encrypted environment (POAM-011)
  # and a dead-letter queue for failed async invocations (POAM-013). It shares
  # the compliance DLQ rather than adding a second queue.
  kms_key_arn = aws_kms_key.at_rest.arn
  dead_letter_config {
    target_arn = aws_sqs_queue.compliance_dlq[0].arn
  }

  environment {
    variables = {
      S3_BUCKET        = data.aws_s3_bucket.website.id
      METRIC_NAMESPACE = local.watchdog_namespace
    }
  }

  depends_on = [aws_cloudwatch_log_group.evidence_watchdog, aws_kms_alias.at_rest]

  tags = merge(local.cls.security_tooling, local.watchdog_tags, {
    Name = local.watchdog_name
  })
}

resource "aws_cloudwatch_event_rule" "evidence_watchdog" {
  count               = local.watchdog_enabled ? 1 : 0
  name                = local.watchdog_name
  description         = "Hourly check that published compliance evidence is fresh"
  schedule_expression = "rate(1 hour)"

  tags = merge(local.cls.internal_tooling_low, local.watchdog_tags, {
    Name = local.watchdog_name
  })
}

resource "aws_cloudwatch_event_target" "evidence_watchdog" {
  count     = local.watchdog_enabled ? 1 : 0
  rule      = aws_cloudwatch_event_rule.evidence_watchdog[0].name
  target_id = "EvidenceWatchdog"
  arn       = aws_lambda_function.evidence_watchdog[0].arn
}

resource "aws_lambda_permission" "evidence_watchdog" {
  count         = local.watchdog_enabled ? 1 : 0
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.evidence_watchdog[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.evidence_watchdog[0].arn
}

# CMK-encrypted, not alias/aws/sns: the AWS-managed SNS key's policy does not let
# CloudWatch alarms use it, so alarm delivery would fail silently. The at-rest
# key's policy carries the matching cloudwatch.amazonaws.com grant (main.tf).
resource "aws_sns_topic" "evidence_alerts" {
  count             = local.watchdog_enabled ? 1 : 0
  name              = local.watchdog_alerts
  kms_master_key_id = aws_kms_key.at_rest.arn

  tags = merge(local.cls.security_tooling, local.watchdog_tags, {
    Name = local.watchdog_alerts
  })
}

# Account-owner access (the SNS default), plus publish for this account's
# evidence alarms only, scoped with aws:SourceArn and aws:SourceAccount per the
# CloudWatch confused-deputy guidance.
resource "aws_sns_topic_policy" "evidence_alerts" {
  count = local.watchdog_enabled ? 1 : 0
  arn   = aws_sns_topic.evidence_alerts[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountOwnerAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action = [
          "SNS:GetTopicAttributes", "SNS:SetTopicAttributes", "SNS:AddPermission",
          "SNS:RemovePermission", "SNS:DeleteTopic", "SNS:Subscribe",
          "SNS:ListSubscriptionsByTopic", "SNS:Publish",
        ]
        Resource  = aws_sns_topic.evidence_alerts[0].arn
        Condition = { StringEquals = { "AWS:SourceOwner" = data.aws_caller_identity.current.account_id } }
      },
      {
        Sid       = "EvidenceAlarmsPublish"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.evidence_alerts[0].arn
        Condition = {
          ArnLike      = { "aws:SourceArn" = "arn:aws:cloudwatch:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alarm:${local.watchdog_name}-*" }
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
    ]
  })
}

resource "aws_cloudwatch_metric_alarm" "evidence" {
  for_each = local.watchdog_enabled ? local.watchdog_alarms : {}

  alarm_name        = "${local.watchdog_name}-${each.key}"
  alarm_description = "${each.value.summary} Runbook: ${local.watchdog_runbook}"
  namespace         = local.watchdog_namespace
  metric_name       = each.value.metric
  statistic         = "Maximum"
  period            = 3600
  # Page when 2 of the last 3 hourly datapoints breach, tolerating one late or
  # lost run. Missing data is a breach: a watchdog that stops reporting pages.
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = each.value.threshold
  treat_missing_data  = "breaching"

  # OK actions too: a recovery email closes the loop.
  alarm_actions = [aws_sns_topic.evidence_alerts[0].arn]
  ok_actions    = [aws_sns_topic.evidence_alerts[0].arn]

  tags = merge(local.cls.security_tooling, local.watchdog_tags, {
    Name = "${local.watchdog_name}-${each.key}"
  })
}
