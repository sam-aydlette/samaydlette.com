# =============================================================================
# FEDRAMP SECURITY INBOX  (AFC-CSO-INB, TFG, RCV, CRA, EMR, IMA, ACK; SI-5, IR-6)
# =============================================================================
# The address FedRAMP writes to. One value, in data/cds/offering.json
# (fedramp_security_inbox.address); this file, the CPO and the change-notice
# check (scripts/check-fsi-notice.py, AFC-CSO-NOC) all read it from there.
#
#   Internet -> MX (Route 53) -> SES receiving, us-east-2
#     receipt rule (one recipient: the inbox address; spam/virus scan on, TLS
#     optional, nothing that can bounce, stop or drop):
#       1. S3 action: the raw message into the inbox bucket (CMK-encrypted)
#       2. Lambda action (async): fedramp-inbox function
#            FedRAMP sender (@fedramp.gov, @gsa.gov)?
#              register record (the bucket's register/ prefix, no body)
#              acknowledgement to the sender (SES, from the inbox address)
#              page to the operator (the evidence-alert SNS topic)
#            otherwise: left in the bucket, logged by message ID only
#   hourly EventBridge rule -> the same function
#     live receiving configuration vs. this file, overdue register items
#     -> two metrics -> two alarms -> the evidence-alert topic
#
# Everything is in us-east-2, beside the watchdog, the at-rest CMK, the alert
# topic and the DLQ it reuses: SES receives mail in us-east-2.
#
# Message bodies are stored only in the inbox bucket. Nothing here publishes,
# logs or pages a message body; pages carry the sender, subject, designation
# and deadline, and go only to the operator's subscription on the alert topic.
#
# The alarms are named under the evidence watchdog's prefix on purpose: the
# alert topic's policy, the at-rest key's CloudWatch grant, the deploy role's
# alarm grant and the operators' test/silence grant are all scoped to that
# prefix, so the inbox pages through the same path without widening any of them.
#
# Cost: two custom metrics and three standard alarms (about $0.90/month), plus
# SES receiving, S3 and KMS requests at this volume (cents). No new KMS key.
# =============================================================================

locals {
  fsi_enabled = local.watchdog_enabled && var.create_fedramp_inbox && var.manage_dns

  # The single source of truth for the inbox address (AFC-CSO-INB).
  fsi         = jsondecode(file("${path.module}/../data/cds/offering.json")).fedramp_security_inbox
  fsi_address = lower(local.fsi.address)

  fsi_name      = "${replace(var.domain_name, ".", "-")}-fedramp-inbox"
  fsi_bucket    = "${replace(var.domain_name, ".", "-")}-fsi-mail"
  fsi_rule_set  = "${replace(var.domain_name, ".", "-")}-fsi"
  fsi_rule      = "fedramp-security-inbox"
  fsi_prefix    = "inbound/"
  fsi_mx        = "inbound-smtp.${var.aws_region}.amazonaws.com"
  fsi_mail_from = "mail.${var.domain_name}"
  fsi_runbook   = "https://github.com/sam-aydlette/samaydlette.com/blob/main/docs/runbooks/fedramp-security-inbox.md"
  fsi_rule_arn  = "arn:aws:ses:${var.aws_region}:${data.aws_caller_identity.current.account_id}:receipt-rule-set/${local.fsi_rule_set}:receipt-rule/${local.fsi_rule}"
  fsi_identity  = "arn:aws:ses:${var.aws_region}:${data.aws_caller_identity.current.account_id}:identity/${var.domain_name}"

  # FedRAMP messages are internal, not public: CMK-encrypted, and readable only
  # by principals the key policy and IAM both allow (the read-only group's
  # kms:Decrypt deny keeps them out).
  fsi_cls = { DataSensitivity = "internal", MissionCriticality = "moderate", InternetReachable = "true", Archetype = "security-tooling" }
  fsi_tags = {
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  }
}

# -----------------------------------------------------------------------------
# DNS: receive (MX), and send the acknowledgement authenticated (DKIM, SPF via
# a custom MAIL FROM, DMARC). Public records; nothing secret.
# -----------------------------------------------------------------------------

resource "aws_route53_record" "fsi_mx" {
  count   = local.fsi_enabled ? 1 : 0
  zone_id = local.site_zone_id
  name    = var.domain_name
  type    = "MX"
  ttl     = 300
  records = ["10 ${local.fsi_mx}"]

  lifecycle {
    precondition {
      condition     = endswith(local.fsi_address, "@${var.domain_name}")
      error_message = "fedramp_security_inbox.address in data/cds/offering.json must be on the system's own domain."
    }
  }
}

# Nothing sends mail with this domain in the envelope except SES's custom MAIL
# FROM subdomain below, so the apex SPF policy authorises no one.
resource "aws_route53_record" "fsi_spf_apex" {
  count   = local.fsi_enabled ? 1 : 0
  zone_id = local.site_zone_id
  name    = var.domain_name
  type    = "TXT"
  ttl     = 300
  records = ["v=spf1 -all"]
}

resource "aws_route53_record" "fsi_dmarc" {
  count   = local.fsi_enabled ? 1 : 0
  zone_id = local.site_zone_id
  name    = "_dmarc.${var.domain_name}"
  type    = "TXT"
  ttl     = 300
  records = ["v=DMARC1; p=quarantine; adkim=r; aspf=r"]
}

resource "aws_sesv2_email_identity" "fsi" {
  count          = local.fsi_enabled ? 1 : 0
  email_identity = var.domain_name

  tags = merge(local.fsi_cls, local.fsi_tags, { Name = "${var.domain_name}-ses-identity" })
}

# Easy DKIM always issues three tokens.
resource "aws_route53_record" "fsi_dkim" {
  count   = local.fsi_enabled ? 3 : 0
  zone_id = local.site_zone_id
  name    = "${aws_sesv2_email_identity.fsi[0].dkim_signing_attributes[0].tokens[count.index]}._domainkey.${var.domain_name}"
  type    = "CNAME"
  ttl     = 1800
  records = ["${aws_sesv2_email_identity.fsi[0].dkim_signing_attributes[0].tokens[count.index]}.dkim.amazonses.com"]
}

resource "aws_sesv2_email_identity_mail_from_attributes" "fsi" {
  count                  = local.fsi_enabled ? 1 : 0
  email_identity         = aws_sesv2_email_identity.fsi[0].email_identity
  mail_from_domain       = local.fsi_mail_from
  behavior_on_mx_failure = "USE_DEFAULT_VALUE"
}

resource "aws_route53_record" "fsi_mail_from_mx" {
  count   = local.fsi_enabled ? 1 : 0
  zone_id = local.site_zone_id
  name    = local.fsi_mail_from
  type    = "MX"
  ttl     = 300
  records = ["10 feedback-smtp.${var.aws_region}.amazonses.com"]
}

resource "aws_route53_record" "fsi_mail_from_spf" {
  count   = local.fsi_enabled ? 1 : 0
  zone_id = local.site_zone_id
  name    = local.fsi_mail_from
  type    = "TXT"
  ttl     = 300
  records = ["v=spf1 include:amazonses.com -all"]
}

# -----------------------------------------------------------------------------
# The inbox bucket: raw messages under inbound/ (written by SES), the register
# under register/ (written by the function and the operator's CLI).
# -----------------------------------------------------------------------------
# The sub-resources name the bucket by its .bucket attribute (known at plan
# time) rather than .id (known only after apply), so the OPA gate joins each
# security setting to the bucket on the first plan instead of failing closed.

resource "aws_s3_bucket" "fsi_mail" {
  # checkov:skip=CKV2_AWS_62:No S3 event notification is needed: SES invokes the inbox function itself, as the receipt rule's second action, after storing the message.
  count  = local.fsi_enabled ? 1 : 0
  bucket = local.fsi_bucket

  # Not internet-reachable itself (only SES writes to it), so the internal
  # security-tooling profile rather than the function's.
  tags = merge(local.cls.security_tooling_internal, local.fsi_tags, { Name = local.fsi_bucket })
}

resource "aws_s3_bucket_public_access_block" "fsi_mail" {
  count                   = local.fsi_enabled ? 1 : 0
  bucket                  = aws_s3_bucket.fsi_mail[0].bucket
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "fsi_mail" {
  count  = local.fsi_enabled ? 1 : 0
  bucket = aws_s3_bucket.fsi_mail[0].bucket
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "fsi_mail" {
  count  = local.fsi_enabled ? 1 : 0
  bucket = aws_s3_bucket.fsi_mail[0].bucket
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.at_rest.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "fsi_mail" {
  count  = local.fsi_enabled ? 1 : 0
  bucket = aws_s3_bucket.fsi_mail[0].bucket
  versioning_configuration { status = "Enabled" }
}

# Messages and register records are kept 400 days (beyond a year, like the
# logs); superseded register versions 90 days, so a record's history survives
# the operator's edits for a quarter.
resource "aws_s3_bucket_lifecycle_configuration" "fsi_mail" {
  count  = local.fsi_enabled ? 1 : 0
  bucket = aws_s3_bucket.fsi_mail[0].bucket
  rule {
    id     = "retain-400-days"
    status = "Enabled"
    filter {}
    expiration { days = 400 }
    noncurrent_version_expiration { noncurrent_days = 90 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_logging" "fsi_mail" {
  count         = local.fsi_enabled ? 1 : 0
  bucket        = aws_s3_bucket.fsi_mail[0].bucket
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access-fsi/"

  depends_on = [aws_s3_bucket_policy.logs]
}

# SES may write the raw message under inbound/ for this account's inbox rule
# only (the documented SES receiving policy, with the confused-deputy
# conditions). Everything else is denied over plain HTTP.
resource "aws_s3_bucket_policy" "fsi_mail" {
  count  = local.fsi_enabled ? 1 : 0
  bucket = aws_s3_bucket.fsi_mail[0].bucket
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "SesStoresInboundMail"
        Effect    = "Allow"
        Principal = { Service = "ses.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.fsi_mail[0].arn}/${local.fsi_prefix}*"
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
            "AWS:SourceArn"     = local.fsi_rule_arn
          }
        }
      },
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.fsi_mail[0].arn, "${aws_s3_bucket.fsi_mail[0].arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.fsi_mail]
}

# -----------------------------------------------------------------------------
# The function
# -----------------------------------------------------------------------------

data "archive_file" "fedramp_inbox" {
  count       = local.fsi_enabled ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/fedramp-inbox.zip"

  source {
    content  = file("${path.module}/fedramp-inbox/index.mjs")
    filename = "index.mjs"
  }
  source {
    content  = file("${path.module}/fedramp-inbox/logic.mjs")
    filename = "logic.mjs"
  }
}

resource "aws_iam_role" "fedramp_inbox" {
  count = local.fsi_enabled ? 1 : 0
  name  = "${local.fsi_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = merge(local.cls.identity_secrets_internal, local.fsi_tags, { Name = "${local.fsi_name}-role" })
}

# Least privilege. No read of inbound/ (the function never reads a message
# body); register/ read and write; send only as the inbox address; publish to
# the one alert topic; read-only on the receiving configuration it checks.
resource "aws_iam_role_policy" "fedramp_inbox" {
  # checkov:skip=CKV_AWS_355:ses:DescribeActiveReceiptRuleSet and ses:GetAccount are account-level reads with no resource type; every other statement is resource-scoped.
  count = local.fsi_enabled ? 1 : 0
  name  = "${local.fsi_name}-policy"
  role  = aws_iam_role.fedramp_inbox[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteOwnLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.fedramp_inbox[0].arn}:*"
      },
      {
        Sid      = "ReadWriteRegister"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.fsi_mail[0].arn}/register/*"
      },
      {
        Sid       = "ListOpenRegister"
        Effect    = "Allow"
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.fsi_mail[0].arn
        Condition = { StringLike = { "s3:prefix" = ["register/open/*"] } }
      },
      {
        # The register objects (SSE-KMS), the encrypted alert topic, and the
        # function's own environment all use the at-rest key.
        Sid      = "UseAtRestKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.at_rest.arn
      },
      {
        Sid      = "AcknowledgeAsTheInboxOnly"
        Effect   = "Allow"
        Action   = ["ses:SendEmail", "ses:SendRawEmail"]
        Resource = local.fsi_identity
        Condition = {
          StringEquals = { "ses:FromAddress" = local.fsi_address }
        }
      },
      {
        Sid      = "PageTheOperator"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.evidence_alerts[0].arn
      },
      {
        Sid      = "ReadOwnIdentity"
        Effect   = "Allow"
        Action   = "ses:GetEmailIdentity"
        Resource = local.fsi_identity
      },
      {
        Sid      = "ReadReceivingConfiguration"
        Effect   = "Allow"
        Action   = ["ses:DescribeActiveReceiptRuleSet", "ses:GetAccount"]
        Resource = "*"
      },
      {
        Sid      = "ReadMxRecord"
        Effect   = "Allow"
        Action   = "route53:ListResourceRecordSets"
        Resource = "arn:aws:route53:::hostedzone/${local.site_zone_id}"
      },
      {
        Sid       = "PublishInboxMetrics"
        Effect    = "Allow"
        Action    = "cloudwatch:PutMetricData"
        Resource  = "*"
        Condition = { StringEquals = { "cloudwatch:namespace" = local.watchdog_namespace } }
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

resource "aws_cloudwatch_log_group" "fedramp_inbox" {
  count             = local.fsi_enabled ? 1 : 0
  name              = "/aws/lambda/${local.fsi_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.at_rest.arn

  tags = merge(local.cls.security_tooling, local.fsi_tags, { Name = "${local.fsi_name}-logs" })
}

resource "aws_lambda_function" "fedramp_inbox" {
  count = local.fsi_enabled ? 1 : 0

  filename         = data.archive_file.fedramp_inbox[0].output_path
  source_code_hash = data.archive_file.fedramp_inbox[0].output_base64sha256
  function_name    = local.fsi_name
  role             = aws_iam_role.fedramp_inbox[0].arn
  handler          = "index.handler"
  runtime          = "nodejs22.x"
  timeout          = 30
  memory_size      = 128

  kms_key_arn = aws_kms_key.at_rest.arn
  dead_letter_config {
    target_arn = aws_sqs_queue.compliance_dlq[0].arn
  }

  # Configuration, not secrets: every value here is public in this repository
  # (the address is published in the CPO).
  environment {
    variables = {
      FSI_ADDRESS      = local.fsi_address
      MAIL_BUCKET      = aws_s3_bucket.fsi_mail[0].bucket
      MAIL_PREFIX      = local.fsi_prefix
      ALERT_TOPIC_ARN  = aws_sns_topic.evidence_alerts[0].arn
      METRIC_NAMESPACE = local.watchdog_namespace
      RULE_SET         = local.fsi_rule_set
      RULE_NAME        = local.fsi_rule
      DOMAIN           = var.domain_name
      ZONE_ID          = local.site_zone_id
      MX_TARGET        = local.fsi_mx
      RUNBOOK_URL      = local.fsi_runbook
    }
  }

  depends_on = [aws_cloudwatch_log_group.fedramp_inbox, aws_kms_alias.at_rest]

  tags = merge(local.fsi_cls, local.fsi_tags, { Name = local.fsi_name })
}

resource "aws_lambda_permission" "fedramp_inbox_ses" {
  count          = local.fsi_enabled ? 1 : 0
  statement_id   = "AllowSesReceiptRule"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.fedramp_inbox[0].function_name
  principal      = "ses.amazonaws.com"
  source_account = data.aws_caller_identity.current.account_id
  source_arn     = local.fsi_rule_arn
}

resource "aws_cloudwatch_event_rule" "fedramp_inbox" {
  count               = local.fsi_enabled ? 1 : 0
  name                = local.fsi_name
  description         = "Hourly check of the FedRAMP Security Inbox configuration and register"
  schedule_expression = "rate(1 hour)"

  tags = merge(local.cls.internal_tooling_low, local.fsi_tags, { Name = local.fsi_name })
}

resource "aws_cloudwatch_event_target" "fedramp_inbox" {
  count     = local.fsi_enabled ? 1 : 0
  rule      = aws_cloudwatch_event_rule.fedramp_inbox[0].name
  target_id = "FedrampInboxCheck"
  arn       = aws_lambda_function.fedramp_inbox[0].arn
}

resource "aws_lambda_permission" "fedramp_inbox_events" {
  count         = local.fsi_enabled ? 1 : 0
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fedramp_inbox[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.fedramp_inbox[0].arn
}

# -----------------------------------------------------------------------------
# Receiving
# -----------------------------------------------------------------------------

resource "aws_ses_receipt_rule_set" "fsi" {
  count         = local.fsi_enabled ? 1 : 0
  rule_set_name = local.fsi_rule_set
}

# One rule set can be active per region; this makes it this one.
resource "aws_ses_active_receipt_rule_set" "fsi" {
  count         = local.fsi_enabled ? 1 : 0
  rule_set_name = aws_ses_receipt_rule_set.fsi[0].rule_set_name
}

# AFC-CSO-RCV / TFG: the rule never bounces, stops or drops a message. Spam and
# virus verdicts are computed (scan_enabled) and only recorded; TLS is
# accepted, not required, so a sender without it is not refused.
resource "aws_ses_receipt_rule" "fsi" {
  count         = local.fsi_enabled ? 1 : 0
  name          = local.fsi_rule
  rule_set_name = aws_ses_receipt_rule_set.fsi[0].rule_set_name
  recipients    = [local.fsi_address]
  enabled       = true
  scan_enabled  = true
  tls_policy    = "Optional"

  s3_action {
    bucket_name       = aws_s3_bucket.fsi_mail[0].bucket
    object_key_prefix = local.fsi_prefix
    position          = 1
  }

  lambda_action {
    function_arn    = aws_lambda_function.fedramp_inbox[0].arn
    invocation_type = "Event"
    position        = 2
  }

  depends_on = [aws_s3_bucket_policy.fsi_mail, aws_lambda_permission.fedramp_inbox_ses, aws_kms_key.at_rest]
}

# -----------------------------------------------------------------------------
# Alarms (named under the watchdog prefix; see the header)
# -----------------------------------------------------------------------------

locals {
  fsi_alarms = {
    "fsi-config" = {
      namespace = local.watchdog_namespace
      metric    = "InboxConfigProblems"
      stat      = "Maximum"
      dims      = {}
      periods   = 3
      breaches  = 2
      missing   = "breaching"
      summary   = "The FedRAMP Security Inbox's live configuration differs from Terraform (receipt rule, identity, MX, SES sandbox), or the hourly check stopped reporting. The function's log names the problem."
    }
    "fsi-overdue" = {
      namespace = local.watchdog_namespace
      metric    = "InboxOverdue"
      stat      = "Maximum"
      dims      = {}
      periods   = 1
      breaches  = 1
      missing   = "notBreaching"
      summary   = "A FedRAMP message is untriaged past its window, past its deadline without closure, or its acknowledgement or page failed. Run scripts/fsi.py list."
    }
    "fsi-errors" = {
      namespace = "AWS/Lambda"
      metric    = "Errors"
      stat      = "Sum"
      dims      = { FunctionName = local.fsi_name }
      periods   = 1
      breaches  = 1
      missing   = "notBreaching"
      summary   = "The FedRAMP Security Inbox function failed (a page did not go out, or the check crashed). SES retries; failed runs land in the compliance DLQ. The message itself is already stored."
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "fsi" {
  for_each = local.fsi_enabled ? local.fsi_alarms : {}

  alarm_name          = "${local.watchdog_name}-${each.key}"
  alarm_description   = "${each.value.summary} Runbook: ${local.fsi_runbook}"
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  dimensions          = length(each.value.dims) > 0 ? each.value.dims : null
  statistic           = each.value.stat
  period              = 3600
  evaluation_periods  = each.value.periods
  datapoints_to_alarm = each.value.breaches
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = each.value.missing

  alarm_actions = [aws_sns_topic.evidence_alerts[0].arn]
  ok_actions    = [aws_sns_topic.evidence_alerts[0].arn]

  tags = merge(local.cls.security_tooling, local.fsi_tags, { Name = "${local.watchdog_name}-${each.key}" })
}
