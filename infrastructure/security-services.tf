# =============================================================================
# AWS SECURITY SERVICES AS EVIDENCE (KSI-CNA-MAT, KSI-SCR-MIT, KSI-SCR-MON)
# =============================================================================
# Two AWS-run checks on the live account, independent of the build-time scans:
#
#   - IAM Access Analyzer, account-level external-access analyzer: AWS's own
#     verdict on which resources (S3 buckets, KMS keys, Lambda functions, IAM
#     roles, SQS queues, Secrets Manager secrets) a principal outside this
#     account can reach. Free. An inventoried component
#     (scripts/build-ksi-signal.py, type access_analyzer).
#   - Amazon Inspector, standard Lambda scanning: CVEs in the deployed Lambda
#     packages, independent of the Grype scan of the build. About $0.30 per
#     function per month (an unverified estimate, 2026-11-19). Lambda code scanning
#     is deliberately not enabled (extra cost). Turning Inspector on is an account
#     setting, not a resource: it is listed as a leveraged AWS service in
#     docs/boundary/boundary-classification.json, not as a component. AWS lists
#     Amazon Inspector in its FedRAMP Class C (East/West) scope
#     (https://aws.amazon.com/compliance/services-in-scope/FedRAMP/, last updated
#     2026-11-11, checked 2026-11-19). That page has no row for IAM Access
#     Analyzer, so this repository claims no FedRAMP status for it.
#
# Their findings enter the VDR as detection feeds (scripts/fetch-detection-feeds.sh),
# and each needs a decision record like any other finding.
#
# Slice 2 (2026-11-21), us-east-2 only (us-east-1, where CloudFront's certificate
# lives, is not covered):
#
#   - AWS Config: records the configuration of every supported resource type in
#     this region plus global IAM resources, delivering to the logs bucket under
#     config/. Its recorder and delivery channel are account settings, so AWS
#     Config is a leveraged service, not a component.
#   - AWS Security Hub CSPM: the hub, with AWS's default standards off and only
#     NIST SP 800-53 Rev. 5 subscribed. It evaluates Config's records. The hub
#     has an ARN, so it is an inventoried component (type security_hub); it
#     takes no tags.
#   - Amazon GuardDuty: a detector, an inventoried component (type
#     threat_detector), with the protection plans AWS enables by default.
#
# AWS's FedRAMP page (above, last updated 2026-11-11, checked 2026-11-21) lists
# AWS Config, AWS Security Hub CSPM and Amazon GuardDuty in its Class C
# (East/West) scope. Estimated together at $3-10 per month (unverified,
# 2026-11-21). How their findings enter the pipeline is a later change.
#
# The deploy role can create and read these, never delete, stop or disable them
# (infrastructure/bootstrap/main.tf, security-services-management). Turning
# either off is an operator break-glass action, so destroying these resources
# through Terraform fails by design.
# =============================================================================

resource "aws_accessanalyzer_analyzer" "external_access" {
  analyzer_name = "${replace(var.domain_name, ".", "-")}-external-access"
  type          = "ACCOUNT"

  # security_tooling_internal: the findings say which resources are reachable
  # from outside the account, so the inventory derives internal sensitivity, and
  # reconcile invariant (i) requires live tags == projected classification.
  tags = merge(local.cls.security_tooling_internal, {
    Name               = "${var.domain_name}-external-access"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  })
}

resource "aws_inspector2_enabler" "lambda" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["LAMBDA"]
}

# --- AWS Config -------------------------------------------------------------

resource "aws_config_configuration_recorder" "this" {
  name = "${replace(var.domain_name, ".", "-")}-recorder"
  # Config's own service-linked role (infrastructure/bootstrap/main.tf,
  # aws_iam_service_linked_role.config).
  role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = "${replace(var.domain_name, ".", "-")}-config"
  s3_bucket_name = aws_s3_bucket.logs.id
  s3_key_prefix  = "config"

  depends_on = [aws_config_configuration_recorder.this, aws_s3_bucket_policy.logs]
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

# --- AWS Security Hub CSPM --------------------------------------------------

resource "aws_securityhub_account" "this" {
  # Only the standard below; AWS's defaults (FSBP, CIS) stay off.
  enable_default_standards = false
}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/nist-800-53/v/5.0.0"

  depends_on = [aws_securityhub_account.this, aws_config_configuration_recorder_status.this]
}

# --- Amazon GuardDuty -------------------------------------------------------

resource "aws_guardduty_detector" "this" {
  # checkov:skip=CKV2_AWS_3:False positive, DEC-043: a single account with no AWS Organization; the detector covers the account in us-east-2.
  enable = true

  # security_tooling_internal: findings describe threats to this account's
  # resources, so the inventory derives internal sensitivity, and reconcile
  # invariant (i) requires live tags == projected classification.
  tags = merge(local.cls.security_tooling_internal, {
    Name               = "${var.domain_name}-guardduty"
    Environment        = var.environment
    CostCenter         = var.cost_center
    DataClassification = "Internal"
    Owner              = var.owner
  })
}
