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
# The deploy role can create and read these, never delete or disable them
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
