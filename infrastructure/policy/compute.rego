# =============================================================================
# FUNCTIONS, DEPLOYED PACKAGES AND MESSAGING SERVICES
# =============================================================================
# Lambda functions (environment encrypted under a customer key), the deployed
# code package (still the one the deploy inventoried), and the SNS topic, SQS
# queue and DynamoDB table this system uses.
#
# lambda_deployment_package is a runtime-only input, not a Terraform type: the
# emitter compares a function's live CodeSha256 with the code_sha256 the deploy
# recorded in the canonical inventory. The deployed zip holds the inventoried
# packages, so a mismatch means code is running that the deploy never scanned.
# =============================================================================

package policy.terraform.compute

import data.policy.gate

packages contains r if {
	some r in gate.resources
	r.type == "lambda_deployment_package"
}

package_hashes_present(r) if {
	gate.value(r, "code_sha256", "") != ""
	gate.value(r, "expected_code_sha256", "") != ""
}

# METADATA
# title: Function environment encrypted with a customer-managed key
# description: Lambda environment variables must be encrypted under a customer-managed KMS key.
# custom:
#   id: lambda_env_not_cmk
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [sc-28]
#   ksi_ids: [KSI-SVC-SIN]
#   resource_types: [aws_lambda_function]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_lambda_function"
	gate.attribute_read_ok(r, "kms_key_arn")
	not gate.planned_unknown(r, "kms_key_arn")
	gate.value(r, "kms_key_arn", "") == ""
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"Lambda environment is not encrypted with a customer-managed KMS key",
	)
}

# METADATA
# title: Deployed code package is verifiable
# description: >-
#   Without the inventoried hash or the live hash the deployed package cannot
#   be compared, so its integrity is unassessed.
# custom:
#   id: package_integrity_unverifiable
#   category: input
#   severity: HIGH
#   nist_controls: [si-7.1]
#   ksi_ids: [KSI-SCR-MIT]
#   resource_types: [lambda_deployment_package]
#   runtime_only: true
violations contains violation if {
	some r in packages
	gate.attribute_read_ok(r, "code_sha256")
	not package_hashes_present(r)
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"Deployed package hash or inventoried hash is missing; integrity is unassessed",
	)
}

# METADATA
# title: Deployed code package is the inventoried one
# description: >-
#   The live function code hash must equal the hash the deploy recorded in the
#   inventory; anything else is code the deploy never inventoried or scanned.
# custom:
#   id: package_integrity_mismatch
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [si-7, si-7.1]
#   ksi_ids: [KSI-SCR-MIT, KSI-SVC-VRI]
#   resource_types: [lambda_deployment_package]
#   runtime_only: true
violations contains violation if {
	some r in packages
	package_hashes_present(r)
	gate.value(r, "code_sha256", "") != gate.value(r, "expected_code_sha256", "")
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"Deployed function code does not match the package the deploy inventoried",
	)
}

# METADATA
# title: Notification topics are encrypted
# description: SNS topics must be encrypted at rest with a KMS key.
# custom:
#   id: sns_topic_unencrypted
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [sc-28]
#   ksi_ids: [KSI-SVC-SIN]
#   resource_types: [aws_sns_topic]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_sns_topic"
	gate.attribute_read_ok(r, "kms_master_key_id")
	not gate.planned_unknown(r, "kms_master_key_id")
	gate.value(r, "kms_master_key_id", "") == ""
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"SNS topic is not encrypted with a KMS key",
	)
}

# METADATA
# title: Queues are encrypted
# description: SQS queues must use SSE-SQS or a KMS key.
# custom:
#   id: sqs_queue_unencrypted
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [sc-28]
#   ksi_ids: [KSI-SVC-SIN]
#   resource_types: [aws_sqs_queue]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_sqs_queue"
	gate.attribute_read_ok(r, "encryption")
	not gate.planned_unknown(r, "kms_master_key_id")
	gate.value(r, "sqs_managed_sse_enabled", false) != true
	gate.value(r, "kms_master_key_id", "") == ""
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"SQS queue is not encrypted (neither SSE-SQS nor a KMS key)",
	)
}

# METADATA
# title: Tables keep point-in-time recovery
# description: DynamoDB tables must have point-in-time recovery enabled.
# custom:
#   id: dynamodb_pitr_disabled
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [cp-9]
#   ksi_ids: [KSI-RPL-ABO]
#   resource_types: [aws_dynamodb_table]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_dynamodb_table"
	gate.attribute_read_ok(r, "point_in_time_recovery")
	gate.value(r, ["point_in_time_recovery", 0, "enabled"], false) != true
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"DynamoDB table point-in-time recovery is disabled",
	)
}
