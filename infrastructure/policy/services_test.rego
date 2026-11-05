package services_test

import data.policy.terraform.cognito
import data.policy.terraform.compute
import data.policy.terraform.keys
import data.policy.terraform.logging
import data.policy.terraform.network

ids(v) := {x.id | some x in v}

_res(type, values) := {"resource": {"type": type, "name": "x", "values": values}}

_plan(type, after, unknown) := {"resource_changes": [{
	"address": sprintf("%s.x", [type]), "mode": "managed", "type": type, "name": "x",
	"change": {"actions": ["create"], "after": after, "after_unknown": unknown},
}]}

# --- Cognito ---

_pool := {
	"mfa_configuration": "ON",
	"password_policy": [{"minimum_length": 14}],
	"admin_create_user_config": [{"allow_admin_create_user_only": true}],
}

test_pool_compliant if {
	count(cognito.violations) == 0 with input as _res("aws_cognito_user_pool", _pool)
}

test_pool_optional_mfa_fails if {
	"cognito_mfa_not_required" in ids(cognito.violations) with input as _res(
		"aws_cognito_user_pool",
		object.union(_pool, {"mfa_configuration": "OPTIONAL"}),
	)
}

test_pool_short_password_fails if {
	"cognito_password_too_short" in ids(cognito.violations) with input as _res(
		"aws_cognito_user_pool",
		object.union(_pool, {"password_policy": [{"minimum_length": 8}]}),
	)
}

test_pool_self_signup_fails if {
	"cognito_self_signup_enabled" in ids(cognito.violations) with input as _res(
		"aws_cognito_user_pool",
		object.union(_pool, {"admin_create_user_config": [{"allow_admin_create_user_only": false}]}),
	)
}

# --- KMS, ACM, DNSSEC ---

test_kms_symmetric_rotating_passes if {
	count(keys.violations) == 0 with input as _res("aws_kms_key", {"enable_key_rotation": true, "is_enabled": true})
}

test_kms_symmetric_not_rotating_fails if {
	"kms_rotation_disabled" in ids(keys.violations) with input as _res("aws_kms_key", {"enable_key_rotation": false})
}

test_kms_asymmetric_rotation_not_required if {
	count(keys.violations) == 0 with input as _res("aws_kms_key", {"customer_master_key_spec": "ECC_NIST_P256"})
}

test_kms_disabled_fails if {
	"kms_key_disabled" in ids(keys.violations) with input as _res(
		"aws_kms_key",
		{"customer_master_key_spec": "ECC_NIST_P256", "is_enabled": false},
	)
}

test_certificate_issued_and_valid_passes if {
	count(keys.violations) == 0 with input as _res(
		"aws_acm_certificate",
		{"status": "ISSUED", "days_to_expiry": 175},
	)
}

test_certificate_not_issued_fails if {
	"certificate_not_issued" in ids(keys.violations) with input as _res("aws_acm_certificate", {"status": "EXPIRED"})
}

test_certificate_expiring_fails if {
	"certificate_expiring" in ids(keys.violations) with input as _res(
		"aws_acm_certificate",
		{"status": "ISSUED", "days_to_expiry": 15},
	)
}

test_dnssec_signing_passes if {
	count(keys.violations) == 0 with input as _res("aws_route53_zone", {"dnssec_status": "SIGNING"})
}

test_dnssec_not_signing_fails if {
	"dnssec_not_signing" in ids(keys.violations) with input as _res(
		"aws_route53_zone",
		{"dnssec_status": "NOT_SIGNING"},
	)
}

# --- logging ---

test_log_group_compliant if {
	count(logging.violations) == 0 with input as _res(
		"aws_cloudwatch_log_group",
		{"retention_in_days": 365, "kms_key_id": "arn:k"},
	)
}

test_log_group_short_retention_fails if {
	"log_retention_below_minimum" in ids(logging.violations) with input as _res(
		"aws_cloudwatch_log_group",
		{"retention_in_days": 30, "kms_key_id": "arn:k"},
	)
}

test_log_group_no_cmk_fails if {
	"log_group_not_cmk" in ids(logging.violations) with input as _res(
		"aws_cloudwatch_log_group",
		{"retention_in_days": 0},
	)
}

test_log_group_cmk_unknown_at_plan_deferred if {
	count(logging.violations) == 0 with input as _plan(
		"aws_cloudwatch_log_group",
		{"retention_in_days": 365, "kms_key_id": null},
		{"kms_key_id": true},
	)
}

test_log_group_null_cmk_in_plan_fails if {
	"log_group_not_cmk" in ids(logging.violations) with input as _plan(
		"aws_cloudwatch_log_group",
		{"retention_in_days": 365, "kms_key_id": null},
		{},
	)
}

_trail := {"enable_logging": true, "is_multi_region_trail": true, "enable_log_file_validation": true}

test_trail_compliant if {
	count(logging.violations) == 0 with input as _res("aws_cloudtrail", _trail)
}

test_trail_stopped_fails if {
	"trail_not_logging" in ids(logging.violations) with input as _res(
		"aws_cloudtrail",
		object.union(_trail, {"enable_logging": false}),
	)
}

test_trail_single_region_fails if {
	"trail_not_logging" in ids(logging.violations) with input as _res(
		"aws_cloudtrail",
		object.union(_trail, {"is_multi_region_trail": false}),
	)
}

test_trail_no_validation_fails if {
	"trail_log_validation_disabled" in ids(logging.violations) with input as _res(
		"aws_cloudtrail",
		object.union(_trail, {"enable_log_file_validation": false}),
	)
}

test_trail_unreadable_reports_only_read_error if {
	count(logging.violations) == 0 with input as {"resource": {
		"type": "aws_cloudtrail", "name": "x",
		"values": {}, "read_errors": ["trail"],
	}}
}

test_alarm_actionable_passes if {
	count(logging.violations) == 0 with input as _res(
		"aws_cloudwatch_metric_alarm",
		{"actions_enabled": true, "alarm_actions": ["arn:sns"]},
	)
}

test_alarm_actions_disabled_fails if {
	"alarm_not_actionable" in ids(logging.violations) with input as _res(
		"aws_cloudwatch_metric_alarm",
		{"actions_enabled": false, "alarm_actions": ["arn:sns"]},
	)
}

test_alarm_without_action_fails if {
	"alarm_not_actionable" in ids(logging.violations) with input as _res(
		"aws_cloudwatch_metric_alarm",
		{"alarm_actions": []},
	)
}

test_alarm_unreadable_reports_only_read_error if {
	res := {"type": "aws_cloudwatch_metric_alarm", "name": "x", "values": {}, "read_errors": ["alarm_actions"]}
	count(logging.violations) == 0 with input as {"resource": res}
}

test_schedule_enabled_passes if {
	count(logging.violations) == 0 with input as _res("aws_cloudwatch_event_rule", {"state": "ENABLED"})
}

test_schedule_disabled_fails if {
	"schedule_disabled" in ids(logging.violations) with input as _res(
		"aws_cloudwatch_event_rule",
		{"state": "DISABLED"},
	)
}

# --- API Gateway, function URLs ---

_stage := {
	"access_log_settings": [{"destination_arn": "arn:logs"}],
	"default_route_settings": [{"throttling_rate_limit": 20, "throttling_burst_limit": 10}],
}

test_stage_compliant if {
	count(network.violations) == 0 with input as _res("aws_apigatewayv2_stage", _stage)
}

test_stage_without_access_log_fails if {
	"apigw_access_logging_disabled" in ids(network.violations) with input as _res(
		"aws_apigatewayv2_stage",
		object.union(_stage, {"access_log_settings": []}),
	)
}

test_stage_unthrottled_fails if {
	"apigw_unthrottled" in ids(network.violations) with input as _res(
		"aws_apigatewayv2_stage",
		object.union(_stage, {"default_route_settings": [{}]}),
	)
}

test_api_route_with_jwt_passes if {
	count(network.violations) == 0 with input as _res(
		"aws_apigatewayv2_route",
		{"route_key": "ANY /api/{proxy+}", "authorization_type": "JWT"},
	)
}

test_api_route_without_auth_fails if {
	"apigw_route_unauthorized" in ids(network.violations) with input as _res(
		"aws_apigatewayv2_route",
		{"route_key": "GET /api/data"},
	)
}

test_default_route_may_be_public if {
	count(network.violations) == 0 with input as _res(
		"aws_apigatewayv2_route",
		{"route_key": "$default", "authorization_type": "NONE"},
	)
}

test_public_function_url_fails if {
	"lambda_public_function_url" in ids(network.violations) with input as _res(
		"aws_lambda_function",
		{"function_url_auth_type": "NONE"},
	)
}

test_public_function_url_resource_fails if {
	"lambda_public_function_url" in ids(network.violations) with input as _res(
		"aws_lambda_function_url",
		{"authorization_type": "NONE"},
	)
}

test_iam_function_url_passes if {
	count(network.violations) == 0 with input as _res("aws_lambda_function", {"function_url_auth_type": "AWS_IAM"})
}

# --- functions, packages, messaging ---

test_function_env_cmk_passes if {
	count(compute.violations) == 0 with input as _res("aws_lambda_function", {"kms_key_arn": "arn:k"})
}

test_function_env_without_cmk_fails if {
	"lambda_env_not_cmk" in ids(compute.violations) with input as _res("aws_lambda_function", {})
}

test_package_matches_passes if {
	count(compute.violations) == 0 with input as _res(
		"lambda_deployment_package",
		{"code_sha256": "abc=", "expected_code_sha256": "abc="},
	)
}

test_package_drift_fails if {
	"package_integrity_mismatch" in ids(compute.violations) with input as _res(
		"lambda_deployment_package",
		{"code_sha256": "new=", "expected_code_sha256": "abc="},
	)
}

test_package_without_inventoried_hash_unassessed if {
	"package_integrity_unverifiable" in ids(compute.violations) with input as _res(
		"lambda_deployment_package",
		{"code_sha256": "abc="},
	)
}

test_topic_encrypted_passes if {
	count(compute.violations) == 0 with input as _res("aws_sns_topic", {"kms_master_key_id": "arn:k"})
}

test_topic_unencrypted_fails if {
	"sns_topic_unencrypted" in ids(compute.violations) with input as _res("aws_sns_topic", {})
}

test_queue_sse_sqs_passes if {
	count(compute.violations) == 0 with input as _res("aws_sqs_queue", {"sqs_managed_sse_enabled": true})
}

test_queue_unencrypted_fails if {
	"sqs_queue_unencrypted" in ids(compute.violations) with input as _res(
		"aws_sqs_queue",
		{"sqs_managed_sse_enabled": false},
	)
}

test_table_pitr_passes if {
	count(compute.violations) == 0 with input as _res(
		"aws_dynamodb_table",
		{"point_in_time_recovery": [{"enabled": true}]},
	)
}

test_table_without_pitr_fails if {
	"dynamodb_pitr_disabled" in ids(compute.violations) with input as _res(
		"aws_dynamodb_table",
		{"point_in_time_recovery": [{"enabled": false}]},
	)
}
