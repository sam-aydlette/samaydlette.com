package terraform.compliance_test

import data.terraform.compliance

# =============================================================================
# Aggregator and fail-closed decision tests
# =============================================================================

# Fail closed: unrecognized input is non-compliant with an explicit
# input_error — never a vacuous pass.
test_empty_input_fails_closed if {
	compliance.compliant == false with input as {}
	some v in compliance.all_violations with input as {}
	v.id == "input_error" with input as {}
}

test_garbage_input_fails_closed if {
	compliance.compliant == false with input as {"unexpected": [1, 2, 3]}
}

# A recognized input with zero violations is compliant.
test_clean_resource_is_compliant if {
	compliance.compliant == true with input as {"resource": {
		"type": "aws_s3_bucket_policy", "name": "website",
		"tags": {}, "tags_all": {},
	}}
}

# The aggregator discovers violations dynamically: a violation emitted by ANY
# package under data.policy surfaces in all_violations and flips the
# decision, with no aggregator edit. The mock stands in for a future policy
# package (this is the property that makes the gate extensible).
_dummy_violation := {
	"id": "dummy_rule",
	"type": "dummy_rule",
	"category": "test",
	"severity": "HIGH",
	"resource": "dummy",
	"address": "dummy.dummy",
	"message": "synthetic violation injected by main_test",
}

test_new_package_violations_are_aggregated if {
	report := compliance.compliance_report with input as {"resource": {
		"type": "aws_s3_bucket_policy", "name": "website", "tags": {},
	}}
		with data.policy.future_domain.violations as {_dummy_violation}
	report.compliant == false
	report.total_violations == 1
	some v in report.violations
	v.id == "dummy_rule"
}

# Per-resource reports keep the published validations.json entry shape.
test_resource_reports_shape if {
	reports := compliance.resource_reports with input as {"resource": {
		"type": "aws_s3_bucket", "name": "logs",
		"tags": {}, "tags_all": {},
	}}
	count(reports) == 1
	reports[0].kind == "infrastructure"
	reports[0].resource_type == "aws_s3_bucket"
	reports[0].resource_name == "logs"
	reports[0].compliant == false
	count(reports[0].violations) > 0
}
