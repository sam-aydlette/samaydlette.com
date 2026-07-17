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

_plain_resource := {"resource": {"type": "aws_s3_bucket_policy", "name": "website", "tags": {}}}

test_new_package_violations_are_aggregated if {
	# future_domain deliberately does not exist: the test proves an unseen
	# package aggregates with no aggregator edit (excepted in .regal/config.yaml).
	report := compliance.compliance_report with input as _plain_resource
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

# =============================================================================
# Exceptions-as-code tests
# =============================================================================

_weak_cf := {"resource": {
	"type": "aws_cloudfront_distribution", "name": "cdn",
	"viewer_protocol_policy": "redirect-to-https",
	"minimum_protocol_version": "TLSv1_2016",
}}

_weak_tls_exception := {
	"resource": "cdn",
	"rule_id": "weak_tls",
	"justification": "test fixture",
	"expiry": "2099-01-01",
	"ticket": "TEST-1",
}

# An active exception suppresses the violation from the decision...
test_active_exception_suppresses if {
	compliance.compliant == true with input as _weak_cf
		with data.exceptions as [_weak_tls_exception]
		with data.runtime as {"evaluated_at": "2026-07-10T00:00:00Z"}
}

# ...but the suppressed finding stays visible under `excepted`, carrying the
# exception that silenced it.
test_excepted_findings_stay_visible if {
	report := compliance.compliance_report with input as _weak_cf
		with data.exceptions as [_weak_tls_exception]
		with data.runtime as {"evaluated_at": "2026-07-10T00:00:00Z"}
	count(report.violations) == 0
	count(report.excepted) == 1
	report.excepted[0].violation.id == "weak_tls"
	report.excepted[0].exception.ticket == "TEST-1"
}

# An expired exception suppresses nothing: the violation resurfaces.
test_expired_exception_resurfaces if {
	compliance.compliant == false with input as _weak_cf
		with data.exceptions as [object.union(_weak_tls_exception, {"expiry": "2020-01-01"})]
		with data.runtime as {"evaluated_at": "2026-07-10T00:00:00Z"}
}

# Fail-safe: with no evaluation timestamp supplied, expiry cannot be checked,
# so no exception is active and the violation surfaces.
test_exception_inactive_without_timestamp if {
	compliance.compliant == false with input as _weak_cf
		with data.exceptions as [_weak_tls_exception]
}
