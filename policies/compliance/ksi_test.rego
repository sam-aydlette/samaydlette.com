# Unit tests for policies/compliance/ksi.rego.
package compliance.ksi_test

import data.compliance.ksi

s3_rule := {"id": "versioning_disabled", "ksi_ids": ["KSI-A"], "resource_types": ["aws_s3_bucket"]}

read_rule := {"id": "resource_read_error", "ksi_ids": ["KSI-B"], "resource_types": ["*"], "runtime_only": true}

obs(stage, tf_type, ids) := {"stage": stage, "tf_type": tf_type, "violation_ids": ids}

base := {"ksis": ["KSI-A", "KSI-B", "KSI-C"], "rules": [], "observations": [], "checks": [], "not_applicable": []}

run(inp) := r if {
	r := ksi.result with input as object.union(base, inp)
}

test_plan_and_live_of_one_rule_are_two_methods if {
	r := run({"rules": [s3_rule], "observations": [obs("plan", "aws_s3_bucket", []), obs("live", "aws_s3_bucket", [])]})
	r.ksis["KSI-A"].status == "Implemented"
	r.ksis["KSI-A"].passing == 2
	not "KSI-A" in r.short
}

test_a_rule_counts_only_where_a_matching_resource_was_evaluated if {
	r := run({"rules": [s3_rule], "observations": [obs("plan", "aws_s3_bucket", []), obs("live", "aws_cloudfront_distribution", [])]})
	r.ksis["KSI-A"].passing == 1
	r.ksis["KSI-A"].status == "Not Demonstrated"
	"KSI-A" in r.short
}

test_a_violation_fails_the_method if {
	r := run({"rules": [s3_rule], "observations": [obs("plan", "aws_s3_bucket", []), obs("live", "aws_s3_bucket", ["versioning_disabled"])]})
	r.ksis["KSI-A"].status == "Not Demonstrated"
	r.ksis["KSI-A"].failing == ["opa:versioning_disabled@live"]
}

test_another_rules_violation_does_not_fail_this_one if {
	r := run({"rules": [s3_rule], "observations": [obs("plan", "aws_s3_bucket", ["weak_tls"]), obs("live", "aws_s3_bucket", [])]})
	r.ksis["KSI-A"].status == "Implemented"
}

test_runtime_only_rules_count_at_live_only if {
	r := run({"rules": [read_rule], "observations": [obs("plan", "aws_s3_bucket", []), obs("live", "aws_kms_key", [])]})
	r.ksis["KSI-B"].methods == [{"method": "opa:resource_read_error", "stage": "live", "passed": true}]
}

test_checks_that_ran_count_per_stage if {
	checks := [
		{"key": "grype", "ksis": ["KSI-C"], "stage": "deploy", "ran": true, "passed": true},
		{"key": "grype", "ksis": ["KSI-C"], "stage": "nightly", "ran": true, "passed": true},
		{"key": "zap", "ksis": ["KSI-C"], "stage": "nightly", "ran": false, "passed": false},
	]
	r := run({"checks": checks})
	r.ksis["KSI-C"].passing == 2
	r.ksis["KSI-C"].status == "Implemented"
}

test_a_failing_check_blocks_implemented if {
	checks := [
		{"key": "a", "ksis": ["KSI-C"], "stage": "deploy", "ran": true, "passed": true},
		{"key": "b", "ksis": ["KSI-C"], "stage": "deploy", "ran": true, "passed": true},
		{"key": "c", "ksis": ["KSI-C"], "stage": "nightly", "ran": true, "passed": false},
	]
	r := run({"checks": checks})
	r.ksis["KSI-C"].status == "Not Demonstrated"
	r.ksis["KSI-C"].failing == ["check:c@nightly"]
}

test_an_unknown_stage_does_not_count if {
	r := run({"checks": [{"key": "a", "ksis": ["KSI-C"], "stage": "someday", "ran": true, "passed": true}]})
	r.ksis["KSI-C"].passing == 0
}

test_only_an_approved_scope_cut_is_not_applicable if {
	na := [{"ksi_id": "KSI-A", "approved": true}, {"ksi_id": "KSI-B", "approved": false}]
	r := run({"not_applicable": na})
	r.ksis["KSI-A"].status == "Not Applicable"
	r.ksis["KSI-B"].status == "Not Demonstrated"
	r.short == ["KSI-B", "KSI-C"]
}
