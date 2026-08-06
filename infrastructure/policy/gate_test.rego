package gate_test

import data.policy.gate

# =============================================================================
# Input-contract and configuration-guard tests
# =============================================================================

config_errors(v) := [x | some x in v; x.id == "config_error"]

input_errors(v) := [x | some x in v; x.id == "input_error"]

read_errors(v) := [x | some x in v; x.id == "resource_read_error"]

# Unrecognized input must produce an explicit input_error.
test_unrecognized_input_flagged if {
	count(input_errors(gate.violations)) == 1 with input as {}
}

test_plan_shape_recognized if {
	count(input_errors(gate.violations)) == 0 with input as {"resource_changes": []}
}

test_resource_shape_recognized if {
	count(input_errors(gate.violations)) == 0 with input as {"resource": {"type": "aws_s3_bucket", "name": "x"}}
}

test_scan_shape_recognized if {
	count(input_errors(gate.violations)) == 0 with input as {"accessibility_scan": {"pages": []}}
}

# The retired raw-HTML shape is no longer a recognized input.
test_html_shape_now_rejected if {
	count(input_errors(gate.violations)) == 1 with input as {"html_content": "<p>x</p>", "file_name": "x.html"}
}

# =============================================================================
# Read-failure contract: an attribute the evaluator could not observe must be
# reported as unassessed, one finding per unreadable attribute, so the gate
# still fails closed while the published reason stays honest.
# =============================================================================

test_read_error_raises_one_finding_per_attribute if {
	count(read_errors(gate.violations)) == 2 with input as {"resource": {
		"type": "aws_s3_bucket", "name": "cloudtrail",
		"read_errors": ["encryption", "tags"],
	}}
}

# MUST-FIRE the other way: a clean resource raises nothing.
test_no_read_errors_when_all_attributes_observed if {
	count(read_errors(gate.violations)) == 0 with input as {"resource": {
		"type": "aws_s3_bucket", "name": "website",
	}}
}

# The plan path never carries read_errors, so deploy-time behaviour is
# unchanged and absent attributes keep failing closed as before.
test_plan_input_raises_no_read_errors if {
	count(read_errors(gate.violations)) == 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket.b", "mode": "managed",
		"type": "aws_s3_bucket", "name": "b",
		"change": {"actions": ["create"], "after": {"bucket": "b", "tags": {}, "tags_all": {}}},
	}]}
}

# A malformed read_errors value must not silently disable the check by making
# the rule body undefined.
test_malformed_read_errors_ignored if {
	count(read_errors(gate.violations)) == 0 with input as {"resource": {
		"type": "aws_s3_bucket", "name": "b", "read_errors": "encryption",
	}}
}

# A gate whose parameters failed to load must fail closed, not enforce
# nothing: with an empty config document every required parameter path is
# reported missing.
test_missing_config_fails_closed if {
	count(config_errors(gate.violations)) == count(gate.required_config_paths) with input as {"resource_changes": []}
		with data.config as {}
}

# A config document missing exactly one parameter (tls.order) yields exactly
# one config_error. The whole document is replaced because `with` on a data
# sub-path does not remove sibling keys from the base document.
test_partial_config_fails_closed if {
	count(config_errors(gate.violations)) == 1 with input as {"resource_changes": []}
		with data.config as {"gate": {
			"required_tags": ["Environment"],
			"governance_tag_types": ["aws_s3_bucket"],
			"required_classification_tags": ["DataSensitivity"],
			"taggable_types": ["aws_s3_bucket"],
			"accessibility": {"fail_on": ["error"]},
			"tls": {"minimum": "TLSv1.2_2021"},
		}}
}

test_complete_config_no_errors if {
	count(config_errors(gate.violations)) == 0 with input as {"resource_changes": []}
}

# The absent-document case (e.g. a Wasm host that never called setData) must
# fail closed too — object.get on an absent data.config is undefined, so it
# needs its own rule and its own test.
test_absent_config_document_fails_closed if {
	count(config_errors(gate.violations)) > 0 with input as {"resource_changes": []}
		with data.config as false
}
