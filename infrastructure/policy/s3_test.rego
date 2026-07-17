package s3_test

import data.policy.terraform.s3

# =============================================================================
# Per-rule tests with MUST-FIRE negatives. Every rule gets a fixture that is
# REQUIRED to produce its violation — the class of test that would have
# caught the dead lookahead-regex rule (a rule that can never fire passes
# every positive test and fails its must-fire negative immediately).
# =============================================================================

_bucket(overrides) := {"resource": object.union(
	{
		"type": "aws_s3_bucket", "name": "b",
		"tags": {}, "tags_all": {},
		"versioning_enabled": true,
		"encryption_enabled": true,
		"public_access_blocked": true,
	},
	overrides,
)}

ids(v) := {x.id | some x in v}

test_secure_bucket_no_s3_violations if {
	count(s3.violations) == 0 with input as _bucket({})
}

# MUST-FIRE: versioning off
test_versioning_disabled_must_fire if {
	ids(s3.violations) == {"versioning_disabled"} with input as _bucket({"versioning_enabled": false})
}

# MUST-FIRE: encryption off
test_encryption_disabled_must_fire if {
	ids(s3.violations) == {"encryption_disabled"} with input as _bucket({"encryption_enabled": false})
}

# MUST-FIRE: public access not fully blocked
test_public_access_must_fire if {
	ids(s3.violations) == {"public_access_not_fully_blocked"} with input as _bucket({"public_access_blocked": false})
}

# MUST-FIRE: a synthesized field that is merely ABSENT (not false) still fails
# — an unknown security posture is treated as insecure.
test_absent_fields_fail_closed if {
	expected := {"versioning_disabled", "encryption_disabled", "public_access_not_fully_blocked"}
	ids(s3.violations) == expected with input as {"resource": {"type": "aws_s3_bucket", "name": "b", "tags": {}}}
}

# Non-bucket types produce no S3 violations.
test_other_types_ignored if {
	count(s3.violations) == 0 with input as {"resource": {"type": "aws_lambda_function", "name": "f", "tags": {}}}
}

# =============================================================================
# Plan-shape join tests: the provider >= 4.x split resources join in Rego.
# =============================================================================

_plan_with_versioning(status) := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.logs", "mode": "managed",
			"type": "aws_s3_bucket", "name": "logs",
			"change": {"actions": ["create"], "after": {"bucket": "logs-bucket", "tags": {}, "tags_all": {}}},
		},
		{
			"address": "aws_s3_bucket_versioning.logs", "mode": "managed",
			"type": "aws_s3_bucket_versioning", "name": "logs",
			"change": {"actions": ["create"], "after": {
				"bucket": "logs-bucket",
				"versioning_configuration": [{"status": status}],
			}},
		},
	],
	"configuration": {"root_module": {"resources": []}},
}

test_plan_join_enabled_versioning_passes if {
	not "versioning_disabled" in ids(s3.violations) with input as _plan_with_versioning("Enabled")
}

test_plan_join_suspended_versioning_must_fire if {
	"versioning_disabled" in ids(s3.violations) with input as _plan_with_versioning("Suspended")
}

# A delete-only change is not gated: a non-compliant bucket being destroyed
# raises nothing.
test_delete_only_change_not_gated if {
	count(s3.violations) == 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket.legacy", "mode": "managed",
		"type": "aws_s3_bucket", "name": "legacy",
		"change": {"actions": ["delete"], "before": {"bucket": "x"}, "after": null},
	}]}
}
