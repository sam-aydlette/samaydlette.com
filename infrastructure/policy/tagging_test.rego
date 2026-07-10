package policy_test.tagging

import data.policy.tagging
import data.terraform.compliance

# =============================================================================
# PR-D: resource classification completeness gate tests
# =============================================================================
# Pins the build-time invariant: every taggable resource must carry all six
# governed classification axes, with the two constant axes allowed to arrive
# via provider default_tags (tags_all). The missing-tag case is the committed
# broken fixture that must fail the gate.

_complete_all := {
	"DataSensitivity": "public",
	"MissionCriticality": "moderate",
	"InternetReachable": "false",
	"Archetype": "identity-secrets",
	"AgencyScope": "single",
	"OwnerRole": "platform-operator",
}

classification_violations(v) := [x | some x in v; x.id == "missing_classification_tag"]

# A fully-classified taggable resource passes.
test_classification_complete_passes if {
	count(classification_violations(tagging.violations)) == 0 with input as {"resource": {
		"type": "aws_kms_key", "name": "at_rest",
		"tags": {}, "tags_all": _complete_all,
	}}
}

# The constant axes may come only from default_tags (tags_all): still complete.
test_constant_axes_from_default_tags_pass if {
	count(classification_violations(tagging.violations)) == 0 with input as {"resource": {
		"type": "aws_apigatewayv2_api", "name": "silk_reeling",
		"tags": {"DataSensitivity": "public", "MissionCriticality": "moderate", "InternetReachable": "true", "Archetype": "public-edge"},
		"tags_all": {"DataSensitivity": "public", "MissionCriticality": "moderate", "InternetReachable": "true", "Archetype": "public-edge", "AgencyScope": "single", "OwnerRole": "platform-operator"},
	}}
}

# BROKEN FIXTURE: a taggable resource missing classification keys fails the gate.
test_missing_classification_fails if {
	count(classification_violations(tagging.violations)) > 0 with input as {"resource": {
		"type": "aws_lambda_function", "name": "silk_reeling",
		"tags": {"DataSensitivity": "public"},
		"tags_all": {"DataSensitivity": "public", "AgencyScope": "single"},
	}}
}

# A missing classification tag makes the whole resource non-compliant.
test_missing_classification_makes_noncompliant if {
	compliance.compliant == false with input as {"resource": {
		"type": "aws_lambda_function", "name": "silk_reeling",
		"tags": {}, "tags_all": {"AgencyScope": "single"},
	}}
}

# Sub-resource configs that do not accept AWS tags are not gated.
test_non_taggable_type_ignored if {
	count(classification_violations(tagging.violations)) == 0 with input as {"resource": {
		"type": "aws_s3_bucket_versioning", "name": "website",
		"tags": {}, "tags_all": {},
	}}
}

# A data source sharing a managed type (data.aws_s3_bucket.website) is not gated.
test_data_source_not_gated if {
	count(classification_violations(tagging.violations)) == 0 with input as {"resource": {
		"type": "aws_s3_bucket", "name": "website", "mode": "data",
		"tags": {}, "tags_all": {},
	}}
}

# A managed resource of the same type, missing tags, still fails.
test_managed_resource_still_gated if {
	count(classification_violations(tagging.violations)) > 0 with input as {"resource": {
		"type": "aws_s3_bucket", "name": "logs", "mode": "managed",
		"tags": {}, "tags_all": {},
	}}
}

# Parameters as data: narrowing the governance scope via config alone changes
# enforcement with no .rego edit.
_untagged_kms := {"resource": {"type": "aws_kms_key", "name": "k", "tags": {}, "tags_all": {}}}

governance_violations(v) := [x | some x in v; x.id == "missing_required_tags"]

test_governance_uniform_by_default if {
	count(governance_violations(tagging.violations)) > 0 with input as _untagged_kms
}

test_governance_scope_config_driven if {
	count(governance_violations(tagging.violations)) == 0 with input as _untagged_kms
		with data.config.gate.governance_tag_types as ["aws_s3_bucket"]
}
