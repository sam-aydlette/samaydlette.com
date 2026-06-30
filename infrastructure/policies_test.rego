package terraform.compliance

# =============================================================================
# PR-D: resource classification completeness gate tests
# =============================================================================
# Pins the build-time invariant: every taggable resource must carry all six
# governed classification axes, with the two constant axes allowed to arrive via
# provider default_tags (tags_all). The missing-tag case is the committed broken
# fixture that must fail the gate.

_complete_all := {
	"DataSensitivity": "public",
	"MissionCriticality": "moderate",
	"InternetReachable": "false",
	"Archetype": "identity-secrets",
	"AgencyScope": "single",
	"OwnerRole": "platform-operator",
}

# A fully-classified taggable resource passes.
test_classification_complete_passes {
	count(classification_violations) == 0 with input as {"resource": {
		"type": "aws_kms_key", "name": "at_rest",
		"tags": {}, "tags_all": _complete_all,
	}}
}

# The constant axes may come only from default_tags (tags_all): still complete.
test_constant_axes_from_default_tags_pass {
	count(classification_violations) == 0 with input as {"resource": {
		"type": "aws_apigatewayv2_api", "name": "silk_reeling",
		"tags": {"DataSensitivity": "public", "MissionCriticality": "moderate", "InternetReachable": "true", "Archetype": "public-edge"},
		"tags_all": {"DataSensitivity": "public", "MissionCriticality": "moderate", "InternetReachable": "true", "Archetype": "public-edge", "AgencyScope": "single", "OwnerRole": "platform-operator"},
	}}
}

# BROKEN FIXTURE: a taggable resource missing classification keys fails the gate.
test_missing_classification_fails {
	count(classification_violations) > 0 with input as {"resource": {
		"type": "aws_lambda_function", "name": "silk_reeling",
		"tags": {"DataSensitivity": "public"},
		"tags_all": {"DataSensitivity": "public", "AgencyScope": "single"},
	}}
}

# A missing classification tag makes the whole resource non-compliant.
test_missing_classification_makes_noncompliant {
	compliant == false with input as {"resource": {
		"type": "aws_lambda_function", "name": "silk_reeling",
		"tags": {}, "tags_all": {"AgencyScope": "single"},
	}}
}

# Sub-resource configs that do not accept AWS tags are not gated.
test_non_taggable_type_ignored {
	count(classification_violations) == 0 with input as {"resource": {
		"type": "aws_s3_bucket_versioning", "name": "website",
		"tags": {}, "tags_all": {},
	}}
}

# A data source sharing a managed type (data.aws_s3_bucket.website) is not gated.
test_data_source_not_gated {
	count(classification_violations) == 0 with input as {"resource": {
		"type": "aws_s3_bucket", "name": "website", "mode": "data",
		"tags": {}, "tags_all": {},
	}}
}

# A managed resource of the same type, missing tags, still fails.
test_managed_resource_still_gated {
	count(classification_violations) > 0 with input as {"resource": {
		"type": "aws_s3_bucket", "name": "logs", "mode": "managed",
		"tags": {}, "tags_all": {},
	}}
}
