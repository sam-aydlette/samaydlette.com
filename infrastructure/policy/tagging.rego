# =============================================================================
# TAGGING AND CLASSIFICATION POLICY
# =============================================================================
# Two related gates:
#
#   1. Governance tags (Environment / CostCenter / DataClassification /
#      Owner). Historically enforced only for S3 buckets; that scope is
#      preserved here and generalized when the parameters move to data
#      (see the organization-defined-parameters refactor).
#   2. Classification completeness (PR-D): every taggable resource must carry
#      the six governed classification axes (see
#      docs/policies/resource-tagging-standard.md). The two constant axes
#      arrive via provider default_tags (so they land in tags_all, not tags);
#      the four varying axes are per-resource. A taggable resource missing
#      any axis fails the build, so a new resource cannot ship unclassified.
#      Value-correctness against the inventory is enforced separately by the
#      reconciliation gate (Part 2); this is the build-time completeness
#      check.
# =============================================================================

package policy.tagging

import data.policy.gate

# Every AWS resource must have these tags for proper governance and cost
# tracking.
required_tags := {
	"Environment", # dev, staging, prod - helps track what this is for
	"CostCenter", # who pays for this resource
	"DataClassification", # public, internal, confidential - what kind of data
	"Owner", # who is responsible for this resource
}

required_classification_tags := {
	"DataSensitivity",
	"MissionCriticality",
	"InternetReachable",
	"AgencyScope",
	"OwnerRole",
	"Archetype",
}

# Resource types this system tags. Sub-resource configs (versioning, policies,
# routes, permissions) do not accept AWS tags and are intentionally excluded.
taggable_types := {
	"aws_kms_key",
	"aws_lambda_function",
	"aws_iam_role",
	"aws_s3_bucket",
	"aws_cloudwatch_log_group",
	"aws_sqs_queue",
	"aws_secretsmanager_secret",
	"aws_cognito_user_pool",
	"aws_apigatewayv2_api",
	"aws_apigatewayv2_stage",
	"aws_cloudwatch_event_rule",
}

missing_required_tags(r) := {tag |
	some tag in required_tags
	not gate.tags_of(r, "tags")[tag]
}

# A classification key counts as present if it is in either the resource's own
# tags or the provider default_tags (which Terraform merges into tags_all).
classification_present(r, key) if gate.tags_of(r, "tags_all")[key]

classification_present(r, key) if gate.tags_of(r, "tags")[key]

# Data sources share a managed resource's type (e.g. data.aws_s3_bucket.website)
# but carry no tags; the gate applies only to managed resources. A missing mode
# is treated as managed (fail-safe: the gate still applies).
is_managed(r) if r.mode != "data"

is_managed(r) if not r.mode

missing_classification(r) := {key |
	some key in required_classification_tags
	not classification_present(r, key)
}

# Flag S3 buckets that are missing required governance tags
violations contains violation if {
	some r in gate.resources
	r.type == "aws_s3_bucket"
	count(missing_required_tags(r)) > 0
	violation := {
		"id": "missing_required_tags",
		"type": "missing_required_tags",
		"category": "infrastructure",
		"severity": "HIGH",
		"resource": r.name,
		"address": gate.address_of(r),
		"message": sprintf("S3 bucket missing required tags: %v", [missing_required_tags(r)]),
	}
}

# Flag taggable resources missing classification axes
violations contains violation if {
	some r in gate.resources
	is_managed(r)
	taggable_types[r.type]
	count(missing_classification(r)) > 0
	violation := {
		"id": "missing_classification_tag",
		"type": "missing_classification_tag",
		"category": "classification",
		"severity": "HIGH",
		"resource": r.name,
		"address": gate.address_of(r),
		"message": sprintf("%s.%s is missing classification tags: %v", [r.type, r.name, missing_classification(r)]),
	}
}
