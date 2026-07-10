# =============================================================================
# TAGGING AND CLASSIFICATION POLICY
# =============================================================================
# Two related gates:
#
#   1. Governance tags (Environment / CostCenter / DataClassification /
#      Owner), enforced uniformly across every resource type listed in
#      data.config.gate.governance_tag_types.
#   2. Classification completeness (PR-D): every taggable resource must carry
#      the governed classification axes (see
#      docs/policies/resource-tagging-standard.md). The two constant axes
#      arrive via provider default_tags (so they land in tags_all, not tags);
#      the four varying axes are per-resource. A taggable resource missing
#      any axis fails the build, so a new resource cannot ship unclassified.
#      Value-correctness against the inventory is enforced separately by the
#      reconciliation gate (Part 2); this is the build-time completeness
#      check.
#
# PARAMETERS AS DATA: the tag lists and type scopes live in
# infrastructure/policy/config/data.json, not in this file — a literal
# implementation of NIST 800-53 organization-defined parameters (ODPs). The
# rule is the control; the config document is the parameter assignment.
# Changing what is enforced is a data change with its own diff and review,
# never a logic edit. If the config document is missing, policy.gate emits a
# config_error and the gate fails closed.
#
# SCOPE NOTE — aws_cloudfront_distribution is deliberately NOT in
# taggable_types / governance_tag_types. In the gated stack the distribution
# is a data source (the bootstrap stack owns the managed resource), and the
# runtime Lambda cannot read CloudFront tags (its role lacks
# cloudfront:ListTagsForResource — see the documented intent in
# infrastructure/lambda/index.js). Adding the type here without growing the
# role and the transformer would turn every runtime signal red. Flip it in
# config only after both have grown.
# =============================================================================

package policy.tagging

import data.policy.gate

required_tags := {t | some t in data.config.gate.required_tags}

required_classification_tags := {t | some t in data.config.gate.required_classification_tags}

# Resource types this system tags. Sub-resource configs (versioning, policies,
# routes, permissions) do not accept AWS tags and are intentionally excluded.
taggable_types := {t | some t in data.config.gate.taggable_types}

governance_tag_types := {t | some t in data.config.gate.governance_tag_types}

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

# Flag governed resources that are missing required governance tags
violations contains violation if {
	some r in gate.resources
	is_managed(r)
	governance_tag_types[r.type]
	count(missing_required_tags(r)) > 0
	violation := {
		"id": "missing_required_tags",
		"type": "missing_required_tags",
		"category": "infrastructure",
		"severity": "HIGH",
		"resource": r.name,
		"address": gate.address_of(r),
		"message": sprintf("%s missing required tags: %v", [r.type, missing_required_tags(r)]),
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
