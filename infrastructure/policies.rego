# =============================================================================
# OPA SECURITY POLICIES FOR TERRAFORM COMPLIANCE AND SECTION 508 ACCESSIBILITY
# =============================================================================
# This file contains the security rules that decide what infrastructure is
# allowed to be deployed AND whether website content meets accessibility
# standards. If any resource violates these rules, deployment is blocked.
#
# INPUT CONTRACT — three shapes are accepted, checked in this order:
#
#   1. Raw `terraform show -json tfplan` output (deploy-time gate). The policy
#      itself iterates `resource_changes`, skips resources whose only action
#      is "delete", and performs the provider >= 4.x S3 sub-resource joins
#      (aws_s3_bucket_versioning / ..._server_side_encryption_configuration /
#      ..._public_access_block -> owning bucket) in Rego. No shell or Python
#      pre-flattening is required or wanted.
#   2. A single pre-normalized `{"resource": {...}}` object (runtime gate).
#      The Lambda emitter builds this shape from live AWS API responses and
#      evaluates the same compiled policy, so one Rego artifact serves both
#      enforcement points.
#   3. `{"html_content": ..., "file_name": ...}` for the Section 508 checks.
#
#   Anything else — including an empty document — produces an explicit
#   `input_error` violation and a non-compliant report. A gate that cannot
#   recognize its input must fail closed, never pass vacuously.
# =============================================================================

# METADATA
# title: Terraform compliance and Section 508 gate
# description: >-
#   Deploy-time and runtime compliance decision for the samaydlette.com
#   pipeline. Consumes raw terraform plan JSON, a normalized single resource,
#   or an HTML document, and emits a uniform compliance report.
# schemas:
#   - input: schema.gate_input
package terraform.compliance

policy_version := "2.0"

# =============================================================================
# INPUT SHAPE DETECTION AND THE FAIL-CLOSED GUARD
# =============================================================================

is_plan_input if is_array(input.resource_changes)

is_resource_input if {
	not is_plan_input
	is_object(input.resource)
}

is_html_input if {
	is_string(input.html_content)
	is_string(input.file_name)
}

valid_input if is_plan_input

valid_input if is_resource_input

valid_input if is_html_input

input_errors contains violation if {
	not valid_input
	violation := {
		"type": "input_error",
		"message": "Input matches no supported shape (terraform plan JSON with resource_changes[], {resource: ...}, or {html_content, file_name}). Refusing to report compliance on input the policy cannot read.",
		"severity": "HIGH",
		"resource": "input",
	}
}

# =============================================================================
# NORMALIZATION: RAW TERRAFORM PLAN -> UNIFORM RESOURCE OBJECTS
# =============================================================================
# Every rule below evaluates `resources`: a set of uniform objects with
# `address`, `type`, `name`, `mode`, `tags`, `tags_all`, `values`, plus
# synthesized security fields for the types that need cross-resource joins.
# The runtime Lambda supplies one already-normalized object; a raw plan is
# normalized here.
# =============================================================================

# A change is gated when the resource still exists after apply. This keeps
# create, update, no-op, replace (["delete","create"]) and data reads, and
# skips pure deletions — a resource being destroyed cannot violate policy.
gated_changes contains rc if {
	some rc in input.resource_changes
	rc.change.actions != ["delete"]
	rc.change.after != null
}

# tags/tags_all may be absent or explicitly null in plan JSON; both mean "no
# tags" to the rules.
tags_of(obj, key) := t if {
	t := obj[key]
	is_object(t)
} else := {}

resource_base(rc) := {
	"address": rc.address,
	"type": rc.type,
	"name": rc.name,
	"mode": rc.mode,
	"tags": tags_of(rc.change.after, "tags"),
	"tags_all": tags_of(rc.change.after, "tags_all"),
	"values": rc.change.after,
}

# --- S3 sub-resource joins (hashicorp/aws >= 4.x splits bucket security
# --- settings into standalone resources) ------------------------------------
#
# Primary join: the sub-resource's `bucket` attribute equals the bucket's
# planned name. Fallback join (covers bucket names computed at apply time,
# when `bucket` is unknown in the plan): the sub-resource's configuration
# expression references the bucket resource by address. LIMITATION: the
# fallback reads `configuration.root_module.resources`, so computed-name
# joins only work for root-module resources; a module-nested bucket with a
# computed name will not join, its synthesized fields stay false, and the
# bucket FAILS the gate — an unjoinable security setting is treated as absent
# (fail closed), never assumed present.

sub_references_bucket(sub, bucket) if {
	sub.change.after.bucket == bucket.change.after.bucket
}

sub_references_bucket(sub, bucket) if {
	some cfg in input.configuration.root_module.resources
	cfg.address == sub.address
	some ref in cfg.expressions.bucket.references
	ref == sprintf("aws_s3_bucket.%s", [bucket.name])
}

has_joined_sub(bucket, sub_type) if {
	some sub in gated_changes
	sub.type == sub_type
	sub_references_bucket(sub, bucket)
}

versioning_state(bucket) if {
	some sub in gated_changes
	sub.type == "aws_s3_bucket_versioning"
	sub_references_bucket(sub, bucket)
	sub.change.after.versioning_configuration[0].status == "Enabled"
} else := false

encryption_state(bucket) if {
	some sub in gated_changes
	sub.type == "aws_s3_bucket_server_side_encryption_configuration"
	sub_references_bucket(sub, bucket)
	some rule in sub.change.after.rule
	rule.apply_server_side_encryption_by_default[0].sse_algorithm in {"AES256", "aws:kms"}
} else := false

public_access_state(bucket) if {
	some sub in gated_changes
	sub.type == "aws_s3_bucket_public_access_block"
	sub_references_bucket(sub, bucket)
	pab := sub.change.after
	pab.block_public_acls == true
	pab.block_public_policy == true
	pab.ignore_public_acls == true
	pab.restrict_public_buckets == true
} else := false

plan_resources contains r if {
	some rc in gated_changes
	rc.type == "aws_s3_bucket"
	r := object.union(resource_base(rc), {
		"versioning_enabled": versioning_state(rc),
		"encryption_enabled": encryption_state(rc),
		"public_access_blocked": public_access_state(rc),
	})
}

plan_resources contains r if {
	some rc in gated_changes
	rc.type == "aws_cloudfront_distribution"
	r := object.union(resource_base(rc), {
		"viewer_protocol_policy": object.get(rc.change.after, ["default_cache_behavior", 0, "viewer_protocol_policy"], ""),
		"minimum_protocol_version": object.get(rc.change.after, ["viewer_certificate", 0, "minimum_protocol_version"], ""),
	})
}

plan_resources contains r if {
	some rc in gated_changes
	not rc.type in {"aws_s3_bucket", "aws_cloudfront_distribution"}
	r := resource_base(rc)
}

# The evaluated resource set, whatever the input shape. The runtime Lambda's
# single resource has no plan address; its name doubles as the address.
default resources := set()

resources := plan_resources if is_plan_input

# Normalization must guarantee `name` (and `address`): a violation object
# references r.name, and a reference to an absent key makes the whole rule
# body undefined — the violation would silently vanish. "unknown" keeps the
# violation visible; a nameless resource must not evade the gate.
resources := {r} if {
	is_resource_input
	base := {
		"address": object.get(input.resource, "address", object.get(input.resource, "name", "unknown")),
		"name": object.get(input.resource, "name", "unknown"),
	}
	r := object.union(base, input.resource)
}

address_of(r) := object.get(r, "address", object.get(r, "name", "unknown"))

# =============================================================================
# REQUIRED TAGS FOR ALL AWS RESOURCES
# =============================================================================
# Every AWS resource must have these tags for proper governance and cost
# tracking.
# =============================================================================

required_tags := {
	"Environment", # dev, staging, prod - helps track what this is for
	"CostCenter", # who pays for this resource
	"DataClassification", # public, internal, confidential - what kind of data
	"Owner", # who is responsible for this resource
}

missing_required_tags(r) := {tag |
	some tag in required_tags
	not tags_of(r, "tags")[tag]
}

# =============================================================================
# RESOURCE CLASSIFICATION COMPLETENESS (PR-D)
# =============================================================================
# Every taggable resource must carry the six governed classification axes (see
# docs/policies/resource-tagging-standard.md). The two constant axes arrive via
# provider default_tags (so they land in tags_all, not tags); the four varying
# axes are per-resource. A taggable resource missing any axis fails the build,
# so a new resource cannot ship unclassified. Value-correctness against the
# inventory is enforced separately by the reconciliation gate (Part 2); this is
# the build-time completeness check.
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

# A classification key counts as present if it is in either the resource's own
# tags or the provider default_tags (which Terraform merges into tags_all).
classification_present(r, key) if tags_of(r, "tags_all")[key]

classification_present(r, key) if tags_of(r, "tags")[key]

# Data sources share a managed resource's type (e.g. data.aws_s3_bucket.website)
# but carry no tags; the gate applies only to managed resources. A missing mode
# is treated as managed (fail-safe: the gate still applies).
is_managed(r) if r.mode != "data"

is_managed(r) if not r.mode

missing_classification(r) := {key |
	some key in required_classification_tags
	not classification_present(r, key)
}

classification_violations contains violation if {
	some r in resources
	is_managed(r)
	taggable_types[r.type]
	count(missing_classification(r)) > 0
	violation := {
		"type": "missing_classification_tag",
		"message": sprintf("%s.%s is missing classification tags: %v", [r.type, r.name, missing_classification(r)]),
		"severity": "HIGH",
		"resource": r.name,
		"address": address_of(r),
	}
}

# =============================================================================
# S3 BUCKET SECURITY VIOLATIONS
# =============================================================================
# Check S3 buckets for required security settings.
# =============================================================================

# Flag S3 buckets that are missing required tags
s3_bucket_violations contains violation if {
	some r in resources
	r.type == "aws_s3_bucket"
	count(missing_required_tags(r)) > 0
	violation := {
		"type": "missing_required_tags",
		"message": sprintf("S3 bucket missing required tags: %v", [missing_required_tags(r)]),
		"severity": "HIGH",
		"resource": r.name,
		"address": address_of(r),
	}
}

# Flag S3 buckets that don't have versioning turned on
s3_bucket_violations contains violation if {
	some r in resources
	r.type == "aws_s3_bucket"
	not r.versioning_enabled
	violation := {
		"type": "versioning_disabled",
		"message": "S3 bucket versioning must be enabled for compliance",
		"severity": "MEDIUM",
		"resource": r.name,
		"address": address_of(r),
	}
}

# Flag S3 buckets that don't have encryption turned on
s3_bucket_violations contains violation if {
	some r in resources
	r.type == "aws_s3_bucket"
	not r.encryption_enabled
	violation := {
		"type": "encryption_disabled",
		"message": "S3 bucket server-side encryption must be enabled",
		"severity": "HIGH",
		"resource": r.name,
		"address": address_of(r),
	}
}

# Flag S3 buckets that don't have public access fully blocked. Evaluated at
# both deploy time (from the plan's aws_s3_bucket_public_access_block join)
# and at runtime (the Lambda populates it from GetPublicAccessBlock API
# calls).
s3_bucket_violations contains violation if {
	some r in resources
	r.type == "aws_s3_bucket"
	not r.public_access_blocked
	violation := {
		"type": "public_access_not_fully_blocked",
		"message": "S3 bucket must block all public access (ACLs, policy, ignore, restrict)",
		"severity": "HIGH",
		"resource": r.name,
		"address": address_of(r),
	}
}

# =============================================================================
# CLOUDFRONT SECURITY VIOLATIONS
# =============================================================================
# Check CloudFront distributions for secure configuration.
# =============================================================================

# Flag CloudFront that allows insecure HTTP connections
cloudfront_violations contains violation if {
	some r in resources
	r.type == "aws_cloudfront_distribution"
	r.viewer_protocol_policy != "redirect-to-https"
	violation := {
		"type": "insecure_protocol",
		"message": "CloudFront must redirect HTTP to HTTPS",
		"severity": "HIGH",
		"resource": r.name,
		"address": address_of(r),
	}
}

# Flag CloudFront using old/weak encryption
cloudfront_violations contains violation if {
	some r in resources
	r.type == "aws_cloudfront_distribution"
	r.minimum_protocol_version != "TLSv1.2_2021"
	violation := {
		"type": "weak_tls",
		"message": "CloudFront must use TLS 1.2 or higher",
		"severity": "MEDIUM",
		"resource": r.name,
		"address": address_of(r),
	}
}

# =============================================================================
# SECTION 508 ACCESSIBILITY VIOLATIONS
# =============================================================================
# Check HTML content for accessibility compliance.
# =============================================================================

# Flag HTML files that don't have a language declaration
accessibility_violations contains violation if {
	is_html_input
	input.html_content != ""
	not contains(input.html_content, "html lang=")
	violation := {
		"type": "missing_language_declaration",
		"message": sprintf("HTML file %s missing language declaration (html lang attribute)", [input.file_name]),
		"severity": "HIGH",
		"resource": input.file_name,
	}
}

# Flag HTML files that have images without alt text
accessibility_violations contains violation if {
	is_html_input
	input.html_content != ""
	contains(input.html_content, "<img")
	img_without_alt := regex.find_all_string_submatch_n(
		`<img[^>]*(?:(?!alt=)[^>])*>`,
		input.html_content, -1,
	)
	count(img_without_alt) > 0
	violation := {
		"type": "missing_alt_text",
		"message": sprintf("HTML file %s contains images without alt text", [input.file_name]),
		"severity": "HIGH",
		"resource": input.file_name,
	}
}

# Flag HTML files that don't have proper heading structure
accessibility_violations contains violation if {
	is_html_input
	input.html_content != ""
	not contains(input.html_content, "<h1")
	violation := {
		"type": "missing_main_heading",
		"message": sprintf("HTML file %s missing main heading (h1 element)", [input.file_name]),
		"severity": "MEDIUM",
		"resource": input.file_name,
	}
}

# Flag HTML files that have empty alt attributes (alt="" with no text)
accessibility_violations contains violation if {
	is_html_input
	input.html_content != ""
	contains(input.html_content, `alt=""`)
	not contains(input.html_content, "decorative")
	violation := {
		"type": "empty_alt_text",
		"message": sprintf("HTML file %s contains images with empty alt text", [input.file_name]),
		"severity": "MEDIUM",
		"resource": input.file_name,
	}
}

# Flag HTML files missing proper document structure
accessibility_violations contains violation if {
	is_html_input
	input.html_content != ""
	not contains(input.html_content, "<!DOCTYPE html>")
	violation := {
		"type": "missing_doctype",
		"message": sprintf("HTML file %s missing DOCTYPE declaration", [input.file_name]),
		"severity": "LOW",
		"resource": input.file_name,
	}
}

# =============================================================================
# OVERALL COMPLIANCE DECISION
# =============================================================================
# Decide whether deployment should be allowed or blocked.
# =============================================================================

# Start by assuming everything is compliant
default compliant := true

# Block deployment if the input shape was not recognized (fail closed)
compliant := false if count(input_errors) > 0

# Block deployment if any S3 bucket has violations
compliant := false if count(s3_bucket_violations) > 0

# Block deployment if any CloudFront has violations
compliant := false if count(cloudfront_violations) > 0

# Block deployment if any classification violations are found
compliant := false if count(classification_violations) > 0

# Block deployment if any accessibility violations are found
compliant := false if count(accessibility_violations) > 0

# =============================================================================
# COLLECT ALL VIOLATIONS
# =============================================================================

# Combine all violations from infrastructure and accessibility checks
all_violations := (((s3_bucket_violations | cloudfront_violations) | accessibility_violations) | classification_violations) | input_errors

# =============================================================================
# PER-RESOURCE RESULTS FOR THE KSI SIGNAL EMITTER
# =============================================================================
# scripts/terraform-plan.sh turns these into validations.json entries, which
# scripts/build-ksi-signal.py joins to inventory components. The entry shape
# (kind / resource_type / resource_name / compliant / violations /
# policy_version) is a published contract — see the KSI signal schema.
# =============================================================================

violations_for(r) := [v |
	some v in all_violations
	object.get(v, "address", v.resource) == address_of(r)
]

resource_reports := [report |
	some address in sort([address_of(r) | some r in resources])
	some r in resources
	address_of(r) == address
	report := {
		"kind": "infrastructure",
		"resource_type": r.type,
		"resource_name": r.name,
		"compliant": count(violations_for(r)) == 0,
		"violations": violations_for(r),
		"policy_version": policy_version,
	}
]

# =============================================================================
# GENERATE FINAL COMPLIANCE REPORT
# =============================================================================
# Create a summary report showing what was checked and what was found.
# =============================================================================

compliance_report := {
	"compliant": compliant, # Overall pass/fail
	"total_violations": count(all_violations), # How many problems found
	"violations_by_severity": {
		"HIGH": count([v | some v in all_violations; v.severity == "HIGH"]), # Break down by severity
		"MEDIUM": count([v | some v in all_violations; v.severity == "MEDIUM"]),
		"LOW": count([v | some v in all_violations; v.severity == "LOW"]),
	},
	"violations_by_type": {
		"infrastructure": count(s3_bucket_violations | cloudfront_violations), # Break down by category
		"accessibility": count(accessibility_violations),
		"classification": count(classification_violations),
		"input": count(input_errors),
	},
	"violations": all_violations, # List of all problems
	# The emitter (terraform-plan.sh or the runtime Lambda) supplies the
	# observation timestamp via the KSI signal's `emitted_at`; not duplicated
	# here. This also keeps the rule pure so it compiles to Wasm cleanly
	# without needing the host to provide time.now_ns().
	"policy_version": policy_version, # Version of these rules
}
