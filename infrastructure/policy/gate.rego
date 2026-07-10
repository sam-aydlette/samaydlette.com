# =============================================================================
# INPUT CONTRACT AND NORMALIZATION
# =============================================================================
# The one package that reads raw input. Everything else in data.policy.*
# evaluates the uniform `resources` set this package derives, so a change in
# what Terraform emits — or a new input source entirely — is absorbed here,
# not in every rule.
#
# Three input shapes are accepted:
#
#   1. Raw `terraform show -json tfplan` output (deploy-time gate). This
#      package iterates `resource_changes`, skips resources whose only action
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
# Anything else — including an empty document — produces an explicit
# `input_error` violation and a non-compliant report. A gate that cannot
# recognize its input must fail closed, never pass vacuously.
# =============================================================================

# METADATA
# title: Gate input contract
# description: >-
#   Input-shape detection, fail-closed guard, and normalization of raw
#   terraform plan JSON into uniform resource objects.
# schemas:
#   - input: schema.gate_input
package policy.gate

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

# Every package under data.policy that gates something exposes a `violations`
# set of uniform objects: {id, type, category, severity, resource, address,
# message}. The aggregator (terraform.compliance) discovers these sets
# dynamically — adding a package requires no aggregator edit.
violations contains violation if {
	not valid_input
	violation := {
		"id": "input_error",
		"type": "input_error",
		"category": "input",
		"severity": "HIGH",
		"resource": "input",
		"address": "input",
		"message": "Input matches no supported shape (terraform plan JSON with resource_changes[], {resource: ...}, or {html_content, file_name}). Refusing to report compliance on input the policy cannot read.",
	}
}

# =============================================================================
# NORMALIZATION: RAW TERRAFORM PLAN -> UNIFORM RESOURCE OBJECTS
# =============================================================================
# `resources` is a set of uniform objects with `address`, `type`, `name`,
# `mode`, `tags`, `tags_all`, `values`, plus synthesized security fields for
# the types that need cross-resource joins. The runtime Lambda supplies one
# already-normalized object; a raw plan is normalized here.
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

address_of(r) := object.get(r, "address", object.get(r, "name", "unknown"))

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

# The evaluated resource set, whatever the input shape.
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
