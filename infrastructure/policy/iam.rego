# =============================================================================
# IAM POLICY: PRIVILEGE AND TRUST
# =============================================================================
# Checks IAM roles, their inline policies, IAM groups and the GitHub OIDC
# provider. The same rules read a Terraform plan (deploy gate) and the live
# GetRole / GetRolePolicy / GetGroupPolicy / GetOpenIDConnectProvider answers
# the runtime emitter writes under the same Terraform attribute names
# (`values.assume_role_policy`, `values.policy`, `values.client_id_list`).
#
# Policy documents arrive as JSON strings, exactly as Terraform and the IAM API
# carry them, and are parsed here. A document that does not parse is reported
# as unreadable (category input), never treated as an empty, harmless policy.
#
# Runtime-only facts (no Terraform attribute exists for them on the resource):
#   values.attached_policy_arns  managed policies attached to a role or group
#   values.inline_policies       a group's inline policy documents (strings)
# =============================================================================

package policy.terraform.iam

import data.policy.gate

policy_types := {"aws_iam_role_policy", "aws_iam_policy", "aws_iam_group_policy"}

statements(doc) := gate.as_list(doc.Statement)

# Every policy document a resource carries, as raw strings.
documents(r) := [p] if {
	r.type in policy_types
	p := gate.value(r, "policy", null)
	is_string(p)
} else := [p | some p in gate.value(r, "inline_policies", []); is_string(p)] if {
	r.type == "aws_iam_group"
} else := []

# A policy resource whose document is absent (and not merely computed at apply
# time, nor declared unreadable by the runtime emitter) cannot be assessed.
document_missing(r) if {
	r.type in policy_types
	not is_string(gate.value(r, "policy", null))
	not gate.planned_unknown(r, "policy")
	gate.attribute_read_ok(r, "policy")
}

parsed(raw) := doc if {
	doc := json.unmarshal(raw)
	is_object(doc)
}

allows(r) := [s |
	some raw in documents(r)
	some s in statements(parsed(raw))
	s.Effect == "Allow"
]

actions(s) := {a | some a in gate.as_list(object.get(s, "Action", []))}

resources_of(s) := {x | some x in gate.as_list(object.get(s, "Resource", []))}

document_unreadable(r) if {
	some raw in documents(r)
	not parsed(raw)
}

document_unreadable(r) if document_missing(r)

grants_everything(s) if {
	"*" in actions(s)
	"*" in resources_of(s)
}

grants_everything(s) if object.get(s, "NotAction", null) != null

# --- role trust ---------------------------------------------------------------

trust_statements(r) := [s |
	r.type == "aws_iam_role"
	raw := gate.value(r, "assume_role_policy", null)
	is_string(raw)
	some s in statements(parsed(raw))
	s.Effect == "Allow"
]

trust_unreadable(r) if {
	r.type == "aws_iam_role"
	raw := gate.value(r, "assume_role_policy", null)
	is_string(raw)
	not parsed(raw)
}

# A role whose trust policy is computed at apply time is checked live instead.
trust_unreadable(r) if {
	r.type == "aws_iam_role"
	not is_string(gate.value(r, "assume_role_policy", null))
	not gate.planned_unknown(r, "assume_role_policy")
	gate.attribute_read_ok(r, "assume_role_policy")
}

principal(s) := p if {
	p := s.Principal
	is_object(p)
} else := {}

public_principal(s) if s.Principal == "*"

public_principal(s) if "*" in gate.as_list(object.get(principal(s), "AWS", []))

github_federated(s) if {
	some f in gate.as_list(object.get(principal(s), "Federated", []))
	endswith(f, "oidc-provider/token.actions.githubusercontent.com")
}

condition_values(s, key) := {v |
	some block in object.get(s, "Condition", {})
	some k, val in block
	k == key
	some v in gate.as_list(val)
}

github_trust_scoped(s) if {
	condition_values(s, "token.actions.githubusercontent.com:aud") == {data.config.gate.iam.github_oidc_audience}
	subs := condition_values(s, "token.actions.githubusercontent.com:sub")
	count(subs) > 0
	every v in subs {
		startswith(v, data.config.gate.iam.github_oidc_subject_prefix)
		not contains(v, "*")
	}
}

# METADATA
# title: IAM policy documents parse
# description: An IAM policy document that cannot be parsed cannot be assessed.
# custom:
#   id: iam_policy_unreadable
#   category: input
#   severity: HIGH
#   nist_controls: [ac-6]
#   ksi_ids: [KSI-IAM-ELP]
violations contains violation if {
	some r in gate.resources
	document_unreadable(r)
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"IAM policy document could not be parsed; its privileges are unassessed",
	)
}

# METADATA
# title: No IAM policy grants every action on every resource
# description: >-
#   An Allow of Action "*" on Resource "*", or an Allow written with
#   NotAction, is administrator access and defeats least privilege.
# custom:
#   id: iam_admin_wildcard
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [ac-6]
#   ksi_ids: [KSI-IAM-ELP]
violations contains violation if {
	some r in gate.resources
	some s in allows(r)
	grants_everything(s)
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"IAM policy allows every action on every resource (Action/NotAction wildcard)",
	)
}

# METADATA
# title: No IAM policy grants a whole service on every resource
# description: An Allow of "<service>:*" on Resource "*" grants every action of that service account-wide.
# custom:
#   id: iam_service_wildcard
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [ac-6]
#   ksi_ids: [KSI-IAM-ELP]
violations contains violation if {
	some r in gate.resources
	some s in allows(r)
	"*" in resources_of(s)
	some a in actions(s)
	endswith(a, ":*")
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		sprintf("IAM policy allows %s on every resource", [a]),
	)
}

# METADATA
# title: No administrator policy attached
# description: The AWS-managed AdministratorAccess policy must not be attached to a role or group.
# custom:
#   id: iam_admin_policy_attached
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [ac-6]
#   ksi_ids: [KSI-IAM-ELP, KSI-IAM-JIT]
violations contains violation if {
	some r in gate.resources
	r.type in {"aws_iam_role", "aws_iam_group"}
	some arn in array.concat(
		gate.as_list(gate.value(r, "managed_policy_arns", [])),
		gate.as_list(gate.value(r, "attached_policy_arns", [])),
	)
	endswith(arn, ":policy/AdministratorAccess")
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"AdministratorAccess is attached",
	)
}

# METADATA
# title: Role trust policy readable
# description: A role whose trust policy cannot be read cannot be assessed for who may assume it.
# custom:
#   id: iam_trust_unreadable
#   category: input
#   severity: HIGH
#   nist_controls: [ac-3]
#   ksi_ids: [KSI-IAM-ELP]
violations contains violation if {
	some r in gate.resources
	trust_unreadable(r)
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"IAM role trust policy is missing or could not be parsed; who may assume it is unassessed",
	)
}

# METADATA
# title: No role is assumable by anyone
# description: A trust policy must name its principals; "*" lets any AWS account assume the role.
# custom:
#   id: iam_trust_public
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [ac-3, ac-6]
#   ksi_ids: [KSI-IAM-ELP]
violations contains violation if {
	some r in gate.resources
	some s in trust_statements(r)
	public_principal(s)
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"IAM role trust policy allows any principal (\"*\")",
	)
}

# METADATA
# title: GitHub OIDC trust pinned to this repository
# description: >-
#   A role federated to GitHub Actions must require the STS audience and a
#   subject inside this repository with no wildcard, or any workflow in any
#   repository could assume it.
# custom:
#   id: iam_oidc_trust_unscoped
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [ia-3, ac-6.5]
#   ksi_ids: [KSI-IAM-SNU]
violations contains violation if {
	some r in gate.resources
	some s in trust_statements(r)
	github_federated(s)
	not github_trust_scoped(s)
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"GitHub OIDC trust is not pinned to the STS audience and a wildcard-free subject in this repository",
	)
}

# --- OIDC provider ------------------------------------------------------------

# METADATA
# title: OIDC provider audience is STS only
# description: The GitHub OIDC provider must accept exactly the STS audience.
# custom:
#   id: oidc_audience_unexpected
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [ia-3]
#   ksi_ids: [KSI-IAM-SNU]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_iam_openid_connect_provider"
	gate.attribute_read_ok(r, "client_id_list")
	not gate.planned_unknown(r, "client_id_list")
	{c | some c in gate.value(r, "client_id_list", [])} != {data.config.gate.iam.github_oidc_audience}
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"OIDC provider client ID list is not exactly the STS audience",
	)
}
