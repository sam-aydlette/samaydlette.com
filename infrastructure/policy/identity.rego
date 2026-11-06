# =============================================================================
# IDENTITY PROVIDER POLICY (COGNITO USER POOL)
# =============================================================================
# The user pool gating the Silk Reeling app. Read from the plan's
# aws_cognito_user_pool values at deploy time and from DescribeUserPool,
# written under the same Terraform attribute names, at runtime.
# =============================================================================

package policy.terraform.cognito

import data.policy.gate

pools contains r if {
	some r in gate.resources
	r.type == "aws_cognito_user_pool"
}

# METADATA
# title: User pool requires MFA
# description: Every sign-in to the user pool must require a second factor.
# custom:
#   id: cognito_mfa_not_required
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [ia-2.1, ia-2.2]
#   ksi_ids: [KSI-IAM-APM]
#   resource_types: [aws_cognito_user_pool]
violations contains violation if {
	some r in pools
	gate.attribute_read_ok(r, "mfa_configuration")
	gate.value(r, "mfa_configuration", "OFF") != "ON"
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"Cognito user pool MFA must be ON (required for every user)",
	)
}

# METADATA
# title: User pool password length meets the floor
# description: The minimum password length must be at least data.config.gate.identity.min_password_length.
# custom:
#   id: cognito_password_too_short
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [ia-5.1]
#   ksi_ids: [KSI-IAM-APM]
#   resource_types: [aws_cognito_user_pool]
violations contains violation if {
	some r in pools
	gate.attribute_read_ok(r, "password_policy")
	not gate.value(r, ["password_policy", 0, "minimum_length"], 0) >= data.config.gate.identity.min_password_length
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		sprintf(
			"Cognito user pool minimum password length must be at least %d",
			[data.config.gate.identity.min_password_length],
		),
	)
}

# METADATA
# title: User pool accounts are provisioned by an administrator
# description: Self sign-up must be off, so every account is created deliberately.
# custom:
#   id: cognito_self_signup_enabled
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [ac-2]
#   ksi_ids: [KSI-IAM-JIT, KSI-IAM-AAM]
#   resource_types: [aws_cognito_user_pool]
violations contains violation if {
	some r in pools
	gate.attribute_read_ok(r, "admin_create_user_config")
	gate.value(r, ["admin_create_user_config", 0, "allow_admin_create_user_only"], false) != true
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"Cognito user pool allows self sign-up; accounts must be created by an administrator",
	)
}
