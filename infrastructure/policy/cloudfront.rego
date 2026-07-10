# =============================================================================
# CLOUDFRONT SECURITY POLICY
# =============================================================================
# Checks CloudFront distributions for secure transport configuration. In the
# production stack the distribution is managed by the operator-applied
# bootstrap stack and appears here only through the runtime Lambda's live
# GetDistributionConfig checks; the rules also cover any managed distribution
# that shows up in a plan.
#
# The TLS floor is an ordered minimum, parameterized as data (an 800-53
# organization-defined parameter): data.config.gate.tls.order ranks the
# CloudFront security-policy names weakest-to-strongest, and any version
# ranked at or above data.config.gate.tls.minimum passes. A version that is
# not in the order list at all fails closed — a policy name this config has
# never heard of cannot be presumed strong. When AWS ships a stronger policy,
# appending it to the order list (a data change, no logic edit) makes it
# pass.
# =============================================================================

package policy.terraform.cloudfront

import data.policy.gate

tls_rank(version) := i if {
	some i, v in data.config.gate.tls.order
	v == version
}

meets_tls_minimum(version) if {
	tls_rank(version) >= tls_rank(data.config.gate.tls.minimum)
}

# Flag CloudFront that allows insecure HTTP connections
violations contains violation if {
	some r in gate.resources
	r.type == "aws_cloudfront_distribution"
	r.viewer_protocol_policy != "redirect-to-https"
	violation := {
		"id": "insecure_protocol",
		"type": "insecure_protocol",
		"category": "infrastructure",
		"severity": "HIGH",
		"resource": r.name,
		"address": gate.address_of(r),
		"message": "CloudFront must redirect HTTP to HTTPS",
	}
}

# Flag CloudFront below the configured TLS floor
violations contains violation if {
	some r in gate.resources
	r.type == "aws_cloudfront_distribution"
	not meets_tls_minimum(r.minimum_protocol_version)
	violation := {
		"id": "weak_tls",
		"type": "weak_tls",
		"category": "infrastructure",
		"severity": "MEDIUM",
		"resource": r.name,
		"address": gate.address_of(r),
		# %q is avoided here deliberately: sprintf compiles to a host builtin
		# under Wasm, and the JS host (sprintf-js in opa-wasm) does not
		# support the %q verb — it would throw at runtime in the Lambda.
		"message": sprintf("CloudFront viewer security policy must rank at or above %s (got '%s')", [data.config.gate.tls.minimum, r.minimum_protocol_version]),
	}
}
