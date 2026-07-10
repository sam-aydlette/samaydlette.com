# =============================================================================
# CLOUDFRONT SECURITY POLICY
# =============================================================================
# Checks CloudFront distributions for secure transport configuration. In the
# production stack the distribution is managed by the operator-applied
# bootstrap stack and appears here only through the runtime Lambda's live
# GetDistribution checks; the rules also cover any managed distribution that
# shows up in a plan.
# =============================================================================

package policy.terraform.cloudfront

import data.policy.gate

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

# Flag CloudFront using old/weak encryption
violations contains violation if {
	some r in gate.resources
	r.type == "aws_cloudfront_distribution"
	r.minimum_protocol_version != "TLSv1.2_2021"
	violation := {
		"id": "weak_tls",
		"type": "weak_tls",
		"category": "infrastructure",
		"severity": "MEDIUM",
		"resource": r.name,
		"address": gate.address_of(r),
		"message": "CloudFront must use TLS 1.2 or higher",
	}
}
