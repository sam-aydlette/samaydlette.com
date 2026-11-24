# =============================================================================
# API ENTRY POINT POLICY
# =============================================================================
# Every way into an application function must require an identity. An API
# Gateway HTTP API route reaches its integration with no check at all when its
# authorization type is NONE, and a Lambda function URL with authorization type
# NONE is a public HTTPS endpoint. Either one is an unauthenticated entry point,
# so either one fails the gate.
#
# An absent authorization type fails closed: the provider's default for both
# resources is NONE, so a plan that does not state one is treated as NONE.
# =============================================================================

package policy.terraform.api

import data.policy.gate

authorization_type(r) := object.get(r, ["values", "authorization_type"], object.get(r, "authorization_type", "NONE"))

# METADATA
# title: Every API Gateway route requires authorization
# description: An HTTP API route with authorization type NONE lets any request reach the integration.
# custom:
#   id: unauthenticated_api_route
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [ac-3, ia-2]
#   ksi_ids: [KSI-IAM-ELP, KSI-CNA-MAT]
#   resource_types: [aws_apigatewayv2_route]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_apigatewayv2_route"
	authorization_type(r) == "NONE"
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"API Gateway routes must require authorization (JWT, AWS_IAM or CUSTOM), not NONE",
	)
}

# METADATA
# title: No Lambda function URL is public
# description: A function URL with authorization type NONE is an unauthenticated public endpoint.
# custom:
#   id: unauthenticated_function_url
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [ac-3, ia-2]
#   ksi_ids: [KSI-IAM-ELP, KSI-CNA-MAT]
#   resource_types: [aws_lambda_function_url]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_lambda_function_url"
	authorization_type(r) == "NONE"
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"Lambda function URLs must use AWS_IAM authorization, not NONE",
	)
}
