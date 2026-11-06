# =============================================================================
# API GATEWAY AND FUNCTION ENDPOINTS
# =============================================================================
# The HTTP API fronting the Silk Reeling app: its stage must log access and
# throttle, and its API routes must require authorization. A Lambda function
# URL with no auth would bypass all of that, so none may exist.
#
# Runtime-only fact: aws_lambda_function.values.function_url_auth_type
# (GetFunctionUrlConfig AuthType; absent when the function has no URL).
# =============================================================================

package policy.terraform.network

import data.policy.gate

route_path(r) := path if {
	parts := split(gate.value(r, "route_key", ""), " ")
	count(parts) == 2
	path := parts[1]
}

public_function_url(r) if {
	r.type == "aws_lambda_function_url"
	gate.value(r, "authorization_type", "") == "NONE"
}

public_function_url(r) if {
	r.type == "aws_lambda_function"
	gate.value(r, "function_url_auth_type", "") == "NONE"
}

# METADATA
# title: API stage writes access logs
# description: Every API Gateway stage must send access logs to a log group.
# custom:
#   id: apigw_access_logging_disabled
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [au-12]
#   ksi_ids: [KSI-MLA-LET]
#   resource_types: [aws_apigatewayv2_stage]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_apigatewayv2_stage"
	not gate.planned_unknown(r, ["access_log_settings", 0, "destination_arn"])
	gate.value(r, ["access_log_settings", 0, "destination_arn"], "") == ""
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"API Gateway stage has no access log destination",
	)
}

# METADATA
# title: API stage throttles requests
# description: Every API Gateway stage must set a default route rate limit.
# custom:
#   id: apigw_unthrottled
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [sc-5]
#   ksi_ids: [KSI-CNA-RVP, KSI-CNA-RNT]
#   resource_types: [aws_apigatewayv2_stage]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_apigatewayv2_stage"
	not gate.value(r, ["default_route_settings", 0, "throttling_rate_limit"], 0) > 0
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"API Gateway stage has no default route throttling rate limit",
	)
}

# METADATA
# title: API routes require authorization
# description: >-
#   A route under one of data.config.gate.api.protected_route_prefixes must
#   carry an authorizer (authorization_type other than NONE).
# custom:
#   id: apigw_route_unauthorized
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [ac-3]
#   ksi_ids: [KSI-IAM-ELP, KSI-CNA-MAT]
#   resource_types: [aws_apigatewayv2_route]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_apigatewayv2_route"
	some prefix in data.config.gate.api.protected_route_prefixes
	startswith(route_path(r), prefix)
	gate.value(r, "authorization_type", "NONE") == "NONE"
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		sprintf("API route %s has no authorizer", [gate.value(r, "route_key", "")]),
	)
}

# METADATA
# title: No unauthenticated function URL
# description: A Lambda function URL with auth type NONE exposes the function to the internet, bypassing the API.
# custom:
#   id: lambda_public_function_url
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [sc-7]
#   ksi_ids: [KSI-CNA-ULN, KSI-CNA-DFP, KSI-CNA-MAT, KSI-CNA-RNT]
#   resource_types: [aws_lambda_function, aws_lambda_function_url]
violations contains violation if {
	some r in gate.resources
	public_function_url(r)
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"Lambda function URL allows unauthenticated invocation (auth type NONE)",
	)
}
