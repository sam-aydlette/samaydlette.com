package api_test

import data.policy.terraform.api

_plan(type, after) := {"resource_changes": [{
	"address": sprintf("%s.r", [type]), "mode": "managed", "type": type, "name": "r",
	"change": {"actions": ["create"], "before": null, "after": after},
}]}

ids(v) := {x.id | some x in v}

test_a_route_with_a_jwt_authorizer_passes if {
	count(api.violations) == 0 with input as _plan("aws_apigatewayv2_route", {"route_key": "ANY /api/{proxy+}", "authorization_type": "JWT"})
}

test_an_iam_or_custom_route_passes if {
	count(api.violations) == 0 with input as _plan("aws_apigatewayv2_route", {"route_key": "GET /x", "authorization_type": "AWS_IAM"})
	count(api.violations) == 0 with input as _plan("aws_apigatewayv2_route", {"route_key": "GET /x", "authorization_type": "CUSTOM"})
}

test_a_default_route_without_authorization_fails if {
	ids(api.violations) == {"unauthenticated_api_route"} with input as _plan("aws_apigatewayv2_route", {"route_key": "$default", "authorization_type": "NONE"})
}

test_a_route_that_states_no_authorization_type_fails_closed if {
	ids(api.violations) == {"unauthenticated_api_route"} with input as _plan("aws_apigatewayv2_route", {"route_key": "$default"})
}

test_a_deleted_route_is_not_gated if {
	count(api.violations) == 0 with input as {"resource_changes": [{
		"address": "aws_apigatewayv2_route.r", "mode": "managed", "type": "aws_apigatewayv2_route", "name": "r",
		"change": {"actions": ["delete"], "before": {"authorization_type": "NONE"}, "after": null},
	}]}
}

test_a_public_function_url_fails if {
	ids(api.violations) == {"unauthenticated_function_url"} with input as _plan("aws_lambda_function_url", {"authorization_type": "NONE"})
}

test_an_iam_function_url_passes if {
	count(api.violations) == 0 with input as _plan("aws_lambda_function_url", {"authorization_type": "AWS_IAM"})
}

# The runtime Lambda's single-resource input shape.
test_the_runtime_input_shape_is_gated_too if {
	ids(api.violations) == {"unauthenticated_api_route"} with input as {"resource": {"type": "aws_apigatewayv2_route", "name": "r", "authorization_type": "NONE"}}
}
