package iam_test

import data.policy.terraform.iam

ids(v) := {x.id | some x in v}

_res(type, values) := {"resource": {"type": type, "name": "x", "values": values}}

_doc(statements) := json.marshal({"Version": "2012-10-17", "Statement": statements})

_policy(type, statement) := _res(type, {"policy": _doc([statement])})

_trust(statement) := _res("aws_iam_role", {"assume_role_policy": _doc([statement])})

_github := "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"

_trust_input(condition) := _trust({
	"Effect": "Allow",
	"Action": "sts:AssumeRoleWithWebIdentity",
	"Principal": {"Federated": _github},
	"Condition": condition,
})

_aud := {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}

_sub_key := "token.actions.githubusercontent.com:sub"

# --- inline policies ---

test_scoped_policy_passes if {
	stmt := {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::b/*"]}
	count(iam.violations) == 0 with input as _policy("aws_iam_role_policy", stmt)
}

test_admin_wildcard_fails if {
	stmt := {"Effect": "Allow", "Action": "*", "Resource": "*"}
	"iam_admin_wildcard" in ids(iam.violations) with input as _policy("aws_iam_role_policy", stmt)
}

test_allow_not_action_fails if {
	stmt := {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
	"iam_admin_wildcard" in ids(iam.violations) with input as _policy("aws_iam_policy", stmt)
}

test_deny_wildcard_passes if {
	stmt := {"Effect": "Deny", "Action": "*", "Resource": "*"}
	count(iam.violations) == 0 with input as _policy("aws_iam_role_policy", stmt)
}

test_service_wildcard_on_everything_fails if {
	stmt := {"Effect": "Allow", "Action": ["kms:*"], "Resource": "*"}
	"iam_service_wildcard" in ids(iam.violations) with input as _policy("aws_iam_role_policy", stmt)
}

test_service_wildcard_on_one_resource_passes if {
	stmt := {"Effect": "Allow", "Action": "s3:*", "Resource": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"]}
	count(iam.violations) == 0 with input as _policy("aws_iam_group_policy", stmt)
}

test_unparseable_policy_is_unassessed if {
	"iam_policy_unreadable" in ids(iam.violations) with input as _res("aws_iam_role_policy", {"policy": "{not json"})
}

test_missing_policy_is_unassessed if {
	"iam_policy_unreadable" in ids(iam.violations) with input as _res("aws_iam_role_policy", {})
}

# A document computed at apply time is checked live, not failed at plan time.
test_policy_unknown_at_plan_is_deferred if {
	change := {"actions": ["create"], "after": {"name": "x"}, "after_unknown": {"policy": true}}
	plan := {"resource_changes": [{
		"address": "aws_iam_role_policy.x", "mode": "managed",
		"type": "aws_iam_role_policy", "name": "x", "change": change,
	}]}
	count(iam.violations) == 0 with input as plan
}

test_group_inline_policy_checked if {
	inline := _doc([{"Effect": "Allow", "Action": "*", "Resource": "*"}])
	values := {"name": "operators", "inline_policies": [inline]}
	"iam_admin_wildcard" in ids(iam.violations) with input as _res("aws_iam_group", values)
}

test_group_admin_attachment_fails if {
	values := {"attached_policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"]}
	"iam_admin_policy_attached" in ids(iam.violations) with input as _res("aws_iam_group", values)
}

test_group_read_only_attachment_passes if {
	values := {"attached_policy_arns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"], "inline_policies": []}
	count(iam.violations) == 0 with input as _res("aws_iam_group", values)
}

# --- role trust ---

test_service_trust_passes if {
	stmt := {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "lambda.amazonaws.com"}}
	count(iam.violations) == 0 with input as _trust(stmt)
}

test_public_trust_fails if {
	stmt := {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": ["*"]}}
	"iam_trust_public" in ids(iam.violations) with input as _trust(stmt)
}

test_star_principal_fails if {
	stmt := {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*"}
	"iam_trust_public" in ids(iam.violations) with input as _trust(stmt)
}

test_role_admin_attachment_fails if {
	trust := _doc([{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}}])
	values := {"assume_role_policy": trust, "attached_policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"]}
	"iam_admin_policy_attached" in ids(iam.violations) with input as _res("aws_iam_role", values)
}

test_missing_trust_is_unassessed if {
	"iam_trust_unreadable" in ids(iam.violations) with input as _res("aws_iam_role", {"name": "r"})
}

test_unparseable_trust_is_unassessed if {
	"iam_trust_unreadable" in ids(iam.violations) with input as _res("aws_iam_role", {"assume_role_policy": "nope"})
}

# An unreadable attribute is the gate's resource_read_error, not a second finding.
test_trust_read_error_not_duplicated if {
	res := {"type": "aws_iam_role", "name": "x", "values": {}, "read_errors": ["assume_role_policy"]}
	count(iam.violations) == 0 with input as {"resource": res}
}

test_github_trust_pinned_passes if {
	condition := {
		"StringEquals": _aud,
		"StringLike": {_sub_key: ["repo:sam-aydlette/samaydlette.com:environment:prod"]},
	}
	count(iam.violations) == 0 with input as _trust_input(condition)
}

test_github_trust_without_subject_fails if {
	"iam_oidc_trust_unscoped" in ids(iam.violations) with input as _trust_input({"StringEquals": _aud})
}

test_github_trust_other_repository_fails if {
	condition := {"StringEquals": object.union(_aud, {_sub_key: "repo:someone-else/fork:ref:refs/heads/main"})}
	"iam_oidc_trust_unscoped" in ids(iam.violations) with input as _trust_input(condition)
}

test_github_trust_wildcard_subject_fails if {
	condition := {"StringEquals": _aud, "StringLike": {_sub_key: "repo:sam-aydlette/samaydlette.com:*"}}
	"iam_oidc_trust_unscoped" in ids(iam.violations) with input as _trust_input(condition)
}

test_github_trust_wrong_audience_fails if {
	condition := {"StringEquals": {
		"token.actions.githubusercontent.com:aud": ["sts.amazonaws.com", "other"],
		_sub_key: "repo:sam-aydlette/samaydlette.com:pull_request",
	}}
	"iam_oidc_trust_unscoped" in ids(iam.violations) with input as _trust_input(condition)
}

# --- OIDC provider ---

test_oidc_sts_audience_passes if {
	values := {"client_id_list": ["sts.amazonaws.com"]}
	count(iam.violations) == 0 with input as _res("aws_iam_openid_connect_provider", values)
}

test_oidc_extra_audience_fails if {
	values := {"client_id_list": ["sts.amazonaws.com", "my-app"]}
	"oidc_audience_unexpected" in ids(iam.violations) with input as _res("aws_iam_openid_connect_provider", values)
}
