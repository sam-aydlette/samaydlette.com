package log_access_test

import data.policy.terraform.log_access

ids(v) := {x.id | some x in v}

_res(type, values) := {"resource": {"type": type, "name": "x", "values": values}}

_v := "log_read_grant_unexpected"

got := ids(log_access.violations)

_logs := "samaydlette-com-logs"

_trail := "samaydlette-com-cloudtrail"

_doc(statements) := json.marshal({"Version": "2012-10-17", "Statement": statements})

# --- log access (log_read_grant_unexpected) ---

_role_policy(role, statement) := _res("aws_iam_role_policy", {"role": role, "policy": _doc([statement])})

_log_objects := "arn:aws:s3:::samaydlette-com-logs/*"

# Curious Carl (simulated), the intern who was handed log reads "just to look
# around": the gate stops him whatever form the grant takes.
test_carl_reading_log_bucket_objects_fails if {
	stmt := {"Effect": "Allow", "Action": "s3:GetObject", "Resource": _log_objects}
	_v in got with input as _role_policy("curious-carl-intern", stmt)
}

test_carl_reading_log_events_fails if {
	stmt := {"Effect": "Allow", "Action": ["logs:GetLogEvents", "logs:FilterLogEvents"], "Resource": "*"}
	_v in got with input as _role_policy("curious-carl-intern", stmt)
}

test_carl_reading_the_trail_history_fails if {
	stmt := {"Effect": "Allow", "Action": "cloudtrail:LookupEvents", "Resource": "*"}
	_v in got with input as _role_policy("curious-carl-intern", stmt)
}

test_carl_with_a_service_wildcard_on_the_log_bucket_fails if {
	stmt := {"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:aws:s3:::samaydlette-com-cloudtrail/AWSLogs/*"}
	_v in got with input as _role_policy("curious-carl-intern", stmt)
}

test_carl_with_a_mid_wildcard_is_matched_conservatively if {
	stmt := {"Effect": "Allow", "Action": "s3:Get?bject", "Resource": "arn:aws:s3:::*-logs/*"}
	_v in got with input as _role_policy("curious-carl-intern", stmt)
}

test_carl_via_not_action_fails if {
	stmt := {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
	_v in got with input as _role_policy("curious-carl-intern", stmt)
}

test_carl_in_a_group_policy_fails if {
	stmt := {"Effect": "Allow", "Action": "logs:StartQuery", "Resource": "*"}
	_v in got with input as _res(
		"aws_iam_group_policy",
		{"group": "interns", "policy": _doc([stmt])},
	)
}

test_carl_in_a_managed_policy_fails if {
	stmt := {"Effect": "Allow", "Action": "logs:GetLogEvents", "Resource": "*"}
	_v in got with input as _res(
		"aws_iam_policy",
		{"name": "carl-log-peek", "policy": _doc([stmt])},
	)
}

# The two grants the seeded allowlist covers, in the shape they take once
# applied (infrastructure/bootstrap/trust-access-logs.tf ReadEdgeAccessRecords,
# evidence-nightly.tf AuditLogReviewReads; account ID replaced).
_deploy := "github-actions-deploy-oidc"

_nightly := "github-actions-evidence-nightly-oidc"

_edge_read := {"Effect": "Allow", "Action": "s3:GetObject", "Resource": [
	"arn:aws:s3:::samaydlette-com-logs/cloudfront/*",
	"arn:aws:s3:::samaydlette-com-logs/AWSLogs/123456789012/CloudFront/*",
]}

_trail_read := {"Effect": "Allow", "Action": "cloudtrail:LookupEvents", "Resource": "*"}

test_seeded_deploy_edge_read_passes if {
	not _v in got with input as _role_policy(_deploy, _edge_read)
}

test_seeded_nightly_trail_read_passes if {
	not _v in got with input as _role_policy(_nightly, _trail_read)
}

test_seeded_reader_by_arn_passes if {
	role := sprintf("arn:aws:iam::123456789012:role/%s", [_nightly])
	not _v in got with input as _role_policy(role, _trail_read)
}

# Each entry covers its role's actions on its resources, not the role.
test_deploy_reading_the_whole_log_bucket_fails if {
	stmt := {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::samaydlette-com-logs/*"}
	_v in got with input as _role_policy(_deploy, stmt)
}

test_deploy_reading_the_trail_bucket_fails if {
	stmt := {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::samaydlette-com-cloudtrail/*"}
	_v in got with input as _role_policy(_deploy, stmt)
}

test_deploy_with_a_broader_action_fails if {
	stmt := object.union(_edge_read, {"Action": "s3:Get*"})
	_v in got with input as _role_policy(_deploy, stmt)
}

test_deploy_reading_the_trail_history_fails if {
	_v in got with input as _role_policy(_deploy, _trail_read)
}

test_nightly_reading_log_events_fails if {
	stmt := {"Effect": "Allow", "Action": "logs:GetLogEvents", "Resource": "*"}
	_v in got with input as _role_policy(_nightly, stmt)
}

test_nightly_reading_the_edge_records_fails if {
	_v in got with input as _role_policy(_nightly, _edge_read)
}

# Without the allowlist, both real grants fire: the list is what authorizes them.
test_empty_allowlist_fires_on_the_deploy_edge_read if {
	_v in got with input as _role_policy(_deploy, _edge_read)
		with data.config.gate.log_access.readers as []
}

test_empty_allowlist_fires_on_the_nightly_trail_read if {
	_v in got with input as _role_policy(_nightly, _trail_read)
		with data.config.gate.log_access.readers as []
}

# Every allowlist entry is scoped and carries its basis and an unconfirmed
# decision marker: the operator has not confirmed it.
test_every_allowlist_entry_is_scoped_and_unconfirmed if {
	every e in data.config.gate.log_access.readers {
		count(e.actions) > 0
		count(e.resources) > 0
		count(e.basis) > 0
		contains(e.decided_by, "not yet confirmed")
	}
}

test_bucket_configuration_reads_are_not_log_reads if {
	stmt := {
		"Effect": "Allow", "Action": ["s3:GetBucketPolicy", "s3:ListBucket"],
		"Resource": "arn:aws:s3:::samaydlette-com-logs",
	}
	count(log_access.violations) == 0 with input as _role_policy("curious-carl-intern", stmt)
}

test_object_read_on_the_bare_bucket_arn_is_not_a_log_read if {
	stmt := {"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:aws:s3:::samaydlette-com-logs"}
	count(log_access.violations) == 0 with input as _role_policy("curious-carl-intern", stmt)
}

test_object_read_on_another_bucket_passes if {
	stmt := {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::samaydlette.com/*"}
	count(log_access.violations) == 0 with input as _role_policy("curious-carl-intern", stmt)
}

test_denied_log_read_passes if {
	stmt := {"Effect": "Deny", "Action": "logs:GetLogEvents", "Resource": "*"}
	count(log_access.violations) == 0 with input as _role_policy("curious-carl-intern", stmt)
}

test_holder_unknown_at_plan_is_deferred_to_the_live_check if {
	stmt := {"Effect": "Allow", "Action": "logs:GetLogEvents", "Resource": "*"}
	r := {"resource": {
		"type": "aws_iam_role_policy", "name": "x",
		"values": {"policy": _doc([stmt])}, "unknown": {"role": true},
	}}
	not _v in got with input as r
}

test_holder_missing_fails_closed if {
	stmt := {"Effect": "Allow", "Action": "logs:GetLogEvents", "Resource": "*"}
	_v in got with input as _res("aws_iam_role_policy", {"policy": _doc([stmt])})
}

# --- the log buckets' own policies ---

_bucket_policy(bucket, statement) := _res("aws_s3_bucket_policy", {"bucket": bucket, "policy": _doc([statement])})

test_log_bucket_policy_granting_carl_fails if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"AWS": "arn:aws:iam::123456789012:role/curious-carl-intern"},
		"Action": "s3:GetObject", "Resource": "arn:aws:s3:::samaydlette-com-cloudtrail/*",
	}
	_v in got with input as _bucket_policy(_trail, stmt)
}

test_log_bucket_policy_granting_everyone_fails if {
	stmt := {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": _log_objects}
	_v in got with input as _bucket_policy(_logs, stmt)
}

test_log_bucket_policy_granting_an_account_fails if {
	stmt := {
		"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
		"Action": "s3:*", "Resource": "arn:aws:s3:::samaydlette-com-logs/*",
	}
	_v in got with input as _bucket_policy(_logs, stmt)
}

test_log_bucket_policy_delivery_writes_pass if {
	stmt := {
		"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
		"Action": ["s3:PutObject", "s3:GetBucketAcl"], "Resource": "arn:aws:s3:::samaydlette-com-cloudtrail/AWSLogs/*",
	}
	not _v in got with input as _bucket_policy(_trail, stmt)
}

# A role named in a bucket policy could be any account's role of that name, so
# the bucket policy can never be the way an allowlisted reader gets its read.
test_log_bucket_policy_naming_an_allowlisted_role_still_fails if {
	stmt := object.union(_edge_read, {"Principal": {"AWS": sprintf("arn:aws:iam::999999999999:role/%s", [_deploy])}})
	_v in got with input as _bucket_policy(_logs, stmt)
}

test_log_bucket_policy_allowlisted_service_passes if {
	stmt := object.union(_edge_read, {"Principal": {"Service": "logs-reader.example.amazonaws.com"}})
	not _v in got with input as _bucket_policy(_logs, stmt)
		with data.config.gate.log_access.readers as [{
			"reader": "service:logs-reader.example.amazonaws.com", "actions": ["s3:GetObject"],
			"resources": ["arn:aws:s3:::samaydlette-com-logs/cloudfront/*", "arn:aws:s3:::samaydlette-com-logs/AWSLogs/*"],
		}]
}

test_log_bucket_policy_allowlisted_role_broader_fails if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"AWS": sprintf("arn:aws:iam::123456789012:role/%s", [_deploy])},
		"Action": "s3:GetObject", "Resource": "arn:aws:s3:::samaydlette-com-logs/*",
	}
	_v in got with input as _bucket_policy(_logs, stmt)
}

test_other_bucket_policies_are_out_of_scope if {
	stmt := {
		"Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
		"Action": "s3:GetObject", "Resource": "arn:aws:s3:::samaydlette.com/*",
	}
	not _v in got with input as _bucket_policy("samaydlette.com", stmt)
}
