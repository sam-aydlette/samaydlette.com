# =============================================================================
# LOG ACCESS (KSI-MLA-ALA)
# =============================================================================
# Reads IAM policy documents (aws_iam_role_policy, aws_iam_group_policy,
# aws_iam_policy) and the log buckets' policies (aws_s3_bucket_policy) the same
# way package policy.terraform.iam does, from a plan or from the runtime
# emitter's live answers, and judges who they let read log data.
# =============================================================================

package policy.terraform.log_access

import data.policy.gate
import data.policy.terraform.iam

# Who may read log data is an allowlist in data.config.gate.log_access.readers.
# Each entry names a reader ("role:<role name>", "group:<group name>",
# "policy:<managed policy name>" or "service:<service principal>"), the actions
# and the resources it may read, its basis and who decided it. A grant of a
# log-content read fails unless an entry covers that reader, that action and
# that resource; a broader grant on an allowlisted reader still fails. In a
# log bucket's own policy only a service principal can be allowlisted. Grants
# are found wherever they are written: an inline or managed IAM policy, or the
# policy of a log bucket (data.config.gate.log_access.log_buckets: the
# access-log and CloudTrail buckets). Reads of log CONTENT only: object reads
# in a log bucket, CloudWatch Logs event reads and queries, and the CloudTrail
# event history. Bucket configuration reads (s3:GetBucket*) and delivery
# writes are not reads of log data. A granted action or resource with a
# wildcard anywhere but at its end is treated as matching a log read.
#
# The known-bad fixture is Curious Carl (simulated), an intern whose role was
# handed log reads "just to look around" (tests/fixtures/plans/
# log-read-grant-curious-carl.json); the gate must stop him on every run.
#
# Not evaluated here: AWS-managed policies attached by ARN (ReadOnlyAccess and
# the like), whose documents are not in the plan or the runtime input.

log_object_actions := {"s3:getobject", "s3:getobjectversion", "s3:getobjecttorrent"}

log_event_actions := {
	"logs:getlogevents",
	"logs:filterlogevents",
	"logs:startquery",
	"logs:startlivetail",
	"logs:getlogrecord",
	"logs:getqueryresults",
	"cloudtrail:lookupevents",
}

# A pattern with a wildcard other than one trailing "*" is assumed to match.
wildcard_inside(p) if contains(trim_suffix(p, "*"), "*")

wildcard_inside(p) if contains(p, "?")

pattern_matches(p, s) if lower(p) == s

pattern_matches(p, s) if {
	endswith(p, "*")
	not wildcard_inside(p)
	startswith(s, trim_suffix(lower(p), "*"))
}

pattern_matches(p, _) if wildcard_inside(p)

# The Allow statement's actions, or every action for a NotAction statement.
statement_actions(s) := {"*"} if object.get(s, "NotAction", null) != null

else := iam.actions(s)

# A NotResource statement may reach anything.
statement_resources(s) := {"*"} if object.get(s, "NotResource", null) != null

else := iam.resources_of(s)

grants_action(s, wanted) if {
	some a in statement_actions(s)
	some w in wanted
	pattern_matches(a, w)
}

# The resource pattern reaches objects in log bucket `b`.
reaches_log_objects(res, b) if pattern_matches(res, sprintf("arn:aws:s3:::%s/", [b]))

reaches_log_objects(res, b) if {
	startswith(lower(res), sprintf("arn:aws:s3:::%s/", [b]))
}

# An IAM statement that grants a read of log content.
reads_logs(s) if grants_action(s, log_event_actions)

reads_logs(s) if {
	grants_action(s, log_object_actions)
	some res in statement_resources(s)
	some b in data.config.gate.log_access.log_buckets
	reaches_log_objects(res, b)
}

# Last segment of a role or group reference (a name, an id or an ARN).
last_segment(x) := parts[count(parts) - 1] if parts := split(x, "/")

holder_attribute := {
	"aws_iam_role_policy": ["role", "role"],
	"aws_iam_group_policy": ["group", "group"],
	"aws_iam_policy": ["name", "policy"],
}

# The identity an IAM policy document grants to, as an allowlist key.
policy_holder(r) := sprintf("%s:%s", [kind, last_segment(ref)]) if {
	[attr, kind] := holder_attribute[r.type]
	ref := gate.value(r, attr, null)
	is_string(ref)
}

# An IAM grant of a log read not covered for its holder; a holder that cannot be
# determined (absent, not merely computed at apply time) is never covered.
unallowed_holder_read(r, s) if uncovered_read(policy_holder(r), s, data.config.gate.log_access.log_buckets)

unallowed_holder_read(r, _) if not policy_holder(r)

holder_deferred(r) if {
	[attr, _] := holder_attribute[r.type]
	gate.planned_unknown(r, attr)
}

# The allowlist keys a bucket-policy statement grants to. Only a service
# principal has a key. An AWS principal never does, even a role: the policy
# names it by ARN, and a role name alone would also match a role of that name
# in another account, whose account cannot be checked here without committing
# an account ID. Log readers are authorized through their own IAM policies,
# where the holder is in this account by construction.
statement_readers(s) := {"*"} if iam.public_principal(s)

else := {key |
	some kind, vals in iam.principal(s)
	some v in gate.as_list(vals)
	key := principal_key(kind, v)
}

principal_key("Service", v) := sprintf("service:%s", [v])

principal_key(kind, _) := "*" if kind != "Service"

# A pattern from the allowlist covers a granted action or resource string. An
# allowlist pattern may use "*" (at most twice); anything else must match
# exactly. A grant broader than its entry is not covered and fails.
covers(p, x) if p == x

covers(p, x) if {
	parts := split(p, "*")
	count(parts) == 2
	count(x) >= count(parts[0]) + count(parts[1])
	startswith(x, parts[0])
	endswith(x, parts[1])
}

covers(p, x) if {
	parts := split(p, "*")
	count(parts) == 3
	count(x) >= count(parts[0]) + count(parts[2])
	startswith(x, parts[0])
	endswith(x, parts[2])
	contains(substring(x, count(parts[0]), (count(x) - count(parts[0])) - count(parts[2])), parts[1])
}

# The allowlist entry for `key` grants this one action on this one resource.
pair_allowed(key, a, res) if {
	some e in data.config.gate.log_access.readers
	e.reader == key
	lower(a) in {lower(x) | some x in e.actions}
	some p in e.resources
	covers(p, res)
}

# Each (action, resource) pair of an Allow statement that reads log data in
# bucket scope `buckets` (every log bucket for an IAM policy, the one bucket for
# a bucket policy).
log_read_pairs(s, buckets) := {[a, res] |
	some a in statement_actions(s)
	some res in statement_resources(s)
	pair_reads_logs(a, res, buckets)
}

pair_reads_logs(a, _, _) if {
	some w in log_event_actions
	pattern_matches(a, w)
}

pair_reads_logs(a, res, buckets) if {
	some w in log_object_actions
	pattern_matches(a, w)
	some b in buckets
	reaches_log_objects(res, b)
}

# A log read granted to `key` that no allowlist entry covers.
uncovered_read(key, s, buckets) if {
	some [a, res] in log_read_pairs(s, buckets)
	not pair_allowed(key, a, res)
}

log_bucket_policy(r) if {
	r.type == "aws_s3_bucket_policy"
	gate.value(r, "bucket", null) in {b | some b in data.config.gate.log_access.log_buckets}
}

bucket_policy_allows(r) := [s |
	raw := gate.value(r, "policy", null)
	is_string(raw)
	some s in iam.statements(iam.parsed(raw))
	s.Effect == "Allow"
]

bucket_statement_reads(s, b) if {
	grants_action(s, log_object_actions)
	some res in statement_resources(s)
	reaches_log_objects(res, b)
}

bucket_statement_reads(s, _) if grants_action(s, log_event_actions)

# METADATA
# title: Log data is readable only by allowlisted readers
# description: >-
#   An IAM policy or a log bucket's policy must not grant a read of log content
#   (log bucket objects, CloudWatch Logs events and queries, the CloudTrail event
#   history) to an identity outside data.config.gate.log_access.readers.
# custom:
#   id: log_read_grant_unexpected
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [au-6.7]
#   ksi_ids: [KSI-MLA-ALA]
#   resource_types: [aws_iam_group_policy, aws_iam_policy, aws_iam_role_policy, aws_s3_bucket_policy]
violations contains violation if {
	some r in gate.resources
	r.type in object.keys(holder_attribute)
	not holder_deferred(r)
	some s in iam.allows(r)
	reads_logs(s)
	unallowed_holder_read(r, s)
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"IAM policy grants a read of log data to an identity outside the log-reader allowlist",
	)
}

# METADATA
# title: Log data is readable only by allowlisted readers
# description: >-
#   An IAM policy or a log bucket's policy must not grant a read of log content
#   (log bucket objects, CloudWatch Logs events and queries, the CloudTrail event
#   history) to an identity outside data.config.gate.log_access.readers.
# custom:
#   id: log_read_grant_unexpected
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [au-6.7]
#   ksi_ids: [KSI-MLA-ALA]
#   resource_types: [aws_iam_group_policy, aws_iam_policy, aws_iam_role_policy, aws_s3_bucket_policy]
violations contains violation if {
	some r in gate.resources
	log_bucket_policy(r)
	b := gate.value(r, "bucket", null)
	some s in bucket_policy_allows(r)
	bucket_statement_reads(s, b)
	some key in statement_readers(s)
	uncovered_read(key, s, {b})
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"Log bucket policy grants a read of log data to a principal outside the log-reader allowlist",
	)
}
