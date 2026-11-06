# =============================================================================
# LOGGING, MONITORING AND ALERTING
# =============================================================================
# CloudWatch log groups (retention, customer-key encryption), the CloudTrail
# trail (logging on, multi-region, log file validation), the alarms that page
# the operator (actions enabled and wired) and the EventBridge schedules that
# drive the monitors (enabled). Plan values at deploy time; Describe* answers
# under the same Terraform attribute names at runtime.
# =============================================================================

package policy.terraform.logging

import data.policy.gate

trail_logs_everywhere(r) if {
	gate.value(r, "enable_logging", true) == true
	gate.value(r, "is_multi_region_trail", false) == true
}

trail_logs_everywhere(r) if not gate.attribute_read_ok(r, "trail")

alarm_actionable(r) if {
	gate.value(r, "actions_enabled", true) == true
	count(gate.as_list(gate.value(r, "alarm_actions", []))) > 0
}

# METADATA
# title: Log groups keep logs for the retention floor
# description: >-
#   A log group with an expiry must keep events at least
#   data.config.gate.logging.min_retention_days (0, never expire, passes).
# custom:
#   id: log_retention_below_minimum
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [au-11]
#   ksi_ids: [KSI-MLA-OSM]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_cloudwatch_log_group"
	days := gate.value(r, "retention_in_days", 0)
	days > 0
	days < data.config.gate.logging.min_retention_days
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		sprintf(
			"Log group retention is %d days, below the %d-day floor",
			[days, data.config.gate.logging.min_retention_days],
		),
	)
}

# METADATA
# title: Log groups are encrypted with a customer-managed key
# description: Log events must be encrypted at rest under a customer-managed KMS key.
# custom:
#   id: log_group_not_cmk
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [au-9]
#   ksi_ids: [KSI-MLA-OSM]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_cloudwatch_log_group"
	gate.attribute_read_ok(r, "kms_key_id")
	not gate.planned_unknown(r, "kms_key_id")
	gate.value(r, "kms_key_id", "") == ""
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"Log group is not encrypted with a customer-managed KMS key",
	)
}

# METADATA
# title: The audit trail is logging
# description: The CloudTrail trail must be logging, across all regions.
# custom:
#   id: trail_not_logging
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [au-12]
#   ksi_ids: [KSI-MLA-LET]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_cloudtrail"
	not trail_logs_everywhere(r)
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"CloudTrail trail must be logging and multi-region",
	)
}

# METADATA
# title: The audit trail validates its log files
# description: CloudTrail log file integrity validation must be on.
# custom:
#   id: trail_log_validation_disabled
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [si-7]
#   ksi_ids: [KSI-SVC-VRI]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_cloudtrail"
	gate.attribute_read_ok(r, "trail")
	gate.value(r, "enable_log_file_validation", false) != true
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"CloudTrail log file validation must be enabled",
	)
}

# METADATA
# title: Alarms can page
# description: An alarm must have its actions enabled and at least one alarm action.
# custom:
#   id: alarm_not_actionable
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [si-4]
#   ksi_ids: [KSI-MLA-RVL]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_cloudwatch_metric_alarm"
	gate.attribute_read_ok(r, "alarm_actions")
	not gate.planned_unknown(r, "alarm_actions")
	not alarm_actionable(r)
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"Alarm has its actions disabled or no alarm action to notify",
	)
}

# METADATA
# title: Monitoring schedules are enabled
# description: The EventBridge rules that run the monitors must be enabled.
# custom:
#   id: schedule_disabled
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [ca-7]
#   ksi_ids: [KSI-MLA-EVC]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_cloudwatch_event_rule"
	gate.value(r, "state", "ENABLED") != "ENABLED"
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		sprintf("EventBridge rule state is %s, not ENABLED", [gate.value(r, "state", "")]),
	)
}
