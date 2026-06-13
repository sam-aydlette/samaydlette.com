package vdr.triage

# false-positive: no risk, no remediation, no SLA
test_false_positive {
	d := decision with input as {
		"id": "CKV_AWS_144", "scanner_severity": "LOW",
		"asserted": {"disposition": "false-positive"},
	}
	d.disposition == "false-positive"
	d.remediation_required == false
	d.sla_days == null
	d.effective_severity == "NONE"
	d.decided_by == "disposition"
}

# operational requirement: real risk, accepted, not patched
test_operational_requirement {
	d := decision with input as {
		"id": "CKV_AWS_68", "scanner_severity": "MEDIUM", "internet_reachable": true,
		"asserted": {"disposition": "operational-requirement"},
	}
	d.disposition == "operational-requirement"
	d.remediation_required == false
	d.sla_days == null
}

# risk adjustment: HIGH cvss adjusted down to LOW is valid; remediates on the
# adjusted (lower) timeline
test_risk_adjustment_valid {
	d := decision with input as {
		"id": "CVE-2026-1", "cvss": 7.5,
		"internet_reachable": false, "likely_exploitable": false,
		"asserted": {"disposition": "risk-adjustment", "adjusted_severity": "LOW"},
	}
	d.effective_severity == "LOW"
	d.remediation_required == true
	d.invalid_risk_adjustment == false
	d.pain == "N1"
}

# risk adjustment that tries to keep/raise severity is flagged invalid
test_risk_adjustment_invalid {
	d := decision with input as {
		"id": "CVE-2026-2", "cvss": 4.0,
		"asserted": {"disposition": "risk-adjustment", "adjusted_severity": "HIGH"},
	}
	d.invalid_risk_adjustment == true
}

# immutable: a KEV vulnerability must be patched now regardless of thresholds
test_kev_must_patch_now {
	d := decision with input as {
		"id": "CVE-2026-3", "cvss": 9.8, "is_kev": true,
		"internet_reachable": true, "likely_exploitable": true,
		"asserted": {"disposition": "remediate"},
	}
	d.must_patch_now == true
	d.sla_days == 0
	d.decided_by == "immutable"
}

# threshold: HIGH, reachable + exploitable -> PAIN bumped, SLA from table
test_threshold_high_reachable_exploitable {
	d := decision with input as {
		"id": "CVE-2026-4", "cvss": 7.5, "is_kev": false,
		"internet_reachable": true, "likely_exploitable": true,
		"asserted": {"disposition": "remediate"},
	}
	d.pain == "N4" # HIGH(3) + reachable&exploitable bump = 4
	d.decided_by == "threshold"
	d.sla_days == 4 # N4|true|true
}

# historical: a shorter precedent tightens the timeline
test_historical_tightens {
	d := decision with input as {
		"id": "CVE-2026-5", "cvss": 5.0, "is_kev": false,
		"internet_reachable": false, "likely_exploitable": false,
		"historical": {"median_days": 10},
		"asserted": {"disposition": "remediate"},
	}
	d.decided_by == "historical"
	d.sla_days == 10
}

# escalation: architectural change required routes to a human
test_escalation_architectural {
	d := decision with input as {
		"id": "CVE-2026-6", "cvss": 6.0,
		"asserted": {"disposition": "remediate", "architectural_change_required": true},
	}
	d.escalate == true
	d.decided_by == "escalation"
	d.escalation_reason == "architectural change required"
}

# escalation: unprecedented critical risk with no history
test_escalation_unprecedented_critical {
	d := decision with input as {
		"id": "CVE-2026-7", "cvss": 9.5, "is_kev": false,
		"asserted": {"disposition": "remediate"},
	}
	d.escalate == true
	d.escalation_reason == "unprecedented critical risk, no historical precedent"
}

# default disposition is remediate when none asserted
test_default_disposition_remediate {
	d := decision with input as {"id": "CVE-2026-8", "cvss": 5.0, "asserted": {}}
	d.disposition == "remediate"
	d.remediation_required == true
}
