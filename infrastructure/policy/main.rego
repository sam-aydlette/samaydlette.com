# =============================================================================
# COMPLIANCE DECISION AND REPORT (AGGREGATOR)
# =============================================================================
# The package every consumer queries — and the Wasm entrypoint the runtime
# Lambda executes (terraform/compliance/compliance_report). It owns three
# things:
#
#   1. Dynamic aggregation: every `violations` set anywhere under data.policy
#      is collected via walk(). A new policy package participates in the gate
#      the moment it exists — no aggregator edits, no forgotten unions.
#   2. The fail-closed decision: `compliant` defaults to FALSE and is only
#      true when the input was recognized AND zero violations exist. An
#      evaluation error, an unrecognized input, or a rule that cannot be
#      evaluated all leave the gate shut.
#   3. The report shapes consumed downstream (compliance_report for humans
#      and the Lambda; resource_reports for the KSI signal emitter).
# =============================================================================

package terraform.compliance

import data.policy.gate

policy_version := "2.0"

# =============================================================================
# DYNAMIC AGGREGATION OVER data.policy
# =============================================================================

# CONVENTION: because this walks the entire data.policy subtree, ONLY policy
# packages may live under data.policy. Test packages go under
# data.policy_test — a test rule that referenced `compliant` from inside
# data.policy would create a static recursion cycle through this walk.
all_violations := {violation |
	walk(data.policy, [path, value])
	path[count(path) - 1] == "violations"
	some violation in value
}

# =============================================================================
# EXCEPTIONS-AS-CODE (POA&M-as-code)
# =============================================================================
# data.exceptions (infrastructure/policy/exceptions/data.json) is the
# machine-readable register of accepted findings: each entry names the
# violation it suppresses ({resource, rule_id}), the justification, an expiry
# date, and a ticket (the docs/poam.md or False Positives register entry it
# traces to). Suppression happens HERE, in the aggregator — never inside a
# rule — so every rule keeps reporting the raw fact and the report shows
# suppressed findings under `excepted` for auditability.
#
# Expiry is evaluated against data.runtime.evaluated_at (RFC3339, supplied by
# the wrapper script / the Lambda alongside the config document), not
# time.now_ns(), keeping evaluation deterministic and Wasm-host-independent.
# FAIL-SAFE: an exception with no parseable evaluation timestamp, or one past
# its expiry, does NOT suppress — the violation resurfaces. An expired entry
# also fails CI via scripts/check-exceptions.py.
# =============================================================================

exception_active(ex) if {
	evaluated_at := time.parse_rfc3339_ns(data.runtime.evaluated_at)
	expiry := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [ex.expiry]))
	evaluated_at < expiry
}

exceptions_for(violation) := [ex |
	some ex in data.exceptions
	ex.rule_id == violation.id
	ex.resource == violation.resource
	exception_active(ex)
]

active_violations := {violation |
	some violation in all_violations
	count(exceptions_for(violation)) == 0
}

# Suppressed findings stay visible: the report carries the violation AND the
# exception that silenced it, so an auditor sees what was accepted, why, by
# which ticket, and until when.
excepted := [{"violation": violation, "exception": exceptions_for(violation)[0]} |
	some violation in all_violations
	count(exceptions_for(violation)) > 0
]

# =============================================================================
# OVERALL COMPLIANCE DECISION — FAIL CLOSED
# =============================================================================

default compliant := false

compliant if {
	gate.valid_input
	count(active_violations) == 0
}

# =============================================================================
# PER-RESOURCE RESULTS FOR THE KSI SIGNAL EMITTER
# =============================================================================
# scripts/terraform-plan.sh turns these into validations.json entries, which
# scripts/build-ksi-signal.py joins to inventory components. The entry shape
# (kind / resource_type / resource_name / compliant / violations /
# policy_version) is a published contract — see the KSI signal schema.
# =============================================================================

violations_for(r) := [v |
	some v in active_violations
	object.get(v, "address", v.resource) == gate.address_of(r)
]

resource_reports := [report |
	some address in sort([gate.address_of(r) | some r in gate.resources])
	some r in gate.resources
	gate.address_of(r) == address
	report := {
		"kind": "infrastructure",
		"resource_type": r.type,
		"resource_name": r.name,
		"compliant": count(violations_for(r)) == 0,
		"violations": violations_for(r),
		"policy_version": policy_version,
	}
]

# =============================================================================
# GENERATE FINAL COMPLIANCE REPORT
# =============================================================================

# Category counts are derived from the violations themselves (zero-filled for
# the categories consumers expect to always see).
violations_by_type := object.union(
	{"infrastructure": 0, "accessibility": 0, "classification": 0, "input": 0},
	{category: n |
		some category in {c | some v in active_violations; c := v.category}
		n := count([v | some v in active_violations; v.category == category])
	},
)

# METADATA
# title: Compliance report
# description: The single decision document both enforcement points consume.
# entrypoint: true
compliance_report := {
	"compliant": compliant, # Overall pass/fail
	"total_violations": count(active_violations), # How many problems found
	"violations_by_severity": {
		"HIGH": count([v | some v in active_violations; v.severity == "HIGH"]),
		"MEDIUM": count([v | some v in active_violations; v.severity == "MEDIUM"]),
		"LOW": count([v | some v in active_violations; v.severity == "LOW"]),
	},
	"violations_by_type": violations_by_type,
	"violations": active_violations, # The findings the gate acts on
	"excepted": excepted, # Suppressed findings, kept visible for audit
	# The emitter (terraform-plan.sh or the runtime Lambda) supplies the
	# observation timestamp via the KSI signal's `emitted_at`; not duplicated
	# here. This also keeps the rule pure so it compiles to Wasm cleanly
	# without needing the host to provide time.now_ns().
	"policy_version": policy_version, # Version of these rules
}
