# =============================================================================
# KSI AUTOMATED METHODS (policy as code; FRC-CSX-VVK)
# =============================================================================
# How many automated methods test each Key Security Indicator, and the status
# that follows. Class C needs at least two per KSI. scripts/_ksi_methods.py
# collects the facts; this module decides; scripts/build-sdr.py publishes.
#
# A method is a mechanism at a stage. The same check run before deploy (plan)
# and again against production (live) counts twice (operator's decision,
# 2026-11-06 and 2026-11-07), but only where it really ran:
#
#   OPA rule   counts for each KSI in its custom.ksi_ids, at a stage, when that
#              stage evaluated a resource of a type in custom.resource_types
#              (`*` any). It passes there when it reported no violation on any
#              such resource. runtime_only rules count at live only.
#   check      every other mechanism (data/ksi-methods.json), at the stages
#              the collector observed it: ran, and passed or not.
#
# Status per KSI:
#   Not Applicable    an approved entry in data/ksi-applicability.json
#   Implemented       two or more passing methods and none failing
#   Not Demonstrated  otherwise; `failing` lists any method that ran and failed
#
# Entry point: data.compliance.ksi.result = {"ksis": {id: {...}}, "short": [...],
# "findings": [...]}
# =============================================================================

package compliance.ksi

stages := {"plan", "live", "deploy", "nightly"}

types_match(rule, _) if "*" in rule.resource_types

types_match(rule, tf_type) if tf_type in rule.resource_types

rule_stages(rule) := {"live"} if rule.runtime_only

rule_stages(rule) := {"plan", "live"} if not rule.runtime_only

# One OPA-rule method per (rule, stage) that evaluated a matching resource.
opa_methods contains m if {
	some rule in input.rules
	some stage in rule_stages(rule)
	some o in input.observations
	o.stage == stage
	types_match(rule, o.tf_type)
	m := {
		"method": sprintf("opa:%s", [rule.id]),
		"stage": stage,
		"ksis": rule.ksi_ids,
		"passed": opa_passed(rule, stage),
	}
}

default opa_passed(_, _) := true

opa_passed(rule, stage) := false if {
	some o in input.observations
	o.stage == stage
	types_match(rule, o.tf_type)
	rule.id in o.violation_ids
}

check_methods contains m if {
	some c in input.checks
	c.ran
	c.stage in stages
	m := {
		"method": sprintf("check:%s", [c.key]),
		"stage": c.stage,
		"ksis": c.ksis,
		"passed": c.passed,
	}
}

methods := opa_methods | check_methods

approved_na(id) if {
	some a in input.not_applicable
	a.ksi_id == id
	a.approved
}

methods_for(id) := sort([{"method": m.method, "stage": m.stage, "passed": m.passed} |
	some m in methods
	id in m.ksis
])

passing(id) := count([m | some m in methods_for(id); m.passed])

failing(id) := [sprintf("%s@%s", [m.method, m.stage]) | some m in methods_for(id); not m.passed]

status(id) := "Not Applicable" if approved_na(id)

status(id) := "Implemented" if {
	not approved_na(id)
	passing(id) >= 2
	count(failing(id)) == 0
}

status(id) := "Not Demonstrated" if {
	not approved_na(id)
	not implemented(id)
}

implemented(id) if {
	passing(id) >= 2
	count(failing(id)) == 0
}

ksis := {id: {
	"status": status(id),
	"methods": methods_for(id),
	"passing": passing(id),
	"failing": failing(id),
} |
	some id in input.ksis
}

# In-scope KSIs short of two passing methods (claims.rego checks FRC-CSX-VVK
# against this list).
short := sort([id |
	some id in input.ksis
	not approved_na(id)
	passing(id) < 2
])

# Anything that could not be verified is a finding, never a quiet loss of
# credit: a check that did not run, a rule with nothing to evaluate at a stage
# (an inventory gap), and a method that ran and failed.
findings contains {
	"kind": "not-run",
	"method": sprintf("check:%s", [c.key]),
	"stage": c.stage,
	"ksis": c.ksis,
	"why": object.get(c, "why", "did not run"),
} if {
	some c in input.checks
	not c.ran
}

findings contains {
	"kind": "no-evaluation",
	"method": sprintf("opa:%s", [rule.id]),
	"stage": stage,
	"ksis": rule.ksi_ids,
	"why": "no resource of its types was evaluated at this stage",
} if {
	some rule in input.rules
	count(rule.resource_types) > 0
	some stage in rule_stages(rule)
	not evaluated(rule, stage)
}

findings contains {
	"kind": "failed",
	"method": m.method,
	"stage": m.stage,
	"ksis": m.ksis,
	"why": "ran and did not pass",
} if {
	some m in methods
	not m.passed
}

evaluated(rule, stage) if {
	some o in input.observations
	o.stage == stage
	types_match(rule, o.tf_type)
}

result := {"ksis": ksis, "short": short, "findings": sort(findings)}
