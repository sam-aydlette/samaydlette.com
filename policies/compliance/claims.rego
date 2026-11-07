# =============================================================================
# FEDRAMP RULE CLAIMS (policy as code; SDR-CSO-FRR)
# =============================================================================
# Which records in data/frr-records.json claim more than their fields support.
# scripts/_frr.py collects the facts: the record as written, whether each piece
# of evidence resolves in this repository, and (in the deploy) which KSIs are
# short of two automated methods. This module decides; the deploy does not
# publish while `deny` is non-empty.
#
# The four statuses (CLAUDE.md, proof-of-concept latitude):
#
#   Implemented       a real mechanism ran on real inputs, and evidence exists
#   Not Demonstrated  buildable, not built yet; the record says what is missing
#   Impractical       one engineer with cheap AWS cannot meet it; the record
#                     names the reason (one-person, no-budget with its cost,
#                     no-outside-party) and what was built anyway
#   Not Applicable    the rule's trigger cannot happen here; the record names
#                     the missing trigger
#
# An honest status never appears in `deny`. Only Implemented counts as met.
# Impractical and Not Applicable are proposed by anyone and approved only by
# the operator.
#
# Entry point: data.compliance.claims.deny, a set of {frr_id, why}.
# =============================================================================

package compliance.claims

needs_approval := {"Impractical", "Not Applicable"}

reasons := {"one-person", "no-budget", "no-outside-party"}

# The rule that every in-scope KSI has two automated methods (Class C).
two_methods_rule := "FRC-CSX-VVK"

# --- Implemented -------------------------------------------------------------

deny contains {"frr_id": r.frr_id, "why": "Implemented without evidence"} if {
	some r in input.records
	r.status == "Implemented"
	count(object.get(r, "evidence", [])) == 0
}

deny contains {"frr_id": r.frr_id, "why": sprintf("Implemented with a %s block", [k])} if {
	some r in input.records
	r.status == "Implemented"
	some k in ["impractical", "not_applicable", "not_demonstrated"]
	r[k]
}

deny contains {"frr_id": r.frr_id, "why": msg} if {
	some r in input.records
	r.frr_id == two_methods_rule
	r.status == "Implemented"
	not input.ksi_short
	msg := "Implemented, but no KSI method count was supplied to check it against"
}

deny contains {"frr_id": r.frr_id, "why": msg} if {
	some r in input.records
	r.frr_id == two_methods_rule
	r.status == "Implemented"
	count(input.ksi_short) > 0
	msg := sprintf("Implemented, but %d KSI(s) have fewer than two automated methods: %s", [
		count(input.ksi_short),
		concat(", ", sort(input.ksi_short)),
	])
}

# --- every status: evidence must resolve ------------------------------------

deny contains {"frr_id": r.frr_id, "why": msg} if {
	some r in input.records
	some ev in object.get(r, "evidence", [])
	not ev.resolves
	msg := sprintf("%s evidence %q does not resolve: %s", [ev.kind, ev.ref, ev.why])
}

# --- Not Demonstrated --------------------------------------------------------

deny contains {"frr_id": r.frr_id, "why": "Not Demonstrated without saying what is missing"} if {
	some r in input.records
	r.status == "Not Demonstrated"
	not r.not_demonstrated
}

# --- Impractical -------------------------------------------------------------

deny contains {"frr_id": r.frr_id, "why": "Impractical without an impractical block"} if {
	some r in input.records
	r.status == "Impractical"
	not r.impractical
}

deny contains {"frr_id": r.frr_id, "why": "Impractical without a reason"} if {
	some r in input.records
	r.status == "Impractical"
	count(object.get(r.impractical, "reasons", [])) == 0
}

deny contains {"frr_id": r.frr_id, "why": sprintf("Impractical reason %q is not one of %v", [x, sort(reasons)])} if {
	some r in input.records
	r.status == "Impractical"
	some x in r.impractical.reasons
	not x in reasons
}

deny contains {"frr_id": r.frr_id, "why": "Impractical for no-budget without naming the cost"} if {
	some r in input.records
	r.status == "Impractical"
	"no-budget" in r.impractical.reasons
	not r.impractical.cost
}

deny contains {"frr_id": r.frr_id, "why": "Impractical without saying why one engineer cannot meet it"} if {
	some r in input.records
	r.status == "Impractical"
	r.impractical
	not r.impractical.why
}

# --- Not Applicable ----------------------------------------------------------

deny contains {"frr_id": r.frr_id, "why": "Not Applicable without naming the missing trigger"} if {
	some r in input.records
	r.status == "Not Applicable"
	not r.not_applicable
}

# "It's a proof of concept" is not a reason (CLAUDE.md).
deny contains {"frr_id": r.frr_id, "why": "Not Applicable because it is a proof of concept: name the missing trigger"} if {
	some r in input.records
	r.status == "Not Applicable"
	regex.match(`(?i)proof[ -]of[ -]concept`, r.not_applicable)
}

# --- stand-ins and scope cuts wait on the operator ---------------------------

deny contains {"frr_id": r.frr_id, "why": sprintf("%s without a proposal (who proposed it, when)", [r.status])} if {
	some r in input.records
	r.status in needs_approval
	not r.proposal
}

deny contains {"frr_id": r.frr_id, "why": sprintf("%s not approved by the operator", [r.status])} if {
	some r in input.records
	r.status in needs_approval
	not r.approval
}

deny contains {"frr_id": r.frr_id, "why": sprintf("approved by %q: only the operator approves", [r.approval.by])} if {
	some r in input.records
	r.approval.by != input.operator
}

deny contains {"frr_id": r.frr_id, "why": sprintf("an approval on a record whose status is %s", [r.status])} if {
	some r in input.records
	r.approval
	not r.status in needs_approval
}
