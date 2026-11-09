# Unit tests for policies/compliance/claims.rego. Each known-bad record must
# produce exactly the denial it is named for; each honest record none.
package compliance.claims_test

import data.compliance.claims

op := "Sam Aydlette"

signoff := {"by": op, "on": "2026-11-07"}

ok_ev := {"kind": "test", "ref": "tests/test_x.py::test_y", "resolves": true, "why": ""}

bad_ev := {"kind": "step", "ref": "deploy-with-opa.yml#Gone", "resolves": false, "why": "no step named 'Gone'"}

denies(rec) := {d.why | some d in claims.deny with input as {"operator": op, "records": [rec]}}

denies_ksi(rec, short) := {d.why | some d in claims.deny with input as {"operator": op, "records": [rec], "ksi_short": short}}

# --- honest records pass -----------------------------------------------------

test_implemented_with_resolving_evidence if {
	count(denies({"frr_id": "A", "status": "Implemented", "evidence": [ok_ev]})) == 0
}

test_not_demonstrated_saying_what_is_missing if {
	count(denies({"frr_id": "A", "status": "Not Demonstrated", "not_demonstrated": "no inbox yet"})) == 0
}

test_approved_impractical if {
	rec := {
		"frr_id": "A", "status": "Impractical",
		"impractical": {"reasons": ["no-budget", "one-person"], "why": "w", "cost": "$X a year"},
		"proposal": signoff, "approval": signoff,
	}
	count(denies(rec)) == 0
}

test_approved_not_applicable if {
	rec := {"frr_id": "A", "status": "Not Applicable", "not_applicable": "no application is made", "proposal": signoff, "approval": signoff}
	count(denies(rec)) == 0
}

test_two_methods_rule_with_no_short_ksi if {
	count(denies_ksi({"frr_id": "FRC-CSX-VVK", "status": "Implemented", "evidence": [ok_ev]}, [])) == 0
}

# --- known-bad records fail --------------------------------------------------

test_implemented_without_evidence if {
	"Implemented without evidence" in denies({"frr_id": "A", "status": "Implemented"})
}

test_implemented_with_a_scope_cut_block if {
	"Implemented with a not_applicable block" in denies({"frr_id": "A", "status": "Implemented", "evidence": [ok_ev], "not_applicable": "x"})
}

test_unresolved_evidence_on_any_status if {
	denies({"frr_id": "A", "status": "Not Demonstrated", "not_demonstrated": "x", "evidence": [bad_ev]}) == {"step evidence \"deploy-with-opa.yml#Gone\" does not resolve: no step named 'Gone'"}
}

test_two_methods_rule_without_a_count if {
	"Implemented, but no KSI method count was supplied to check it against" in denies({"frr_id": "FRC-CSX-VVK", "status": "Implemented", "evidence": [ok_ev]})
}

test_two_methods_rule_with_short_ksis if {
	"Implemented, but 2 KSI(s) have fewer than two automated methods: KSI-A, KSI-B" in denies_ksi({"frr_id": "FRC-CSX-VVK", "status": "Implemented", "evidence": [ok_ev]}, ["KSI-B", "KSI-A"])
}

test_not_demonstrated_silent if {
	"Not Demonstrated without saying what is missing" in denies({"frr_id": "A", "status": "Not Demonstrated"})
}

test_impractical_without_block if {
	"Impractical without an impractical block" in denies({"frr_id": "A", "status": "Impractical", "proposal": signoff, "approval": signoff})
}

test_impractical_without_reason if {
	"Impractical without a reason" in denies({"frr_id": "A", "status": "Impractical", "impractical": {"reasons": [], "why": "w"}, "proposal": signoff, "approval": signoff})
}

test_impractical_unknown_reason if {
	d := denies({"frr_id": "A", "status": "Impractical", "impractical": {"reasons": ["too-hard"], "why": "w"}, "proposal": signoff, "approval": signoff})
	d == {"Impractical reason \"too-hard\" is not one of [\"no-budget\", \"no-outside-party\", \"one-person\"]"}
}

test_no_budget_without_cost if {
	"Impractical for no-budget without naming the cost" in denies({"frr_id": "A", "status": "Impractical", "impractical": {"reasons": ["no-budget"], "why": "w"}, "proposal": signoff, "approval": signoff})
}

test_impractical_without_why if {
	"Impractical without saying why one engineer cannot meet it" in denies({"frr_id": "A", "status": "Impractical", "impractical": {"reasons": ["one-person"]}, "proposal": signoff, "approval": signoff})
}

test_not_applicable_silent if {
	"Not Applicable without naming the missing trigger" in denies({"frr_id": "A", "status": "Not Applicable", "proposal": signoff, "approval": signoff})
}

test_not_applicable_because_proof_of_concept if {
	"Not Applicable because it is a proof of concept: name the missing trigger" in denies({"frr_id": "A", "status": "Not Applicable", "not_applicable": "This is a Proof-of-Concept.", "proposal": signoff, "approval": signoff})
}

test_scope_cut_without_proposal if {
	"Not Applicable without a proposal (who proposed it, when)" in denies({"frr_id": "A", "status": "Not Applicable", "not_applicable": "x", "approval": signoff})
}

test_scope_cut_awaiting_the_operator if {
	denies({"frr_id": "A", "status": "Impractical", "impractical": {"reasons": ["one-person"], "why": "w"}, "proposal": signoff}) == {"Impractical not approved by the operator"}
}

test_approved_by_someone_else if {
	"approved by \"An Agent\": only the operator approves" in denies({"frr_id": "A", "status": "Not Applicable", "not_applicable": "x", "proposal": signoff, "approval": {"by": "An Agent", "on": "2026-11-07"}})
}

test_approval_on_an_implemented_record if {
	"an approval on a record whose status is Implemented" in denies({"frr_id": "A", "status": "Implemented", "evidence": [ok_ev], "approval": signoff})
}

acc := {"by": op, "on": "2026-11-09", "review_by": "2027-11-09"}

test_an_accepted_gap_is_supported if {
	count(denies({"frr_id": "A", "status": "Not Demonstrated", "not_demonstrated": "x", "acceptance": acc})) == 0
}

test_only_the_operator_accepts_a_gap if {
	"accepted by \"An Agent\": only the operator accepts a gap" in denies({"frr_id": "A", "status": "Not Demonstrated", "not_demonstrated": "x", "acceptance": object.union(acc, {"by": "An Agent"})})
}

test_acceptance_is_for_not_demonstrated_only if {
	"an acceptance on a record whose status is Implemented" in denies({"frr_id": "A", "status": "Implemented", "evidence": [ok_ev], "acceptance": acc})
}
