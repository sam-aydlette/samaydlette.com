# Unit tests for policies/triage.rego. data.rules is a cut-down copy of the
# three FedRAMP rules the policy reads; the Python tests run it against the
# pinned file (tests/test_triage_policy.py).
package vdr.triage_test

import data.vdr.triage

day := ((24 * 60) * 60) * 1000000000

now := 1000 * day

cells(irv_lev, nirv_lev, nlev) := {
	"irv_lev": {"timeframe_type": "days", "timeframe_num": irv_lev},
	"nirv_lev": {"timeframe_type": "days", "timeframe_num": nirv_lev},
	"nlev": {"timeframe_type": "days", "timeframe_num": nlev},
}

rules := {"FRR": {
	"VDR": {"data": {"all": {"TFR": {"VDR-TFR-PVR": {"varies_by_class": {"c": {"pain_timeframes": {
		"1": {},
		"2": cells(48, 128, 192),
		"3": cells(16, 32, 128),
		"4": cells(4, 8, 64),
		"5": cells(2, 4, 16),
	}}}}}}}},
	"VER": {"data": {"all": {"TFR": {"VER-TFR-MAV": {"timeframe_type": "days", "timeframe_num": 192}}}}},
}}

base := {
	"id": "f1", "kind": "finding", "pain": "N2", "is_kev": false, "exploitation": null,
	"metrics": {}, "epss": null, "fully_mitigated": false,
	"reach": {"observed": false, "component_id": "c", "is_package": false, "declared": true},
	"mitigation": null, "check_decision": null, "register": null,
	"advisory": "CVE-1", "resource": "pkg:npm/a@1", "fix_state": null,
	"clock": {"start_ns": now, "first_evaluated_ns": now},
}

floor_metrics := {"AV": "N", "PR": "N", "UI": "N", "C": "H", "I": "N", "A": "N"}

no_impact := {"AV": "N", "PR": "N", "UI": "N", "C": "N", "I": "N", "A": "N"}

run(items, overrides) := ds if {
	ds := triage.decisions with data.rules as rules
		with input as {
			"now_ns": now, "today": "2026-11-03", "epss_threshold": 0.1, "margin_days": 5,
			"lev_overrides": overrides, "items": items,
		}
}

one(patch) := run([object.union(base, patch)], {})[0]

errs(items) := es if {
	es := triage.errors with data.rules as rules
		with input as {"now_ns": now, "today": "2026-11-03", "epss_threshold": 0.1, "margin_days": 5, "items": items}
}

# ---- Figure 7, first match decides -------------------------------------------------
test_fully_mitigated_first if {
	d := one({"is_kev": true, "fully_mitigated": true})
	d.lev == false
	d.lev_basis == "fully-mitigated"
	d.pain == "N1"
	d.needs_remediation == false
}

test_kev_before_floor if one({"is_kev": true, "metrics": floor_metrics}).lev_basis == "known-exploited"

test_exploitation_observed if one({"exploitation": "Active", "epss": 0.0}).lev_basis == "exploitation-observed"

test_floor_beats_a_low_score if {
	d := one({"metrics": floor_metrics, "epss": 0.001})
	d.lev == true
	d.lev_basis == "floor"
}

test_floor_needs_irv if {
	d := one({"metrics": floor_metrics, "epss": 0.001, "reach": object.union(base.reach, {"declared": false})})
	d.lev == false
	d.lev_basis == "prediction"
}

test_no_direct_impact if {
	d := one({"metrics": no_impact})
	d.lev == false
	d.lev_basis == "no-direct-impact"
}

test_prediction_at_threshold if one({"epss": 0.1}).lev == true

test_no_score_is_lev if one({}).lev_basis == "no-score"

# ---- reachability -------------------------------------------------------------------
test_unresolved_is_irv if {
	d := one({"reach": {"observed": false, "component_id": null, "is_package": false, "declared": false}})
	d.irv == true
	d.irv_basis == "unresolved"
}

test_package_host_unrecorded if {
	d := one({"reach": object.union(base.reach, {"is_package": true, "declared": false})})
	d.irv_basis == "package-host-unrecorded"
}

test_not_reachable_mitigation if {
	d := one({"mitigation": {"id": "M", "valid": true, "effect": "not-reachable"}})
	d.irv == false
	d.irv_basis == "mitigation"
}

test_void_mitigation_changes_nothing if {
	d := one({"mitigation": {"id": "M", "valid": false, "effect": "full"}})
	d.fully_mitigated == false
	d.irv_basis == "inventory"
}

# ---- mitigations and overrides never clear a KEV -------------------------------------
test_nlev_mitigation_not_for_kev if {
	d := one({"is_kev": true, "mitigation": {"id": "M", "valid": true, "effect": "not-likely-exploitable"}})
	d.lev == true
}

override := {"O1": {
	"advisory": "CVE-1", "selector": "pkg:npm/*", "exclusions": [],
	"lev": false, "review_by": "2027-01-01",
}}

test_override_applies_by_selector if run([base], override)[0].lev_override == "O1"

test_override_lapses if {
	lapsed := {"O1": object.union(override.O1, {"review_by": "2026-11-02"})}
	run([base], lapsed)[0].lev_override == null
}

test_override_never_clears_kev if run([object.union(base, {"is_kev": true})], override)[0].lev_override == null

# ---- dispositions ---------------------------------------------------------------------
reg(entry) := {"key": "CVE-1", "entry": entry}

test_register_in_force_closes if {
	d := one({"register": reg({"disposition": "operational-requirement", "decision_id": "P1", "review_by": "2027-01-01"})})
	d.record_status == "in-force"
	d.closed == true
	d.decision_id == "P1"
}

test_lapsed_record_is_absent if {
	d := one({"register": reg({"disposition": "accepted", "decision_id": "P1", "review_by": "2026-11-02"})})
	d.record_status == "lapsed"
	d.disposition == null
	d.closed == false
}

test_false_positive_naming_a_control_is_invalid if {
	d := one({"register": reg({"disposition": "false-positive", "decision_id": "P1", "mitigation": "M"})})
	d.record_status == "invalid"
}

test_vendor_dependency_lapses_without_not_fixed if {
	d := one({"register": reg({"disposition": "vendor-dependency", "decision_id": "P1"})})
	d.record_status == "invalid"
}

test_vendor_dependency_in_force_stays_on_the_clock if {
	d := one({"fix_state": "not-fixed", "register": reg({"disposition": "vendor-dependency", "decision_id": "P1"})})
	d.record_status == "in-force"
	d.closed == false
}

test_unknown_term_is_invalid if {
	d := one({"register": reg({"disposition": "risk-adjustment", "decision_id": "P1"})})
	d.record_reason == "unknown disposition 'risk-adjustment'"
}

test_check_decision_lapses if {
	cd := {"disposition": "risk-accepted", "decision_id": "P7", "record": {"review_by": "2026-01-01"}}
	d := one({"check_decision": cd})
	d.record_status == "lapsed"
	d.disposition == null
}

# ---- deadline and blocking ---------------------------------------------------------------
test_deadline_from_clock_start_and_rules if {
	d := one({})
	d.sla_days == 48
	d.due_ns == now + (48 * day)
}

test_past_deadline_blocks if {
	d := one({"clock": {"start_ns": now - (49 * day), "first_evaluated_ns": now - (49 * day)}})
	d.is_overdue == true
	d.block_rule == "past-deadline"
}

test_likely_overdue_inside_margin if {
	d := one({"clock": {"start_ns": now - (44 * day), "first_evaluated_ns": now}})
	d.will_be_overdue == true
}

test_maximum_period if {
	d := one({
		"epss": 0.0, "reach": object.union(base.reach, {"declared": false}),
		"clock": {"start_ns": now, "first_evaluated_ns": now - (192 * day)},
	})
	d.accepted == true
}

test_top_level_lev_irv_blocks if one({"pain": "N5"}).block_rule == "top-impact-lev-irv"

test_kev_blocks_through_a_false_positive if {
	d := one({"is_kev": true, "register": reg({"disposition": "false-positive", "decision_id": "P1"})})
	d.closed == true
	d.block_rule == "kev"
}

test_dispositioned_finding_still_has_a_deadline if {
	d := one({"register": reg({"disposition": "operational-requirement", "decision_id": "P1"})})
	d.sla_days == 48
	d.needs_remediation == true
}

# ---- fail closed ---------------------------------------------------------------------------
test_off_scale_impact_is_an_error if count(errs([object.union(base, {"pain": "N7"})])) > 0

test_clean_input_has_no_errors if count(errs([base])) == 0

test_vocabulary_has_pass_within_dispositions if {
	every p in triage.vocabulary.pass {
		p in triage.vocabulary.dispositions
	}
}

# ---- pre-merge review (#479) -----------------------------------------------------------
test_wont_fix_lapses_vendor_dependency_with_its_own_reason if {
	d := one({"fix_state": "wont-fix", "register": reg({"disposition": "vendor-dependency", "decision_id": "P1"})})
	d.record_status == "invalid"
	contains(d.record_reason, "will not ship a fix")
}

test_override_never_clears_observed_exploitation if {
	d := run([object.union(base, {"exploitation": "active"})], override)[0]
	d.lev_override == null
	d.lev_basis == "exploitation-observed"
}

test_mitigation_never_clears_observed_exploitation if {
	d := one({"exploitation": "active", "mitigation": {"id": "M", "valid": true, "effect": "not-likely-exploitable"}})
	d.lev == true
}

test_observed_reachability_beats_not_reachable_mitigation if {
	d := one({
		"reach": object.union(base.reach, {"observed": true}),
		"mitigation": {"id": "M", "valid": true, "effect": "not-reachable"},
	})
	d.irv_basis == "observed"
}

# ---- VER-TFR-IRI / VER-TFR-NRI: vulnerabilities treated as incidents ------------------
iri_text := concat(" ", [
	"Providers with Class C Certifications SHOULD treat internet-reachable likely exploitable vulnerabilities",
	"where Potential Agency Impact N-rating > 3 as a FedRAMP Reportable Incident",
	"until they are partially mitigated vulnerabilities at N3 or below.",
])

nri_text := concat(" ", [
	"Providers with Class C Certifications MAY treat likely exploitable vulnerabilities that are NOT internet-reachable",
	"where Potential Agency Impact N-rating = 5 as a FedRAMP Reportable Incident",
	"until they are partially mitigated vulnerabilities at N4 or below.",
])

ver_rules(iri, nri) := {"FRR": {"VER": {"data": {"all": {"TFR": {
	"VER-TFR-IRI": {"varies_by_class": {"c": {"statement": iri}}},
	"VER-TFR-NRI": nri,
}}}}}}

good_ver := ver_rules(iri_text, {"varies_by_class": {"c": {"statement": nri_text}}})

vf := {
	"tracking_id": "t1", "cve": "CVE-2099-0001", "pain": "N4", "internet_reachable": true,
	"likely_exploitable": true, "fully_mitigated": false, "final_disposition": "open",
	"first_evaluated": "2026-11-01T00:00:00+00:00",
}

triggers(patch, r) := ts if {
	ts := triage.incident_triggers with data.rules as r
		with input as {"findings": [object.union(vf, patch)]}
}

ierrs(findings, r) := es if {
	es := triage.incident_errors with data.rules as r with input as {"findings": findings}
}

test_iri_opens_above_n3 if {
	ts := triggers({}, good_ver)
	ts == [{
		"tracking_id": "t1", "cve": "CVE-2099-0001", "rule": "VER-TFR-IRI", "pain": "N4",
		"first_evaluated": "2026-11-01T00:00:00+00:00",
	}]
	triggers({"pain": "N5"}, good_ver)[0].rule == "VER-TFR-IRI"
}

test_iri_ends_at_n3_or_below if {
	triggers({"pain": "N3"}, good_ver) == []
	triggers({"pain": "N1"}, good_ver) == []
}

test_nri_opens_only_at_n5 if {
	triggers({"internet_reachable": false, "pain": "N5"}, good_ver)[0].rule == "VER-TFR-NRI"
	triggers({"internet_reachable": false, "pain": "N4"}, good_ver) == []
}

test_not_likely_exploitable_never_triggers if {
	triggers({"likely_exploitable": false, "pain": "N5"}, good_ver) == []
	triggers({"likely_exploitable": false, "internet_reachable": false, "pain": "N5"}, good_ver) == []
}

test_false_positive_and_fully_mitigated_never_trigger if {
	triggers({"final_disposition": "false-positive", "pain": "N5"}, good_ver) == []
	triggers({"fully_mitigated": true, "pain": "N5"}, good_ver) == []
}

test_accepted_still_triggers if {
	triggers({"final_disposition": "accepted", "pain": "N5"}, good_ver)[0].rule == "VER-TFR-IRI"
}

test_missing_cve_is_null if {
	ts := triage.incident_triggers with data.rules as good_ver
		with input as {"findings": [object.remove(vf, ["cve", "first_evaluated"])]}
	ts[0].cve == null
	ts[0].first_evaluated == null
}

test_rules_read_cleanly if {
	ierrs([vf], good_ver) == set()
}

test_changed_iri_text_fails_closed if {
	es := ierrs([vf], ver_rules("treat them as incidents", {"statement": nri_text}))
	"VER-TFR-IRI Class C statement no longer reads 'N-rating > n ... at Nn or below'" in es
}

test_changed_nri_text_fails_closed if {
	es := ierrs([vf], ver_rules(iri_text, {"statement": "treat them as incidents"}))
	"VER-TFR-NRI Class C statement no longer reads 'N-rating = n ... at Nn or below'" in es
}

test_non_complement_fails_closed if {
	bad_iri := replace(iri_text, "at N3 or below", "at N2 or below")
	bad_nri := replace(nri_text, "at N4 or below", "at N3 or below")
	es := ierrs([vf], ver_rules(bad_iri, {"statement": bad_nri}))
	"VER-TFR-IRI: the trigger and the 'until' level are not complements" in es
	"VER-TFR-NRI: the trigger and the 'until' level are not complements" in es
}

test_bad_rating_fails_closed if {
	es := ierrs([object.union(vf, {"pain": "high"})], good_ver)
	"t1: impact high is not an N-rating" in es
}
