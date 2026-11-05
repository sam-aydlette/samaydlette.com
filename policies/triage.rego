# =============================================================================
# VDR TRIAGE ENGINE (policy as code; REQ-LEV-1, REQ-IRV-6, REQ-DSP-*, REQ-DLN-*)
# =============================================================================
# The decisions the published VDR report makes about each finding. The Python
# builder (scripts/build-vdr-report.py) collects facts: scanner output, the
# inventory component and its declared reachability, the verified state of a
# mitigation (fingerprint, live read, signature), the disposition and decision
# records, the PAIN arithmetic, the EPSS score, and the clock start from the
# ledger. This module decides; the builder publishes what it returns.
#
# Timeframes, the maximum period and the impact scale are read from FedRAMP's
# Consolidated Rules as data.rules (the vendored file, hash-checked by
# scripts/_rules.py before it is passed in). Nothing here restates them.
#
# Entry points:
#   data.vdr.triage.decisions   one decision per input.items[i], in order
#   data.vdr.triage.errors      non-empty => the builder fails closed
#   data.vdr.triage.vocabulary  disposition terms and the sets that pass/close
#
# Per finding, in order:
#   1. fully mitigated   a verified mitigation with effect "full" (rule 1)
#   2. impact            N0 when fully mitigated (VER-EVA-EPA), else PAIN
#   3. reachability      inventory (REQ-IRV-6); unresolved or package => IRV;
#                        a verified "not-reachable" mitigation => NIRV
#   4. exploitability    Figure 7, first match decides; then a verified
#                        "not-likely-exploitable" mitigation; then an LEV
#                        override in force. Neither ever clears known or
#                        observed exploitation.
#   5. disposition       check-ID decision record, else the register entry;
#                        a lapsed or invalid record is absent (REQ-DSP-2)
#   6. deadline          clock start + Class C timeframe; likely overdue
#                        inside the governed margin; accepted past VER-TFR-MAV,
#                        or earlier when the projected remediation is past it
#   7. grouping          VER-EVA-GRV: findings sharing a group are evaluated at
#                        their most exposed member; the group's clock starts at
#                        its earliest member and its deadline binds every member
#   8. evaluation time   VER-TFR-EVU: evaluated later than the rules allow after
#                        detection, or still resting on a default after it
#   9. blocking          KEV (even when dispositioned) > closed > top impact
#                        level + LEV + IRV > past the deadline (own or group's)
# =============================================================================
package vdr.triage

day_ns := ((24 * 60) * 60) * 1000000000

# ---- vocabulary --------------------------------------------------------------
dispositions := {
	"false-positive", "mitigated", "vendor-dependency", "under-investigation",
	"operational-requirement", "accepted", "remediate",
}

# A register record with one of these, in force and with a decision reference,
# dispositions the finding (scripts/vuln-gate.py PASS_DISPOSITIONS is the same set).
pass_dispositions := {"false-positive", "operational-requirement", "accepted", "mitigated", "vendor-dependency"}

# Closed for the deadline gate. "mitigated" closes only when fully mitigated.
closing_dispositions := {"false-positive", "risk-accepted", "operational-requirement", "accepted"}

vocabulary := {
	"dispositions": dispositions,
	"pass": pass_dispositions,
	"closing": closing_dispositions,
}

# ---- FedRAMP rules (data.rules) -----------------------------------------------
pvr := data.rules.FRR.VDR.data.all.TFR["VDR-TFR-PVR"].varies_by_class.c.pain_timeframes

levels := [sprintf("N%d", [n]) | some n in sort([to_number(k) | some k, _ in pvr])]

lowest_level := levels[0]

top_level := levels[count(levels) - 1]

# VER-EVA-EPA added N0 (October 2026) for an impact removed entirely: a fully
# mitigated finding takes it. N0 has no timeframe in VDR-TFR-PVR. Read from the
# rule's own scale; a rules file without N0 keeps the timeframe table's lowest.
epa_rule := object.get(data.rules.FRR.VER.data.all, ["EVA", "VER-EVA-EPA"], {})

mitigated_level := "N0" if {
	some b in object.get(epa_rule, "following_information_bullets", [])
	startswith(b, "**N0**")
} else := lowest_level

level_index(p) := i if {
	some i, l in levels
	l == p
} else := -1

mav_rule := data.rules.FRR.VER.data.all.TFR["VER-TFR-MAV"]

mav_cell := c if {
	c := mav_rule.varies_by_class.c
} else := mav_rule

mav_days := mav_cell.timeframe_num if {
	mav_cell.timeframe_type == "days"
	is_number(mav_cell.timeframe_num)
	mav_cell.timeframe_num > 0
}

cell_name(true, true) := "irv_lev"

cell_name(true, false) := "nirv_lev"

cell_name(false, _) := "nlev"

# Days, or null for a level with no timeframe (N1: routine operations).
timeframe(pain, lev, irv) := d if {
	cell := pvr[substring(pain, 1, -1)][cell_name(lev, irv)]
	cell.timeframe_type == "days"
	d := cell.timeframe_num
} else := null

# ---- fail closed -------------------------------------------------------------
errors contains "VDR-TFR-PVR Class C impact scale missing from data.rules" if count(levels) == 0

errors contains "VER-TFR-MAV missing or not a positive number of days in data.rules" if not mav_days

errors contains msg if {
	count(decisions) != count(input.items)
	msg := sprintf("%d decisions for %d items", [count(decisions), count(input.items)])
}

errors contains msg if {
	some i, item in input.items
	item.kind == "finding"
	d := decisions[i]
	not d.pain in {lowest_level, mitigated_level}
	d.sla_days == null
	msg := sprintf("%v: no Class C timeframe for %v/%v/%v in data.rules", [d.id, d.pain, d.lev, d.irv])
}

errors contains msg if {
	some item in input.items
	item.kind == "finding"
	not item.pain in levels
	msg := sprintf("%v: impact %v is not on the rules' scale", [item.id, item.pain])
}

# ---- helpers -------------------------------------------------------------------
truthy(x) if {
	x != null
	x != false
	x != ""
	x != 0
}

is_day(s) if {
	is_string(s)
	regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`, s)
	time.parse_ns("2006-01-02", s)
}

py_repr(s) := sprintf("'%s'", [s]) if {
	is_string(s)
} else := "None" if {
	s == null
} else := sprintf("%v", [s])

mit_valid(m) if {
	m != null
	m.valid == true
}

metric(m, k) := object.get(m, k, null)

# (C, I, A) from v3 or v4 metrics; undefined when incomplete.
impacts(m) := [m.C, m.I, m.A] if {
	m.C
	m.I
	m.A
} else := [m.VC, m.VI, m.VA] if {
	m.VC
	m.VI
	m.VA
}

no_direct_impact(m) if {
	imp := impacts(m)
	every x in imp {
		x == "N"
	}
}

floor_vector(m) if {
	metric(m, "AV") == "N"
	metric(m, "PR") == "N"
	metric(m, "UI") == "N"
	impacts(m)
	not no_direct_impact(m)
}

# ---- 1-2. fully mitigated, impact ------------------------------------------------
fully_mitigated(item) if item.fully_mitigated == true

fully_mitigated(item) if {
	mit_valid(item.mitigation)
	item.mitigation.effect == "full"
}

fm_bool(item) if {
	fully_mitigated(item)
} else := false

impact(item) := mitigated_level if {
	fully_mitigated(item)
} else := item.pain

# ---- 3. reachability -------------------------------------------------------------
reach(item) := [true, "observed"] if {
	item.reach.observed == true
} else := [true, "unresolved"] if {
	item.reach.component_id == null
} else := [true, "package-host-unrecorded"] if {
	item.reach.is_package == true
} else := [item.reach.declared, "inventory"] if {
	is_boolean(item.reach.declared)
} else := [true, "unresolved"]

irv(item) := [false, "mitigation"] if {
	# An outside-in observation this run outranks any claim it is unreachable.
	not item.reach.observed == true
	mit_valid(item.mitigation)
	item.mitigation.effect == "not-reachable"
} else := reach(item)

# ---- 4. exploitability (Figure 7) ---------------------------------------------------
figure7(item, irv) := [false, "fully-mitigated"] if {
	fully_mitigated(item)
} else := [true, "known-exploited"] if {
	item.is_kev == true
} else := [true, "exploitation-observed"] if {
	lower(sprintf("%v", [object.get(item, "exploitation", "")])) == "active"
} else := [true, "floor"] if {
	irv == true
	floor_vector(item.metrics)
} else := [false, "no-direct-impact"] if {
	no_direct_impact(item.metrics)
} else := [item.epss >= input.epss_threshold, "prediction"] if {
	is_number(item.epss)
} else := [true, "no-score"]

# Known or observed exploitation: no mitigation or override clears it.
exploited(item) if item.is_kev == true

exploited(item) if lower(sprintf("%v", [object.get(item, "exploitation", "")])) == "active"

after_mitigation(item, l) := [false, "mitigation"] if {
	l[0] == true
	not exploited(item)
	mit_valid(item.mitigation)
	item.mitigation.effect == "not-likely-exploitable"
} else := l

override_applies(o, item) if {
	o.advisory == item.advisory
	not item.resource in object.get(o, "exclusions", [])

	# fnmatch semantics: "*" crosses every character.
	glob.match(o.selector, ["\u0000"], item.resource)
	o.review_by >= input.today
}

overrides := object.get(input, "lev_overrides", {})

# REQ-LEV-4: the first override in force, by ID. Findings only; never known or
# observed exploitation.
override(item) := ids[0] if {
	item.kind == "finding"
	not exploited(item)
	ids := [oid | some oid in sort(object.keys(overrides)); override_applies(overrides[oid], item)]
	count(ids) > 0
}

lev(item, irv) := [overrides[oid].lev == true, "override", oid] if {
	oid := override(item)
} else := [l[0], l[1], null] if {
	l := after_mitigation(item, figure7(item, irv))
}

# ---- 5. disposition ------------------------------------------------------------------
# (status, reason) for one decision record: in-force, lapsed or invalid.
record_status(e, item) := ["invalid", sprintf("unknown disposition %s", [py_repr(object.get(e, "disposition", null))])] if {
	not object.get(e, "disposition", null) in dispositions
} else := ["invalid", sprintf("review_by %s is not a date", [py_repr(e.review_by)])] if {
	truthy(object.get(e, "review_by", null))
	not is_day(e.review_by)
} else := ["lapsed", sprintf("review_by %v has passed", [e.review_by])] if {
	truthy(object.get(e, "review_by", null))
	e.review_by < input.today
} else := ["invalid", "names a control; a finding a control protects is recorded as mitigated, never as a false positive"] if {
	e.disposition == "false-positive"
	truthy(object.get(e, "mitigation", null))
} else := ["invalid", "no mitigation in force for this finding"] if {
	e.disposition == "mitigated"
	not mit_valid(item.mitigation)
} else := ["invalid", sprintf("names %v but %v covers the finding", [e.mitigation, item.mitigation.id])] if {
	e.disposition == "mitigated"
	truthy(object.get(e, "mitigation", null))
	e.mitigation != item.mitigation.id
} else := ["invalid", "fix state wont-fix: the vendor will not ship a fix, so this is not a vendor dependency; record it as accepted, or remediate another way"] if {
	e.disposition == "vendor-dependency"
	object.get(item, "fix_state", null) == "wont-fix"
} else := ["invalid", sprintf("fix state %v: a fix may be available, so the vendor dependency has lapsed", [fix_state_word(item)])] if {
	e.disposition == "vendor-dependency"
	object.get(item, "fix_state", null) != "not-fixed"
} else := ["in-force", null]

fix_state_word(item) := item.fix_state if {
	truthy(object.get(item, "fix_state", null))
} else := "unknown"

# A check-ID decision record (Checkov/tfsec map): only its own lapse applies.
check_record(item) := record_status(object.union(item.check_decision.record, {"disposition": "accepted"}), item) if {
	item.check_decision != null
}

register_record(item) := record_status(item.register.entry, item) if {
	item.check_decision == null
	item.register != null
}

record(item) := r if {
	r := check_record(item)
} else := r if {
	r := register_record(item)
} else := null

# (disposition, decision reference, label) before the fully-mitigated default.
disposed(item) := [item.check_decision.disposition, item.check_decision.decision_id, item.check_decision.disposition] if {
	check_record(item)[0] == "in-force"
} else := [null, null, null] if {
	item.check_decision != null
} else := [e.disposition, e.decision_id, e.disposition] if {
	register_record(item)[0] == "in-force"
	e := item.register.entry
	e.disposition in pass_dispositions
	truthy(object.get(e, "decision_id", null))
} else := [null, null, item.register.entry.disposition] if {
	register_record(item)[0] == "in-force"
} else := [null, null, null]

final_disposition(d, fm) := "mitigated" if {
	d == null
	fm == true
} else := d

closes(d, _) if d in closing_dispositions

closes(d, fm) if {
	d == "mitigated"
	fm == true
}

closed_bool(d, fm) if {
	closes(d, fm)
} else := false

# A false positive is not a vulnerability; a fully mitigated finding is not
# exploitable. Neither has a clock. Everything else does, whatever its disposition.
needs_remediation(d, fm) if {
	d != "false-positive"
	fm == false
} else := false

# ---- 6. deadline -----------------------------------------------------------------------------
past(due) if input.now_ns > due

# Governed margin, capped at half the timeframe so a short deadline is not
# flagged the moment it opens.
within_margin(due, sla) if 2 * (due - input.now_ns) <= min([2 * input.margin_days, sla]) * day_ns

overdue(needs, due) if {
	needs == true
	past(due)
} else := false

will_be_overdue(needs, due, sla) if {
	needs == true
	not past(due)
	within_margin(due, sla)
} else := false

deadline(item, sla, needs) := {"due_ns": null, "is_overdue": false, "will_be_overdue": false} if {
	item.kind != "finding"
} else := {"due_ns": null, "is_overdue": false, "will_be_overdue": false} if {
	sla == null
} else := {"due_ns": due, "is_overdue": overdue(needs, due), "will_be_overdue": will_be_overdue(needs, due, sla)} if {
	due := item.clock.start_ns + (sla * day_ns)
}

# VER-TFR-MAV: counted from the first evaluation; no mitigation resets it.
accepted_ns(item) := item.clock.first_evaluated_ns + (mav_days * day_ns) if {
	item.kind == "finding"
} else := null

accepted_now(needs, ns) if {
	needs == true
	ns != null
	input.now_ns >= ns
} else := false

# VER-TFR-MAV "will not be": a finding whose projected remediation (a decision's
# planned date, passed in as projected_ns) falls after the maximum period is
# accepted now, not when the period runs out.
projected_past(needs, item, ns) if {
	needs == true
	ns != null
	p := object.get(item, "projected_ns", null)
	is_number(p)
	p > ns
} else := false

accepted_basis(needs, item, ns) := "maximum-period-passed" if {
	accepted_now(needs, ns)
} else := "projected-past-maximum-period" if {
	projected_past(needs, item, ns)
} else := null

# ---- 8. evaluation time (VER-TFR-EVU) ------------------------------------------------------
# input.evaluation_days is read from the rules by scripts/_rules.py. A finding
# is late when its first evaluation came more than that many days after the
# source detected it, or when, that long after detection, it is still open on a
# default (no exploit-prediction score and no vector: Figure 7's last step).
evaluation_late(item, l, needs) := "evaluated-late" if {
	is_number(object.get(input, "evaluation_days", null))
	d := object.get(item, "detected_ns", null)
	is_number(d)
	object.get(item, "evaluated_ns", item.clock.first_evaluated_ns) - d > input.evaluation_days * day_ns
} else := "default-after-evaluation-window" if {
	is_number(object.get(input, "evaluation_days", null))
	needs == true
	l[1] == "no-score"
	object.get(item, "default_evaluation", false) == true
	d := object.get(item, "detected_ns", item.clock.first_evaluated_ns)
	input.now_ns - d > input.evaluation_days * day_ns
} else := null

# ---- 7. blocking ---------------------------------------------------------------------------
# KEV is tested before the disposition: a register entry never buys a known
# exploited vulnerability out of the gate.
block_rule(is_kev, closed, pain, lev, irv, is_overdue) := "kev" if {
	is_kev == true
} else := null if {
	closed == true
} else := "top-impact-lev-irv" if {
	pain == top_level
	lev == true
	irv == true
} else := "past-deadline" if {
	is_overdue == true
} else := null

# ---- the decision ---------------------------------------------------------------------------
pair_or_null(rec, i) := rec[i] if {
	rec != null
} else := null

label_of(disposition, label) := disposition if {
	disposition != null
} else := label

base(item) := {
	"id": item.id,
	"fully_mitigated": fm,
	"pain": pain,
	"irv": r[0],
	"irv_basis": r[1],
	"lev": l[0],
	"lev_basis": l[1],
	"lev_override": l[2],
	"record_status": pair_or_null(rec, 0),
	"record_reason": pair_or_null(rec, 1),
	"disposition": disposition,
	"decision_id": dsp[1],
	"label": label_of(disposition, dsp[2]),
	"closed": closed,
	"needs_remediation": needs,
	"sla_days": sla,
	"due_ns": dl.due_ns,
	"is_overdue": dl.is_overdue,
	"will_be_overdue": dl.will_be_overdue,
	"accepted": accepted_basis(needs, item, acc) != null,
	"accepted_basis": accepted_basis(needs, item, acc),
	"accepted_ns": acc,
	"evaluation_late": evaluation_late(item, l, needs),
	"start_ns": field_or_null(item.clock, "start_ns"),
	"is_kev": item.is_kev == true,
} if {
	fm := fm_bool(item)
	pain := impact(item)
	r := irv(item)
	l := lev(item, r[0])
	rec := record(item)
	dsp := disposed(item)
	disposition := final_disposition(dsp[0], fm)
	closed := closed_bool(disposition, fm)
	needs := needs_remediation(disposition, fm)
	sla := timeframe(pain, l[0], r[0])
	dl := deadline(item, sla, needs)
	acc := accepted_ns(item)
}

base_decisions := [base(item) | some item in input.items]

# ---- 7. grouping (VER-EVA-GRV) -----------------------------------------------------------
# input.items[i].group names the finding's group (a CVE, a decision record, or a
# check ID); a finding without one is its own group. The group is evaluated at
# its most exposed open member: the highest impact, LEV if any member is, IRV if
# any member is, the clock from its earliest member. The group's deadline binds
# each open member, so a new instance of an old group does not get a new clock.
group_key(i) := g if {
	g := input.items[i].group
	is_string(g)
	g != ""
} else := sprintf("item:%d", [i])

open_members(g) := [j |
	some j, it in input.items
	it.kind == "finding"
	group_key(j) == g
	base_decisions[j].needs_remediation == true
	level_index(base_decisions[j].pain) >= 0
]

group_eval(g) := {
	"pain": levels[max([level_index(base_decisions[j].pain) | some j in m])],
	"lev": any_true([base_decisions[j].lev | some j in m]),
	"irv": any_true([base_decisions[j].irv | some j in m]),
	"start_ns": min([base_decisions[j].start_ns | some j in m]),
	"members": count(m),
} if {
	m := open_members(g)
	count(m) > 0
} else := null

field_or_null(o, k) := o[k] if {
	is_object(o)
} else := null

past_bool(due) if {
	past(due)
} else := false

any_true(xs) if {
	some x in xs
	x == true
} else := false

group_deadline(ge) := {"due_ns": null, "is_overdue": false} if {
	ge == null
} else := {"due_ns": null, "is_overdue": false} if {
	timeframe(ge.pain, ge.lev, ge.irv) == null
} else := {"due_ns": due, "is_overdue": past_bool(due)} if {
	due := ge.start_ns + (timeframe(ge.pain, ge.lev, ge.irv) * day_ns)
}

own_or_group_overdue(b, gd) if {
	b.is_overdue == true
} else if {
	b.needs_remediation == true
	gd.is_overdue == true
} else := false

decide(i) := object.union(b, {
	"group": g,
	"group_pain": field_or_null(ge, "pain"),
	"group_lev": field_or_null(ge, "lev"),
	"group_irv": field_or_null(ge, "irv"),
	"group_due_ns": gd.due_ns,
	"is_overdue": is_overdue,
	"blocking": rule != null,
	"block_rule": rule,
}) if {
	b := base_decisions[i]
	g := group_key(i)
	ge := group_eval(g)
	gd := group_deadline(ge)
	is_overdue := own_or_group_overdue(b, gd)
	rule := block_rule(b.is_kev, b.closed, b.pain, b.lev, b.irv, is_overdue)
}

decisions := [decide(i) | some i, _ in input.items]
