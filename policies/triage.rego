# =============================================================================
# FINDING TRIAGE ENGINE  (policy-as-code)
# =============================================================================
# Triages a single finding (a Checkov config suppression OR a vulnerability from
# ZAP/Grype/Dependabot) into a disposition and, when remediation is required, a
# remediation timeline derived from the risk score through a layered policy
# chain. Pure policy: human decisions arrive as `input.asserted` (sourced from
# the disposition register); this module decides nothing a human must own, it
# applies the operator's recorded decision and computes the consequences.
#
# DISPOSITIONS (exactly one per finding):
#   false-positive         no real risk / not applicable
#   operational-requirement risk is accurate but accepted (tracked, not patched)
#   risk-adjustment         risk is real but lower than the CVSS (preferred) /
#                           scanner severity; severity is adjusted down
#   remediate               (default for a real vulnerability) fix on a timeline
#
# REMEDIATION-TIMELINE CHAIN (only for remediate / risk-adjustment), in order:
#   1. contextual   PAIN from effective severity, bumped by reachability (IRV) +
#                   exploitability (LEV)
#   2. immutable    CISA KEV (is_kev) => must patch now, overrides thresholds
#   3. threshold    Class C SLA table keyed by (PAIN, LEV, IRV) => days
#   4. historical   if similar past cases set a shorter timeline, use it
#   5. escalation   unprecedented risk or architectural change => route to human
#
# Output: data.vdr.triage.decision  (see bottom).
# =============================================================================
package vdr.triage

import future.keywords.in

# Boolean rules default to false so they are always defined (an undefined rule
# referenced inside `decision` would make the whole object undefined).
default remediation_required := false
default must_patch_now := false
default escalate := false
default invalid_risk_adjustment := false
default historical_present := false
default tighter_history := false

# Context flags read with defaults so a finding that omits them is still defined.
irv := object.get(input, "internet_reachable", false)
lev := object.get(input, "likely_exploitable", false)

# ---- severity helpers -------------------------------------------------------
sev_rank := {"NONE": 0, "LOW": 1, "MEDIUM": 2, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}

# CVSS base score -> severity bucket (CVSS v3 ranges).
cvss_severity(score) = "CRITICAL" { score >= 9.0 }
cvss_severity(score) = "HIGH"     { score >= 7.0; score < 9.0 }
cvss_severity(score) = "MEDIUM"   { score >= 4.0; score < 7.0 }
cvss_severity(score) = "LOW"      { score > 0.0;  score < 4.0 }
cvss_severity(score) = "NONE"     { score <= 0.0 }

# Baseline anchor, in preference order:
#   1. the CVE's base CVSS score          (preferred)
#   2. the scanner's own numeric score    (0-10 scale)
#   3. the scanner's severity label
default has_cvss := false
has_cvss { is_number(input.cvss) }

default has_scanner_score := false
has_scanner_score { is_number(input.scanner_score) }

base_severity := cvss_severity(input.cvss) { has_cvss }

base_severity := cvss_severity(input.scanner_score) {
	not has_cvss
	has_scanner_score
}

base_severity := upper(object.get(input, "scanner_severity", "MEDIUM")) {
	not has_cvss
	not has_scanner_score
}

# ---- disposition ------------------------------------------------------------
valid_dispositions := {"false-positive", "operational-requirement", "risk-adjustment", "remediate"}

default disposition := "remediate"

disposition := d {
	d := object.get(input.asserted, "disposition", null)
	d != null
	d in valid_dispositions
}

# ---- effective severity (what the timeline is computed against) -------------
effective_severity := "NONE" { disposition == "false-positive" }

effective_severity := base_severity {
	disposition == "operational-requirement"
}

# Risk adjustment may only LOWER severity, and is anchored to the base (CVSS
# preferred). A valid adjustment uses the adjusted value; an adjustment at or
# above the base is invalid (flagged) and falls back to the base severity.
effective_severity := adj {
	disposition == "risk-adjustment"
	adj := upper(object.get(input.asserted, "adjusted_severity", base_severity))
	sev_rank[adj] < sev_rank[base_severity]
}

effective_severity := base_severity {
	disposition == "risk-adjustment"
	adj := upper(object.get(input.asserted, "adjusted_severity", base_severity))
	sev_rank[adj] >= sev_rank[base_severity]
}

effective_severity := base_severity { disposition == "remediate" }

# An invalid risk adjustment (tried to raise or keep severity) is flagged.
invalid_risk_adjustment {
	disposition == "risk-adjustment"
	adj := upper(object.get(input.asserted, "adjusted_severity", base_severity))
	sev_rank[adj] >= sev_rank[base_severity]
}

remediation_required {
	disposition in {"remediate", "risk-adjustment"}
}

# ---- 1. contextual: PAIN rating --------------------------------------------
pain_base := {"NONE": 1, "LOW": 1, "MEDIUM": 2, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}

# Reachable AND exploitable bumps PAIN one notch (capped at N5).
default reachable_and_exploitable := false

reachable_and_exploitable {
	irv
	lev
}

pain_n := n {
	reachable_and_exploitable
	n := min([5, pain_base[effective_severity] + 1])
}

pain_n := pain_base[effective_severity] {
	not reachable_and_exploitable
}

pain := sprintf("N%d", [pain_n])

# ---- 2. immutable: CISA KEV must-patch-now ---------------------------------
must_patch_now {
	remediation_required
	input.is_kev
}

# ---- 3. threshold: Class C SLA (days) keyed by (pain, lev, irv) -------------
# Mirrors CLASS_C_SLA_DAYS in build-vdr-report.py (VDR-TFR-PVR). N1 has no fixed
# SLA (routine ops); represented as 365 (review within a year).
sla_table := {
	"N1|x|x": 365,
	"N2|true|true": 48, "N2|true|false": 128, "N2|false|true": 192, "N2|false|false": 192,
	"N3|true|true": 16, "N3|true|false": 32, "N3|false|true": 128, "N3|false|false": 128,
	"N4|true|true": 4, "N4|true|false": 8, "N4|false|true": 64, "N4|false|false": 64,
	"N5|true|true": 2, "N5|true|false": 4, "N5|false|true": 16, "N5|false|false": 16,
}

sla_key := k {
	pain == "N1"
	k := "N1|x|x"
}

sla_key := k {
	pain != "N1"
	k := sprintf("%s|%v|%v", [pain, lev, irv])
}

threshold_days := object.get(sla_table, sla_key, 365)

# ---- 4. historical: similar past cases may tighten the timeline -------------
historical_days := d {
	d := input.historical.median_days
	is_number(d)
}

# ---- 5. escalation ----------------------------------------------------------
escalate {
	remediation_required
	object.get(input.asserted, "architectural_change_required", false)
}

escalate {
	remediation_required
	effective_severity == "CRITICAL"
	not historical_present
}

historical_present {
	is_number(input.historical.median_days)
}

escalation_reason := "architectural change required" {
	object.get(input.asserted, "architectural_change_required", false)
}

escalation_reason := "unprecedented critical risk, no historical precedent" {
	not object.get(input.asserted, "architectural_change_required", false)
	effective_severity == "CRITICAL"
	not historical_present
}

# ---- final SLA + deciding layer --------------------------------------------
sla_days := 0 { must_patch_now }

sla_days := d {
	not must_patch_now
	remediation_required
	historical_present
	historical_days < threshold_days
	d := historical_days
}

sla_days := threshold_days {
	not must_patch_now
	remediation_required
	not tighter_history
}

tighter_history {
	historical_present
	historical_days < threshold_days
}

decided_by := "disposition" { not remediation_required }
decided_by := "immutable" { must_patch_now }
decided_by := "escalation" { not must_patch_now; remediation_required; escalate }
decided_by := "historical" { not must_patch_now; remediation_required; not escalate; tighter_history }
decided_by := "threshold" { not must_patch_now; remediation_required; not escalate; not tighter_history }

# ---- decision ---------------------------------------------------------------
decision := {
	"id": object.get(input, "id", ""),
	"disposition": disposition,
	"effective_severity": effective_severity,
	"remediation_required": remediation_required,
	"pain": pain,
	"must_patch_now": must_patch_now,
	"sla_days": sla_days_out,
	"escalate": escalate,
	"escalation_reason": reason_out,
	"decided_by": decided_by,
	"invalid_risk_adjustment": invalid_risk_adjustment,
}

# sla_days only meaningful when remediation is required.
sla_days_out := sla_days { remediation_required }
sla_days_out := null { not remediation_required }

reason_out := escalation_reason { escalate }
reason_out := "" { not escalate }
