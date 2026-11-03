"""Deadlines and history (REQ-DLN-1..3, REQ-PAI-2, REQ-SRC-1; T14, T34-T36).

A deadline counts from the clock start, which is the first evaluation unless a
verified mitigation changed the evaluation. First detection and first
evaluation carry across builds. No disposition pauses the clock. The maximum
period counts from the first evaluation and never resets.
"""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("vdr", REPO / "scripts" / "build-vdr-report.py")
vdr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vdr)
CFG, _ = vdr.load_pain_config()
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
N3_VEC = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N"


def iso(days_ago):
    return (NOW - timedelta(days=days_ago)).isoformat()


def build(findings, ledger=None, suppressions=()):
    report, blocking = vdr.build_report(list(findings), list(suppressions), set(), ledger or {},
                                        config=CFG, now=NOW)
    return report


def finding(**kw):
    base = {"tracking_id": "t1", "source": "grype", "cve": "CVE-0000-0100", "resource": "pkg:npm/a@1",
            "severity": "HIGH", "cvss_vector": N3_VEC}
    base.update(kw)
    return base


def entry(first_detected, first_evaluated=None, clock_start=None, pain=None, history=None):
    e = {"first_detected": first_detected}
    if first_evaluated:
        e["first_evaluated"] = first_evaluated
    if clock_start:
        e["clock_start"] = clock_start
    if pain:
        e["pain"] = pain
        e["historical_pain"] = pain
    if history is not None:
        e["rating_history"] = history
    return e


# --- ledger ----------------------------------------------------------------------

def test_ledger_reads_findings_and_risk_accepted(tmp_path):
    prev = {"findings": [{"tracking_id": "a", "first_detected": iso(10), "first_evaluated": iso(9)}],
            "risk_accepted": [{"tracking_id": "b", "first_detected": iso(30)}]}
    p = tmp_path / "prev.json"
    p.write_text(json.dumps(prev))
    ledger = vdr.ingest_previous_ledger(str(p))
    assert ledger["a"]["first_evaluated"] == iso(9)
    assert ledger["b"]["first_detected"] == iso(30)
    # A record from before first_evaluated was published: evaluated at detection.
    assert ledger["b"]["first_evaluated"] == iso(30)


# --- REQ-DLN-1 ----------------------------------------------------------------------

def test_first_evaluation_carries_and_is_not_now():
    f = build([finding()], ledger={"t1": entry(iso(20), iso(19))})["findings"][0]
    assert f["first_detected"] == iso(20)
    assert f["first_evaluated"] == iso(19)
    assert f["completed_evaluation"] == NOW.isoformat()


def test_deadline_counts_from_first_evaluation():
    f = build([finding()], ledger={"t1": entry(iso(20), iso(19))})["findings"][0]
    days = f["remediation_sla_days"]
    assert f["remediation_due_at"] == (datetime.fromisoformat(iso(19)) + timedelta(days=days)).isoformat()


def test_t35_evaluation_change_without_mitigation_keeps_the_clock_start():
    led = {"t1": entry(iso(40), iso(40), pain="N2")}
    f = build([finding()], ledger=led)["findings"][0]
    assert f["clock_start"] == iso(40)
    assert f["remediation_due_at"] == (datetime.fromisoformat(iso(40)) + timedelta(days=f["remediation_sla_days"])).isoformat()


def test_t34_verified_mitigation_starts_a_new_clock():
    d = iso(3)
    led = {"t1": entry(iso(40), iso(40), pain="N4")}
    f = build([finding(verified_mitigation_at=d)], ledger=led)["findings"][0]
    assert f["clock_start"] == d and f["first_evaluated"] == iso(40)


def test_no_disposition_pauses_the_clock():
    reg = {"CVE-0000-0100": {"disposition": "operational-requirement", "poam_ref": "POAM-1"}}
    f = {**finding(), "tracking_id": "grype-CVE-0000-0100-pkg:npm/a@1", "tool_id": "CVE-0000-0100"}
    report, _ = vdr.build_report([f], [], set(), {f["tracking_id"]: entry(iso(400), iso(400))}, config=CFG,
                                 now=NOW, disposition_register=reg)
    r = report["findings"][0]
    assert r["current_disposition"] == "operational-requirement"
    assert r["remediation_due_at"] is not None and r["is_overdue"] is True and r["is_blocking"] is False


# --- REQ-DLN-2 ----------------------------------------------------------------------

NLEV_VEC = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N"


def _sla_of(**kw):
    return build([finding(**kw)])["findings"][0]["remediation_sla_days"]


def test_likely_overdue_before_the_deadline():
    sla = _sla_of(cvss_vector=NLEV_VEC)
    margin = min(CFG["likely_overdue_margin_days"], sla / 2)
    started = int(sla - margin) + 1  # inside the margin, not yet due
    f = build([finding(cvss_vector=NLEV_VEC)], ledger={"t1": entry(iso(started), iso(started))})["findings"][0]
    assert f["is_overdue"] is False and f["will_be_overdue"] is True


def test_not_likely_overdue_with_time_left():
    f = build([finding(cvss_vector=NLEV_VEC)], ledger={"t1": entry(iso(0), iso(0))})["findings"][0]
    assert f["remediation_sla_days"] > 2 * CFG["likely_overdue_margin_days"]
    assert f["will_be_overdue"] is False


def test_margin_is_governed_with_a_rationale():
    assert isinstance(CFG["likely_overdue_margin_days"], int) and CFG["likely_overdue_margin_days"] >= 1
    assert CFG["likely_overdue_margin_rationale"].strip()


# --- REQ-DLN-3: maximum period (VER-TFR-MAV) ---------------------------------------------

def test_t14_past_maximum_period_is_reported_accepted_with_unrecorded_explanation():
    f = build([finding()], ledger={"t1": entry(iso(200), iso(200))})["findings"][0]
    assert f["accepted"] is True
    assert f["accepted_at"] == (datetime.fromisoformat(iso(200)) + timedelta(days=192)).isoformat()
    assert f["acceptance_explanation"] == "not recorded"


def test_t36_mitigations_never_reset_the_maximum_period():
    led = {"t1": entry(iso(200), iso(200), clock_start=iso(10))}
    f = build([finding(verified_mitigation_at=iso(10))], ledger=led)["findings"][0]
    assert f["clock_start"] == iso(10) and f["accepted"] is True


def test_within_maximum_period_not_accepted():
    f = build([finding()], ledger={"t1": entry(iso(10), iso(10))})["findings"][0]
    assert f["accepted"] is False and f["accepted_at"] is None


def test_maximum_period_comes_from_the_rules():
    assert vdr._rules.max_accepted_days() == 192


# --- REQ-PAI-2: rating history ---------------------------------------------------------------

def test_rating_change_is_appended_with_time_and_reason():
    led = {"t1": entry(iso(5), iso(5), pain="N5", history=[{"at": iso(5), "pain": "N5", "reason": "first evaluation"}])}
    f = build([finding(cvss_vector=NLEV_VEC)], ledger=led)["findings"][0]
    assert f["historical_pain"] == "N5"
    assert f["current_pain"] < "N5"
    last = f["rating_history"][-1]
    assert last["at"] == NOW.isoformat() and last["pain"] == f["current_pain"] and last["reason"]
    assert f["completed_reductions"] and f["completed_reductions"][-1]["from"] == "N5"


def test_new_finding_starts_its_history():
    f = build([finding()])["findings"][0]
    assert f["historical_pain"] == f["current_pain"]
    assert f["rating_history"] == [{"at": NOW.isoformat(), "pain": f["current_pain"], "lev": f["likely_exploitable"],
                                   "irv": f["internet_reachable"], "reason": "first evaluation"}]


# --- REQ-SRC-1: the source's detection time ---------------------------------------------------

def test_source_detection_time_is_kept():
    f = build([finding(detected_at=iso(15))])["findings"][0]
    assert f["first_detected"] == iso(15)


def test_dependabot_created_at_is_the_detection_time(tmp_path):
    p = tmp_path / "d.json"
    p.write_text(json.dumps([{"number": 1, "state": "open", "created_at": "2026-10-01T00:00:00Z",
                              "security_advisory": {"ghsa_id": "GHSA-x", "cve_id": "CVE-0000-0101", "severity": "high"},
                              "dependency": {"package": {"ecosystem": "npm", "name": "a"}}}]))
    assert vdr.ingest_dependabot(str(p))[0]["detected_at"] == "2026-10-01T00:00:00Z"


def test_risk_accepted_record_keeps_its_dates():
    s = {"tracking_id": "CKV_AWS_68", "source": "checkov-suppression", "tool_id": "CKV_AWS_68",
         "resource": ".checkov.yaml", "pain": "N2", "is_kev": False}
    r = build([], ledger={"CKV_AWS_68": entry(iso(90), iso(90))}, suppressions=[s])["risk_accepted"][0]
    assert r["first_detected"] == iso(90) and r["first_evaluated"] == iso(90)


def test_suppression_detection_time_comes_from_its_decision_record(tmp_path):
    poam = vdr.POAM_BY_CHECK_ID["CKV_AWS_68"]
    rec = tmp_path / "decisions.json"
    rec.write_text(json.dumps({"items": [{"id": poam, "original_detection_date": "2026-05-01"}]}))
    sup = {s["tool_id"]: s for s in vdr.ingest_suppressions(str(REPO / ".checkov.yaml"), rec)}
    assert sup["CKV_AWS_68"]["detected_at"] == "2026-05-01T00:00:00+00:00"


def test_identical_scanner_results_collapse_with_a_count():
    a = {"tracking_id": "x", "source": "checkov", "tool_id": "C", "resource": "r"}
    out = vdr.dedupe_findings([dict(a), dict(a), {**a, "tracking_id": "y"}])
    assert [f["tracking_id"] for f in out] == ["x", "y"] and out[0]["occurrences"] == 2
