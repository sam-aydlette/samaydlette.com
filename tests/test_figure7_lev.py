"""Figure 7 likely exploitability (REQ-LEV-1..4, REQ-PAI-7; Appendix B T8, T9).

Order, first match deciding: fully mitigated -> known exploited -> exploitation
observed -> FRD-LEV floor (IRV and AV:N/PR:N/UI:N with some direct impact) ->
no direct impact (rule 2) -> prediction score >= theta -> no score = LEV.
"""
import importlib.util
import json
from datetime import date
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "check-vectors"


def _vdr():
    spec = importlib.util.spec_from_file_location("vdr", REPO / "scripts" / "build-vdr-report.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vdr = _vdr()
TH = 0.10
FLOOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
NO_IMPACT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
LOCAL_PRIV = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N"


def lev(f, epss=None, kev=False, irv=False):
    return vdr.lev_determination(f, epss or {}, TH, is_kev=kev, irv=irv)


# --- T8: the floor is not overridden by a prediction score ---------------------

def test_t8_irv_network_noauth_nointeraction_low_score_is_lev():
    f = {"cve": "CVE-0000-0001", "cvss_vector": FLOOR, "severity": "LOW"}
    assert lev(f, {"CVE-0000-0001": 0.01}, irv=True) == (True, "floor")


def test_floor_needs_irv():
    f = {"cve": "CVE-0000-0001", "cvss_vector": FLOOR}
    assert lev(f, {"CVE-0000-0001": 0.01}, irv=False) == (False, "prediction")


def test_floor_needs_no_privileges():
    f = {"cve": "CVE-0000-0001", "cvss_vector": LOCAL_PRIV}
    assert lev(f, {"CVE-0000-0001": 0.01}, irv=True) == (False, "prediction")


def test_floor_reads_cvss4():
    f = {"cve": "CVE-0000-0001", "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}
    assert lev(f, {"CVE-0000-0001": 0.0}, irv=True) == (True, "floor")


# --- T9: no prediction score means LEV ----------------------------------------

def test_t9_nirv_no_score_medium_severity_is_lev():
    f = {"cve": "CVE-0000-0002", "severity": "MEDIUM"}
    assert lev(f, {}, irv=False) == (True, "no-score")


def test_config_finding_without_vector_is_lev():
    f = {"tool_id": "CKV_AWS_999", "severity": "LOW"}
    assert lev(f) == (True, "no-score")


# --- Rule 2: no direct impact --------------------------------------------------

def test_rule2_no_direct_impact_is_nlev_even_when_irv():
    f = {"tool_id": "CKV_AWS_18", "cvss_vector": NO_IMPACT}
    assert lev(f, irv=True) == (False, "no-direct-impact")


def test_rule2_does_not_beat_known_exploited():
    f = {"cve": "CVE-0000-0003", "cvss_vector": NO_IMPACT}
    assert lev(f, kev=True) == (True, "known-exploited")


# --- Order of the remaining checks --------------------------------------------

def test_fully_mitigated_is_first():
    f = {"cve": "CVE-0000-0004", "cvss_vector": FLOOR, "fully_mitigated": True}
    assert lev(f, kev=True, irv=True) == (False, "fully-mitigated")


def test_exploitation_observed():
    assert lev({"cve": "X", "exploitation": "active"}, {"X": 0.0}) == (True, "exploitation-observed")


def test_prediction_at_threshold_is_lev():
    assert lev({"cve": "X"}, {"X": 0.10}) == (True, "prediction")


def test_bool_wrapper_still_works():
    assert vdr.is_likely_exploitable({"cve": "X"}, {"X": 0.5}, TH) is True


# --- REQ-LEV-2: feed date and model version per finding ------------------------

def test_epss_feed_provenance_is_kept(tmp_path):
    p = tmp_path / "e.csv"
    p.write_text("#model_version:v2026.06.15,score_date:2026-11-03T12:00:27Z\ncve,epss,percentile\nCVE-0000-0005,0.2,0.9\n")
    scores = vdr.ingest_epss(str(p))
    assert scores["CVE-0000-0005"] == 0.2
    assert scores.model_version == "v2026.06.15"
    assert scores.score_date == "2026-11-03T12:00:27Z"


def test_report_records_epss_provenance_per_finding(tmp_path):
    p = tmp_path / "e.csv"
    p.write_text("#model_version:v2026.06.15,score_date:2026-11-03T12:00:27Z\ncve,epss,percentile\nCVE-0000-0005,0.2,0.9\n")
    scores = vdr.ingest_epss(str(p))
    cfg, _ = vdr.load_pain_config()
    findings = [{"tracking_id": "t1", "source": "grype", "cve": "CVE-0000-0005", "severity": "MEDIUM", "resource": "pkg:npm/x@1"}]
    report, _ = vdr.build_report(findings, [], set(), {}, index={}, config=cfg, epss_scores=scores)
    f = report["findings"][0]
    assert f["lev_basis"] == "prediction"
    assert f["epss"] == {"score": 0.2, "model_version": "v2026.06.15", "score_date": "2026-11-03T12:00:27Z"}


# --- Governed per-check vectors -------------------------------------------------

def test_vectors_without_a_decision_are_not_in_force():
    vec = vdr.load_check_vectors(FIX / "undecided.json", today=date(2026, 11, 3))
    assert vec == {}


def test_lapsed_vector_is_not_in_force():
    vec = vdr.load_check_vectors(FIX / "lapsed.json", today=date(2026, 11, 3))
    assert vec == {}


def test_malformed_vector_fails_closed():
    with pytest.raises(SystemExit):
        vdr.load_check_vectors(FIX / "malformed.json", today=date(2026, 11, 3))


def test_in_force_vector_is_applied_and_drives_lev_and_pain():
    vec = vdr.load_check_vectors(FIX / "in-force.json", today=date(2026, 11, 3))
    f = vdr.apply_check_vector({"tool_id": "CKV_AWS_18", "severity": "MEDIUM"}, vec)
    assert f["cvss_vector"] == NO_IMPACT and f["vector_source"] == "governed-check-vector"
    cfg, _ = vdr.load_pain_config()
    assert vdr.assign_pain(f, {}, cfg) == "N1"
    assert lev(f, irv=True) == (False, "no-direct-impact")


def test_known_bad_decided_vector_without_a_decision_record_fails_closed():
    with pytest.raises(SystemExit, match="is not a decision record in force"):
        vdr.load_check_vectors(FIX / "decided-without-record.json", today=date(2026, 11, 3))


def test_the_committed_vectors_are_in_force_through_their_decision():
    vec = vdr.load_check_vectors(REPO / "infrastructure" / "schemas" / "check-vectors.json",
                                 today=date(2026, 11, 5))
    assert vec and {e["decision"] for e in vec.values()} == {"DEC-180"}


def test_the_committed_vector_file_loads():
    vdr.load_check_vectors(REPO / "infrastructure" / "schemas" / "check-vectors.json", today=date.today())


# --- REQ-PAI-7: technical impact -------------------------------------------------

def test_pai7_total_when_c_and_i_high():
    assert vdr.technical_impact({"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}) == "total"
    assert vdr.technical_impact({"cvss_vector": FLOOR}) == "partial"


def test_pai7_total_when_neither_vector_nor_severity():
    cfg, _ = vdr.load_pain_config()
    f = {"tool_id": "x"}
    assert vdr.technical_impact(f) == "total"
    assert vdr.assign_pain(f, {}, cfg) in ("N4", "N5")


# --- REQ-LEV-4: overrides ---------------------------------------------------------

def test_lev_override_applies_and_is_published_then_lapses():
    ov = {"OVR-1": {"advisory": "CVE-0000-0006", "selector": "pkg:npm/*", "exclusions": [],
                     "lev": False, "justification": "j", "decided_by": "Operator",
                     "decided_on": "2026-11-01", "review_by": "2026-12-01"}}
    f = {"cve": "CVE-0000-0006", "resource": "pkg:npm/a@1"}
    assert vdr.apply_lev_override(f, True, ov, today=date(2026, 11, 3)) == (False, "OVR-1")
    assert vdr.apply_lev_override(f, True, ov, today=date(2026, 12, 2)) == (True, None)


def test_lev_override_never_clears_known_exploited():
    ov = {"OVR-1": {"advisory": "CVE-0000-0006", "selector": "*", "exclusions": [], "lev": False,
                     "justification": "j", "decided_by": "Operator", "decided_on": "2026-11-01", "review_by": "2027-01-01"}}
    f = {"cve": "CVE-0000-0006", "resource": "r"}
    assert vdr.apply_lev_override(f, True, ov, today=date(2026, 11, 3), is_kev=True) == (True, None)


def test_lev_override_exclusion():
    ov = {"OVR-1": {"advisory": "CVE-0000-0006", "selector": "*", "exclusions": ["r"], "lev": False,
                     "justification": "j", "decided_by": "Operator", "decided_on": "2026-11-01", "review_by": "2027-01-01"}}
    assert vdr.apply_lev_override({"cve": "CVE-0000-0006", "resource": "r"}, True, ov, today=date(2026, 11, 3)) == (True, None)


def test_committed_override_file_loads():
    json.loads((REPO / "data" / "lev-overrides.json").read_text())
