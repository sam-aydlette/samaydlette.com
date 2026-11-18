"""The Ongoing Certification Report calendar (data/ocr-calendar.json) and the
dates the OCR and the CPO publish from it.

CCM-OCR-SOR, CCM-QTR-SAR, CCM-OCR-NRD and CCM-QTR-NRD cite these tests.
"""
import importlib.util
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _decisions  # noqa: E402
import _fedramp_schema as fs  # noqa: E402
import _ocr_calendar as oc  # noqa: E402


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ocr = _load("build_ocr", "build-ocr.py")
cpo = _load("build_cpo", "build-cpo.py")
CAL = oc.load()
NOW = datetime(2026, 11, 18, 12, tzinfo=timezone.utc)
ISSUED_Q4 = [{"id": "2026-Q4", "due": "2026-11-15", "issued_on": "2026-11-18",
              "period_from": "2026-11-04", "period_to": "2026-11-18"}]


# --- the cycle (CCM-OCR-SOR) -------------------------------------------------------------

def test_reports_fall_mid_quarter_on_a_regular_three_month_cycle():
    dues = oc.due_dates(CAL, date(2027, 12, 31))
    assert dues[:5] == [date(2026, 11, 15), date(2027, 2, 15), date(2027, 5, 15),
                        date(2027, 8, 15), date(2027, 11, 15)]
    assert {(d.month - 1) % 3 for d in dues} == {1}  # the middle month of each quarter
    assert [oc.issue_id(d) for d in dues[:2]] == ["2026-Q4", "2027-Q1"]


def _write(tmp_path, **change):
    p = tmp_path / "cal.json"
    p.write_text(json.dumps({**json.loads(oc.PATH.read_text()), **change}))
    return p


@pytest.mark.parametrize("change", [
    {"issue_dates": {"months": [1, 2, 3, 4], "day": 15}},     # not one per quarter
    {"issue_dates": {"months": [2, 5, 8, 11], "day": 31}},
    {"review_business_days": 2}, {"review_business_days": 11},  # outside CCM-QTR-SAR's window
    {"first_period_start": "soon"}, {"decided_by": ""}, {"schema": "x"},
])
def test_a_calendar_that_breaks_the_cycle_or_has_no_decision_fails_closed(tmp_path, change):
    with pytest.raises(SystemExit, match="OCR calendar"):
        oc.load(_write(tmp_path, **change))


def test_the_calendar_is_a_recorded_operator_decision():
    assert CAL["decided_by"] == "Sam Aydlette" and CAL["decided_on"] == "2026-11-18"


# --- the review (CCM-QTR-SAR) ------------------------------------------------------------

def test_the_review_falls_three_to_ten_business_days_after_the_release():
    r = oc.next_review(CAL, ISSUED_Q4, NOW.date())
    assert r == date(2026, 11, 25)
    business = sum(1 for n in range(1, (r - date(2026, 11, 18)).days + 1)
                   if date.fromordinal(date(2026, 11, 18).toordinal() + n).weekday() < 5)
    assert 3 <= business <= 10


def test_business_days_skip_weekends():
    assert oc.add_business_days(date(2027, 2, 12), 5) == date(2027, 2, 19)  # Friday to Friday


# --- the next dates (CCM-OCR-NRD, CCM-QTR-NRD) --------------------------------------------

def test_an_unissued_due_date_is_the_next_report_and_is_reported_overdue():
    assert oc.next_report(CAL, [], NOW.date()) == (date(2026, 11, 15), True)


def test_once_issued_the_next_report_is_the_following_quarter():
    assert oc.next_report(CAL, ISSUED_Q4, NOW.date()) == (date(2027, 2, 15), False)
    assert oc.period_start(CAL, ISSUED_Q4, date(2026, 11, 19)) == date(2026, 11, 19)


def test_on_the_issue_day_the_current_period_is_the_issued_one():
    assert oc.period_start(CAL, ISSUED_Q4, NOW.date()) == date(2026, 11, 4)


def _ocr(issued=(), now=NOW):
    return ocr.build_ocr({"risk_accepted": [{"tracking_id": "t"}]}, _decisions.load(), [], "sig", now, CAL, issued)


def test_the_ocr_is_in_fedramps_schema_and_publishes_the_calendar_dates():
    doc = _ocr()
    assert fs.validate(doc, "ocr") == []
    assert doc["reportPeriod"] == {"from": "2026-11-04", "to": "2026-11-18"}
    assert doc["next_ongoing_certification_report_date"] == "2026-11-15"
    assert doc["next_ongoing_certification_report_overdue"] is True
    assert doc["next_quarterly_review_date"] == "2026-11-25"
    assert doc["reportableIncidents"] == {"incidents": []}


def test_the_ocrs_period_starts_after_the_last_issue():
    doc = _ocr(ISSUED_Q4, datetime(2026, 12, 1, tzinfo=timezone.utc))
    assert doc["reportPeriod"] == {"from": "2026-11-19", "to": "2026-12-01"}
    assert doc["next_ongoing_certification_report_date"] == "2027-02-15"


def test_the_cpo_publishes_the_same_next_dates():
    off = json.loads((REPO / "data" / "cds" / "offering.json").read_text())
    prof = json.loads((REPO / "data" / "system-profile.json").read_text())
    doc = cpo.build(off, prof, {"signal_id": "s", "components": []}, NOW, "abc", None, CAL)
    assert fs.validate(doc, "cpo") == []
    assert doc["serviceProperties"]["nextOngoingCertificationReportDate"] == "2026-11-15"
    assert doc["next_quarterly_review_date"] == _ocr()["next_quarterly_review_date"]


def test_on_its_issue_day_the_ocr_names_the_issue_and_how_late_it_is():
    issued = [{**ISSUED_Q4[0], "days_late": 3}]
    assert _ocr(issued)["issue"] == {"id": "2026-Q4", "due": "2026-11-15", "days_late": 3}
    assert "issued 3 days late" in ocr.render_markdown(_ocr(issued))
    assert _ocr()["issue"] is None
