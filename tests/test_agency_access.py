"""Agency access: inventory and history (CDS-TRC-AAI), self-service request and
withdrawal (CDS-TRC-SSM), access on request (CDS-UTC-AGA), and the
five-business-day denial notice to FedRAMP (CDS-UTC-AAD), exercised with
plainly fictional agencies."""
import copy
import importlib.util
import json
from datetime import date
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "agency-access"
spec = importlib.util.spec_from_file_location("agency_access", REPO / "scripts" / "agency-access.py")
aa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aa)


@pytest.mark.parametrize("start,n,expected", [
    (date(2026, 11, 25), 5, date(2026, 12, 3)),   # Thanksgiving (Thu 26 Nov) is skipped
    (date(2026, 12, 23), 5, date(2026, 12, 31)),  # Christmas (Fri 25 Dec)
    (date(2027, 7, 1), 2, date(2027, 7, 6)),      # 4 July 2027 is a Sunday, observed Monday 5 July
    (date(2026, 11, 6), 1, date(2026, 11, 9)),    # Friday to Monday
])
def test_business_days_skip_weekends_and_federal_holidays(start, n, expected):
    assert aa.add_business_days(start, n) == expected


def test_known_bad_an_unnotified_denial_past_five_business_days_fails():
    doc = aa.load(FIX / "overdue-denial.json")
    assert aa.process(doc, date(2026, 11, 9))["problems"] == []          # last day of the window
    assert aa.process(doc, date(2026, 11, 10))["problems"] == [
        "AAR-B01: FedRAMP denial notice overdue (deadline 2026-11-09)"]
    with pytest.raises(SystemExit):
        aa.main(["validate", "--register", str(FIX / "overdue-denial.json"), "--today", "2026-11-10"])


def test_known_bad_the_register_never_names_a_person():
    with pytest.raises(SystemExit, match="not people"):
        aa.load(FIX / "person-in-register.json")


def test_inventory_and_history_follow_grants_and_withdrawals():
    doc = aa.validate({"schema": "agency-access/1", "requests": [
        {"id": "AAR-T1", "agency": "A (simulated)", "system": "S1", "kind": "access", "channel": "form",
         "received_on": "2026-11-02", "decision": "granted", "decided_on": "2026-11-03", "decided_by": "Operator"},
        {"id": "AAR-T2", "agency": "A (simulated)", "kind": "withdrawal", "channel": "form",
         "received_on": "2026-11-04", "withdraws": "AAR-T1"}]}, "t")
    r = aa.process(doc, date(2026, 11, 5))
    assert r["inventory"] == []
    assert [h["event"] for h in r["history"]] == ["access received", "granted", "access withdrawn",
                                                  "withdrawal received"]


@pytest.mark.parametrize("bad", [
    {"decision": "denied"},                                   # a denial with no reason or date
    {"decision": "granted", "decided_on": "2026-11-01"},      # decided before received
    {"fedramp_notified_on": "2026-11-03"},                    # notice with no denial
])
def test_invalid_records_fail(bad):
    rec = {"id": "AAR-T1", "agency": "A (simulated)", "kind": "access", "channel": "form",
           "received_on": "2026-11-02", "decided_by": "Operator", **bad}
    with pytest.raises(SystemExit):
        aa.validate({"schema": "agency-access/1", "requests": [rec]}, "t")


@pytest.mark.parametrize("today", ["2026-11-05", "2026-11-27", "2026-12-28", "2027-01-04", "2027-07-06"])
def test_the_exercise_observes_every_expected_outcome_on_any_day(today):
    scenario = json.loads(aa.SCENARIO.read_text())
    _, _, mismatches = aa.exercise(scenario, date.fromisoformat(today))
    assert mismatches == []


def test_the_exercise_fails_when_an_outcome_is_not_the_expected_one():
    scenario = copy.deepcopy(json.loads(aa.SCENARIO.read_text()))
    scenario["expected"]["AAR-X07"] = "denial notice on time"   # the clock must catch it
    _, _, mismatches = aa.exercise(scenario, date(2026, 11, 5))
    assert mismatches == ["AAR-X07: expected 'denial notice on time', observed 'denial notice overdue'"]


def test_the_exercise_agencies_are_obviously_fictional():
    scenario = json.loads(aa.SCENARIO.read_text())
    assert all(r["agency"].endswith("(simulated)") for r in scenario["requests"])
    assert "SIMULATED" in scenario["disclaimer"] and "nothing is sent" in scenario["disclaimer"]


def test_the_committed_register_is_valid_and_has_nothing_overdue():
    doc = aa.load(aa.REGISTER)
    assert aa.process(doc, date(2026, 11, 5))["problems"] == []


def test_the_exercise_writes_a_log_that_says_it_is_simulated(tmp_path):
    out, md = tmp_path / "log.json", tmp_path / "log.md"
    assert aa.main(["exercise", "--output", str(out), "--md-output", str(md), "--today", "2026-11-05"]) == 0
    log = json.loads(out.read_text())
    assert log["simulated"] is True and log["counterparty"] == "agency"
    assert {n["state"] for n in log["denial_notices"]} == {"on time", "pending", "late", "overdue"}
    assert all("nothing is sent" in n["to"] for n in log["denial_notices"])
    assert "Agency access exercise (simulated)" in md.read_text()
