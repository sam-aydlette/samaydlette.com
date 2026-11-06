"""The withheld-detail request path (VER-RPT-NID, DEC-182), exercised on every
VDR build against a simulated requester: the log records what would be
supplied (field names and a sha256), never the detail, and no real request is
answered (DEC-194)."""
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _evaluation  # noqa: E402

OPEN = {"tracking_id": "F-1", "final_disposition": "open", "internet_reachable": True, "likely_exploitable": True,
        "pain": "N4", "description": "where and how", "locations": ["/api/x"], "fix_versions": ["1.2.3"]}


def test_a_withheld_finding_is_logged_without_its_detail():
    log = _evaluation.withheld_detail_exercise([OPEN, {**OPEN, "tracking_id": "F-2", "pain": "N1"}])
    assert log["simulated"] is True and "(simulated)" in log["requester"] and log["cannedFinding"] is False
    assert [e["tracking_id"] for e in log["findings"]] == ["F-1"]
    assert log["findings"][0]["withheldFields"] == ["description", "locations", "fix_versions"]
    text = json.dumps(log)
    assert "where and how" not in text and "/api/x" not in text and log["deliveredTo"].startswith("nobody")


def test_with_nothing_withheld_a_canned_simulated_finding_runs_the_path():
    log = _evaluation.withheld_detail_exercise([{**OPEN, "pain": "N1"}])
    assert log["cannedFinding"] is True and [e["tracking_id"] for e in log["findings"]] == ["SIM-0001"]


def test_known_bad_a_disclosure_rule_that_stops_withholding_fails_the_exercise(monkeypatch):
    monkeypatch.setattr(_evaluation, "_WITHHOLD_FROM", 9)
    with pytest.raises(SystemExit, match="simulated finding was not withheld"):
        _evaluation.withheld_detail_exercise([])


def test_the_disclosure_reason_promises_no_party_anything():
    reason = _evaluation.disclosure(OPEN)["reason"]
    assert "DEC-194" in reason and "necessary parties" not in reason
