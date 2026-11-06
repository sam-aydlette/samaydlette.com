"""KSI-CED-RAT: training generated from the system's own data and completed by a
simulated trainee (scripts/_training.py, DEC-194), checked by two automated
methods: packet currency and completion with effectiveness."""
import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _decisions  # noqa: E402
import _training  # noqa: E402

NOW = datetime(2026, 11, 6, 12, tzinfo=timezone.utc)
REG = _decisions.load()
INC = json.loads((REPO / "data" / "incidents.json").read_text())


def _eval(previous=None, reg=REG, now=NOW):
    return _training.evaluate(previous, reg, INC, 150, 46, now)


def test_the_packet_covers_the_data_and_the_trainee_passes():
    cur, comp, summ = _eval()
    assert cur == (True, None) and comp == (True, None)
    assert summ["simulated"] is True and summ["trainee"].endswith("(simulated)")
    last = summ["history"][-1]
    assert last["passed"] and last["score"] >= _training.PASS and last["misses"]   # it misses some, on purpose
    assert {"decision:DEC-194", "incident:INC-2026-001", "rules:150", "ksis:46"} <= set(last["covers"])


def test_the_history_is_carried_and_a_new_completion_only_when_the_packet_changes():
    _, _, first = _eval()
    _, _, same = _eval(previous=first)
    assert same["history"] == first["history"]
    reg = copy.deepcopy(REG)
    new = copy.deepcopy(next(r for r in reg["decisions"] if r["id"] == "DEC-194"))
    new.update(id="DEC-999", title="A brand-new decision")
    reg["decisions"].append(new)
    _, _, changed = _eval(previous=first, reg=reg)
    assert len(changed["history"]) == 2 and "decision:DEC-999" in changed["history"][-1]["covers"]


def test_known_bad_a_packet_missing_a_new_decision_fails_currency():
    _, _, first = _eval()
    reg = copy.deepcopy(REG)
    new = copy.deepcopy(next(r for r in reg["decisions"] if r["id"] == "DEC-194"))
    new.update(id="DEC-999")
    reg["decisions"].append(new)
    required = _training.required_items(reg, INC, 150, 46, NOW.date())
    ok, why = _training.currency(first["history"], required)
    assert not ok and "decision:DEC-999" in why


def test_known_bad_a_late_or_failing_completion_fails_completion():
    _, _, summ = _eval()
    sha = summ["packet"]["sha256"]
    late = copy.deepcopy(summ["history"])
    late[-1]["completedOn"] = "2026-12-31"
    assert _training.completion(late, datetime(2027, 1, 2).date(), sha) == (
        False, "the current packet was not completed by its due date")
    failed = copy.deepcopy(summ["history"])
    failed[-1].update(score=0.5, passed=False)
    assert "below the pass mark" in _training.completion(failed, NOW.date(), sha)[1]
    trend = [dict(summ["history"][-1], score=0.7), summ["history"][-1]]
    assert "effectiveness trend" in _training.completion(trend, NOW.date(), sha)[1]
    assert _training.completion(summ["history"], NOW.date(), "0" * 64)[1] == "the current packet has not been completed"


def test_the_training_log_carries_no_obligation():
    text = (REPO / "docs" / "training-log.md").read_text()
    assert "no obligation" in text and "Annually" not in text
