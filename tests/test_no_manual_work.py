"""No in-force record commits the operator to reviewing logs or reports by hand.

The operator's direction (2026-11-06): people-run processes are automated and
exercised against simulated participants; nothing commits him to recurring
manual work. This screens the text of in-force decisions and rule records for
the operator-review wording that DEC-101 and DEC-181 used to carry. The
before-text kept under source.reworded is history, not a commitment, so it is
not screened.
"""
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures" / "manual-work"

_MANUAL = re.compile(
    r"\b(?:the\s+)?operator\s+reviews\b|\boperator's\s+log\s+review\b",
    re.IGNORECASE,
)


def _text(value):
    """Every string in a record, skipping the source block (drafting history)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for v in value:
            yield from _text(v)
    elif isinstance(value, dict):
        for k, v in value.items():
            if k != "source":
                yield from _text(v)


def manual_commitments(record):
    return [m.group(0) for s in _text(record) for m in _MANUAL.finditer(s)]


def _in_force(path, key):
    data = json.loads(path.read_text())
    rows = data[key] if isinstance(data, dict) else data
    return [r for r in rows if r.get("status") not in ("closed", "superseded")]


def test_no_in_force_decision_commits_the_operator_to_a_manual_review():
    bad = {
        r["id"]: manual_commitments(r)
        for r in _in_force(REPO / "data" / "decisions.json", "decisions")
        if manual_commitments(r)
    }
    assert bad == {}


def test_no_rule_record_commits_the_operator_to_a_manual_review():
    bad = {
        r["frr_id"]: manual_commitments(r)
        for r in _in_force(REPO / "data" / "frr-records.json", "records")
        if manual_commitments(r)
    }
    assert bad == {}


def test_known_bad_an_operator_log_review_is_caught():
    record = json.loads((FIXTURES / "bad-record.json").read_text())
    assert manual_commitments(record) == ["the operator reviews"]


def test_the_drafting_history_is_not_screened():
    record = {
        "id": "DEC-998",
        "justification": "Every build records the basis.",
        "source": {"reworded": {"before": "the operator reviews the logs"}},
    }
    assert manual_commitments(record) == []
