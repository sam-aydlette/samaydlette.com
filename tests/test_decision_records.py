"""Every recorded human risk decision says who made it, when, and when it is reviewed.

Risk decisions are reviewed annually. The trust center publishes these fields,
and a record without them is reported to the Authorizing Official as a gap, so
a new record must carry them from the start.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DECISIONS = {"false-positive", "configuration", "interconnection", "operational-requirement"}


def _date(value: str) -> date:
    return date.fromisoformat(value)


def _annual(decided_on: str, review_by: str) -> bool:
    d = _date(decided_on)
    return _date(review_by) == d.replace(year=d.year + 1)


def test_every_open_poam_decision_is_attributed_and_reviewed_annually():
    items = json.loads((REPO / "data" / "poam-items.json").read_text())["items"]
    decisions = [i for i in items if i.get("category") in DECISIONS]
    assert decisions
    for i in decisions:
        for field in ("decided_by", "decided_on", "review_by"):
            assert i.get(field), f"{i['id']} lacks {field}"
        assert _annual(i["decided_on"], i["review_by"]), f"{i['id']}: review_by is not one year after decided_on"


def test_every_vulnerability_disposition_is_attributed_and_reviewed_annually():
    register = json.loads((REPO / "data" / "vuln-dispositions.json").read_text())["dispositions"]
    for key, d in register.items():
        for field in ("decided_by", "decided_on", "review_by"):
            assert d.get(field), f"{key} lacks {field}"
        assert _annual(d["decided_on"], d["review_by"]), key


def test_every_policy_exception_is_attributed():
    # An exception's review date is its expiry, which check-exceptions.py enforces.
    for e in json.loads((REPO / "infrastructure" / "policy" / "exceptions" / "data.json").read_text()):
        assert e.get("decided_by") and _date(e["decided_on"]) <= _date(e["expiry"])
