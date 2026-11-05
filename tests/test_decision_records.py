"""Every recorded human risk decision says who made it, when, and when it is reviewed.

Risk decisions are reviewed annually. The trust center publishes these fields,
and a record without them is reported to the Authorizing Official as a gap, so
a new record must carry them from the start.
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import _decisions  # noqa: E402


def _date(value: str) -> date:
    return date.fromisoformat(value)


def _annual(decided_on: str, review_by: str) -> bool:
    d = _date(decided_on)
    return _date(review_by) == d.replace(year=d.year + 1)


def test_every_in_force_decision_is_attributed_and_reviewed_annually():
    # Configuration suppressions and vulnerability dispositions alike: one register.
    records = _decisions.in_force(_decisions.load())
    assert records
    for r in records:
        for field in ("decided_by", "decided_on", "review_by"):
            assert r.get(field), f"{r['id']} lacks {field}"
        assert _annual(r["decided_on"], r["review_by"]), f"{r['id']}: review_by is not one year after decided_on"
    assert any(r["applies_to"].get("vuln_ids") for r in records)
    assert any(r["applies_to"].get("check_ids") for r in records)


def test_every_policy_exception_is_attributed():
    # An exception's review date is its expiry, which check-exceptions.py enforces.
    for e in json.loads((REPO / "infrastructure" / "policy" / "exceptions" / "data.json").read_text()):
        assert e.get("decided_by") and _date(e["decided_on"]) <= _date(e["expiry"])
