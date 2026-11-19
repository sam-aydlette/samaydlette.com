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
    """Reviewed at least once a year: review_by is after decided_on and no later
    than one year on. A sooner review is stricter, never weaker (DEC-041 is
    reviewed after 90 days; operator, 2026-11-19)."""
    d = _date(decided_on)
    return d < _date(review_by) <= d.replace(year=d.year + 1)


def test_every_in_force_decision_is_attributed_and_reviewed_annually():
    # Configuration suppressions and vulnerability dispositions alike: one register.
    records = _decisions.in_force(_decisions.load())
    assert records
    for r in records:
        for field in ("decided_by", "decided_on", "review_by"):
            assert r.get(field), f"{r['id']} lacks {field}"
        assert _annual(r["decided_on"], r["review_by"]), f"{r['id']}: review_by is not within a year of decided_on"
    assert any(r["applies_to"].get("vuln_ids") for r in records)
    assert any(r["applies_to"].get("check_ids") for r in records)


def test_every_policy_exception_is_attributed():
    # An exception's review date is its expiry, which check-exceptions.py enforces.
    for e in json.loads((REPO / "infrastructure" / "policy" / "exceptions" / "data.json").read_text()):
        assert e.get("decided_by") and _date(e["decided_on"]) <= _date(e["expiry"])


def test_a_review_may_come_sooner_than_a_year_never_later_or_before_the_decision():
    assert _annual("2026-11-19", "2027-11-19") and _annual("2026-11-19", "2027-02-19")
    assert not _annual("2026-11-19", "2027-11-20") and not _annual("2026-11-19", "2026-11-19")
