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

import pytest
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


def test_an_accepted_mfa_finding_publishes_no_planned_purchase():
    """DEC-150 accepts virtual TOTP; DEC-025 must not still plan a hardware key,
    or the OCR's planned changes (build-ocr.py planned_changes) publish it."""
    rows = {r["id"]: r for r in _in_force(REPO / "data" / "decisions.json", "decisions")}
    assert "DEC-150" in rows
    assert not rows["DEC-025"].get("remediation_plan")
    assert not rows["DEC-025"].get("planned_completion")


# --- the relapse gate (DEC-195): no recurring manual work anywhere it can be promised ---
# scripts/_nonmachine.manual_work screens every sentence for a person, a review-like
# act and a recurring cadence (or a "Review cadence" line). Allowed: a sentence citing
# DEC-195 (the three recurring human acts that remain), a section headed as history,
# and the DEC-195 record itself.

import ast  # noqa: E402
import sys  # noqa: E402

sys.path.insert(0, str(REPO / "scripts"))
import _nonmachine  # noqa: E402

ALLOWED_RECORDS = {"DEC-195"}


def _hits(text):
    return [s for _, s in _nonmachine.manual_work(text)]


def test_known_bad_the_operator_reviews_cloudtrail_quarterly_is_caught():
    assert _hits((FIXTURES / "bad-doc.md").read_text()) == ["The operator reviews CloudTrail quarterly."]
    probs = _nonmachine.text_problems("NMR-X", (FIXTURES / "bad-doc.md").read_text(), FIXTURES / "bad-doc.md",
                                      REPO, set())
    assert probs == ["NMR-X: line 5 commits a person to recurring manual work: "
                     "'The operator reviews CloudTrail quarterly.'"]


def test_known_bad_a_passive_cadence_and_a_review_cadence_line_are_caught():
    assert _hits((FIXTURES / "bad-passive.md").read_text()) == [
        "**Review cadence.** Annually with the security review.",
        "Plans are version-controlled and reviewed annually."]


def test_dec_195_acts_mechanisms_and_history_sections_are_allowed():
    assert _hits((FIXTURES / "allowed.md").read_text()) == []


def test_no_document_commits_a_person_to_recurring_manual_work():
    bad = {}
    for p in sorted((REPO / "docs").rglob("*.md")) + [REPO / "README.md"]:
        hits = _nonmachine.manual_work(p.read_text(encoding="utf-8"))
        if hits:
            bad[str(p.relative_to(REPO))] = hits
    assert bad == {}


def _screen(record):
    return [s for t in _text(record) for _, s in _nonmachine.manual_work(t)]


def test_no_in_force_decision_or_rule_record_commits_a_person_to_recurring_manual_work():
    bad = {r["id"]: _screen(r) for r in _in_force(REPO / "data" / "decisions.json", "decisions")
           if r["id"] not in ALLOWED_RECORDS and _screen(r)}
    bad |= {r["frr_id"]: _screen(r) for r in _in_force(REPO / "data" / "frr-records.json", "records")
            if _screen(r)}
    assert bad == {}


def _string_constants(path):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.lineno, node.value


@pytest.mark.parametrize("script", ["scripts/_controls.py", "scripts/build-vdr-report.py"])
def test_no_published_statement_or_rationale_commits_a_person_to_recurring_manual_work(script):
    bad = [(n, s) for n, text in _string_constants(REPO / script) for _, s in _nonmachine.manual_work(text)]
    assert bad == []


def test_no_data_record_commits_a_person_to_recurring_manual_work():
    bad = {}
    for name in ("vdr-activities.json", "non-machine-resources.json"):
        hits = _screen(json.loads((REPO / "data" / name).read_text()))
        if hits:
            bad[name] = hits
    assert bad == {}
