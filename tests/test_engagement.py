"""No engagement (DEC-194), crystal clear everywhere: the statement is published
on the trust page, in the CPO, the OCR, the Quarterly Review output, the review
calendar and every simulated output's header; and a phrase screen fails on any
wording that invites, registers, notifies, serves or answers a real agency or
FedRAMP, over the rule records, the in-force decisions, the documentation and
the trust page."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _decisions  # noqa: E402
import _engagement  # noqa: E402

KNOWN_BAD = [line for line in (REPO / "tests" / "fixtures" / "engagement" / "invitations.txt").read_text().splitlines()
             if line and not line.startswith("#")]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("line", KNOWN_BAD)
def test_known_bad_invitation_wording_is_caught(line):
    assert _engagement.invitations(line), line
    with pytest.raises(SystemExit, match="DEC-194"):
        _engagement.require_none({"text": line}, "fixture")


@pytest.mark.parametrize("line", [
    "The automated notifier writes the notice to the simulated FedRAMP as a log entry.",
    "FedRAMP (simulated) asks for the inventory.",
    "Department of Hypothetical Affairs (simulated) attends.",
    _engagement.STATEMENT,
    _engagement.SHORT,
])
def test_simulated_parties_and_the_statement_pass_the_screen(line):
    assert _engagement.invitations(line) == []


def test_no_rule_record_offers_engagement():
    doc = json.loads((REPO / "data" / "frr-records.json").read_text())
    hits = {r["frr_id"]: _engagement.invitations(json.dumps(r, ensure_ascii=False)) for r in doc["records"]}
    assert {k: v for k, v in hits.items() if v} == {}


def test_no_in_force_decision_offers_engagement():
    hits = {r["id"]: _engagement.invitations(f"{r['title']} {r['justification']}")
            for r in _decisions.in_force(_decisions.load())}
    assert {k: v for k, v in hits.items() if v} == {}


def test_no_document_or_trust_page_offers_engagement():
    files = sorted((REPO / "docs").rglob("*.md")) + [REPO / "website" / "trust" / "index.html",
                                                     REPO / "website" / ".well-known" / "security.txt"]
    hits = [f"{f.relative_to(REPO)}:{n}: {h}" for f in files
            for n, line in enumerate(f.read_text().splitlines(), 1) for h in _engagement.invitations(line)]
    assert hits == []


def test_the_statement_is_on_the_trust_page_and_in_security_txt():
    page = (REPO / "website" / "trust" / "index.html").read_text()
    assert 'id="engagement-statement"' in page and "No engagement (DEC-194)" in page
    assert "vulnerability reports only" in (REPO / "website" / ".well-known" / "security.txt").read_text()


def test_the_cpo_and_ocr_carry_the_statement():
    cyc = _load("cycle_for_engagement", REPO / "tests" / "test_certification_cycle.py")
    assert cyc._cpo()["providerExtensions"]["engagement"] == _engagement.STATEMENT
    assert cyc._ocr()["providerExtensions"]["engagement"] == _engagement.STATEMENT


def test_the_simulated_outputs_carry_the_statement(tmp_path):
    aa = _load("aa_for_engagement", REPO / "scripts" / "agency-access.py")
    out = tmp_path / "aa.json"
    aa.main(["exercise", "--output", str(out), "--md-output", "", "--today", "2026-11-05"])
    assert json.loads(out.read_text())["engagement"] == _engagement.STATEMENT
    import _ccm
    ics = _ccm.ics(_ccm.load(_ccm.CALENDAR_PATH), __import__("datetime").date(2026, 11, 6)).replace("\r\n ", "")
    assert "Simulated (DEC-194)" in ics


def test_the_decision_is_in_force_and_says_so():
    rec = _decisions.records(_decisions.load())["DEC-194"]
    assert rec["status"] == "in-force" and rec["decided_by"] == "Sam Aydlette"
    assert "really, really wants" in rec["justification"]


def test_no_intake_form_or_engagement_label_remains():
    assert not (REPO / ".github" / "ISSUE_TEMPLATE").exists() or not list((REPO / ".github" / "ISSUE_TEMPLATE").iterdir())
    agency = json.loads((REPO / "data" / "agency-access.json").read_text())
    assert all(r.get("simulated") is True for r in agency["requests"])
