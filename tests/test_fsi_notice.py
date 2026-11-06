"""AFC-CSO-NOC: changing the FedRAMP Security Inbox contact (simulated inbox;
the contact is a statement, not a mailbox) without recording
that FedRAMP was notified fails the unit-test job (scripts/check-fsi-notice.py).

Known-bad fixtures under tests/fixtures/fsi/ each fail for one reason; the good
one shows what a compliant change looks like."""

import copy
import importlib.util
import json
from datetime import date
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "fsi"
TODAY = date(2026, 12, 15)

spec = importlib.util.spec_from_file_location("check_fsi_notice", REPO / "scripts" / "check-fsi-notice.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def load(name):
    return json.loads((FIX / f"offering-{name}.json").read_text())


def live():
    return json.loads((REPO / "data" / "cds" / "offering.json").read_text())


def test_the_committed_inbox_record_passes():
    assert mod.check(live(), today=date.today()) == []
    assert mod.main([]) == 0


def test_a_contact_change_without_a_history_entry_fails():
    out = mod.check(load("changed-without-history"), base=live(), today=TODAY)
    assert any("without a history entry" in p for p in out), out
    assert any("no history entry was added" in p for p in out), out


def test_a_contact_change_with_its_dated_history_entry_passes():
    assert mod.check(load("changed"), base=live(), today=TODAY) == []


def test_known_bad_a_hand_recorded_notice_is_refused():
    out = mod.check(load("changed-hand-recorded"), base=live(), today=TODAY)
    assert out and all("fedramp_notified" in p for p in out), out


def test_the_cli_fails_the_known_bad_fixture(tmp_path):
    base = tmp_path / "base.json"
    base.write_text(json.dumps(live()))
    assert mod.main(["--offering", str(FIX / "offering-changed-hand-recorded.json"), "--base", str(base)]) == 1


def test_a_change_dated_in_the_future_fails():
    doc = load("changed")
    doc["fedramp_security_inbox"]["history"][-1]["since"] = "2027-01-01"
    assert any("not in the future" in p for p in mod.check(doc, today=TODAY))


def test_rewriting_history_fails_against_the_base():
    good = load("changed")
    rewritten = copy.deepcopy(good)
    rewritten["fedramp_security_inbox"]["history"][0]["since"] = "2026-01-01"
    assert any("append-only" in p for p in mod.check(rewritten, base=good, today=TODAY))


# --- the deploy files the notice with the simulated FedRAMP (nothing is sent) ------------

def _intake(notice):
    return {"receiptId": "SIM-NOC-TEST", "receivedBy": "FedRAMP (simulated)"}


def test_the_deploy_files_a_change_notice_once_and_carries_it_over():
    notices, problems = mod.file_notices(load("changed"), None, date(2026, 12, 2), _intake)
    assert problems == [] and len(notices) == 1
    n = notices[0]
    assert n["changedOn"] == "2026-12-01" and n["filedOn"] == "2026-12-02" and n["receipt"]["receiptId"]
    again, problems = mod.file_notices(load("changed"), notices, date(2027, 3, 1), _intake)
    assert problems == [] and again == notices  # filed once; never re-filed or re-dated


def test_the_establishing_entry_needs_no_notice():
    notices, problems = mod.file_notices(live(), None, date.today(), _intake)
    assert notices == [] and problems == []


def test_a_notice_filed_more_than_one_business_day_after_the_change_fails():
    # 2026-12-01 is a Tuesday: the notice is due by Wednesday 2026-12-02.
    _, problems = mod.file_notices(load("changed"), None, date(2026, 12, 3), _intake)
    assert any("one business day" in p for p in problems), problems


def test_known_bad_a_late_notice_on_record_fails_the_deploy():
    prev = json.loads((FIX / "notices-late.json").read_text())["changeNotices"]
    _, problems = mod.file_notices(load("changed"), prev, date(2026, 12, 4), _intake)
    assert any("filed 2026-12-03" in p and "one business day" in p for p in problems), problems


def test_a_change_over_a_weekend_is_due_the_next_business_day():
    doc = load("changed")
    doc["fedramp_security_inbox"]["history"][-1]["since"] = "2026-11-27"  # Friday after Thanksgiving
    _, problems = mod.file_notices(doc, None, date(2026, 11, 30), _intake)  # the next Monday
    assert problems == []


def test_a_rewritten_earlier_notice_fails():
    notices, _ = mod.file_notices(load("changed"), None, date(2026, 12, 2), _intake)
    bad = [dict(notices[0], extra="rewritten")]
    _, problems = mod.file_notices(load("changed"), bad, date(2026, 12, 2), _intake)
    assert any("malformed" in p for p in problems)


@pytest.mark.parametrize("contact", ["", "   ", "two\nlines", "x" * 301, None])
def test_the_contact_must_be_one_printable_line(contact):
    doc = live()
    doc["fedramp_security_inbox"]["contact"] = contact
    doc["fedramp_security_inbox"]["history"][-1]["contact"] = contact
    assert any("must be one non-empty line" in p for p in mod.check(doc, today=TODAY))


def test_the_published_contact_says_simulated_and_points_to_linkedin():
    contact = live()["fedramp_security_inbox"]["contact"]
    assert "Simulated for this proof of concept" in contact
    assert "https://www.linkedin.com/in/sa2/" in contact
    assert "@" not in contact


def test_establishing_the_inbox_needs_a_basis():
    doc = live()
    doc["fedramp_security_inbox"]["history"][0]["basis"] = ""
    assert any("basis" in p for p in mod.check(doc, today=TODAY))


def test_a_missing_inbox_block_fails():
    assert mod.check({}, today=TODAY)
