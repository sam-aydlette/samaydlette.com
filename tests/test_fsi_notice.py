"""AFC-CSO-NOC: changing the FedRAMP Security Inbox address without recording
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


def test_an_address_change_without_a_history_entry_fails():
    out = mod.check(load("changed-without-history"), base=live(), today=TODAY)
    assert any("without a history entry" in p for p in out), out
    assert any("no history entry was added" in p for p in out), out


def test_an_address_change_without_the_fedramp_notified_marker_fails():
    out = mod.check(load("changed-without-notice"), base=live(), today=TODAY)
    assert out and all("fedramp_notified" in p for p in out), out


def test_an_address_change_that_records_the_notification_passes():
    assert mod.check(load("changed-with-notice"), base=live(), today=TODAY) == []


def test_the_cli_fails_the_known_bad_fixture(tmp_path):
    base = tmp_path / "base.json"
    base.write_text(json.dumps(live()))
    assert mod.main(["--offering", str(FIX / "offering-changed-without-notice.json"), "--base", str(base)]) == 1


def test_a_notification_dated_in_the_future_fails():
    doc = load("changed-with-notice")
    doc["fedramp_security_inbox"]["history"][-1]["fedramp_notified"]["on"] = "2027-01-01"
    assert any("not in the future" in p for p in mod.check(doc, today=TODAY))


def test_rewriting_history_fails_against_the_base():
    good = load("changed-with-notice")
    rewritten = copy.deepcopy(good)
    rewritten["fedramp_security_inbox"]["history"][0]["since"] = "2026-01-01"
    assert any("append-only" in p for p in mod.check(rewritten, base=good, today=TODAY))


@pytest.mark.parametrize("address", ["fsi@example.com", "FSI@samaydlette.com", "not-an-address"])
def test_the_address_must_be_on_the_systems_domain(address):
    doc = live()
    doc["fedramp_security_inbox"]["address"] = address
    doc["fedramp_security_inbox"]["history"][-1]["address"] = address
    assert any("must be a lower-case address" in p for p in mod.check(doc, today=TODAY))


def test_establishing_the_inbox_needs_a_basis_when_nobody_was_notified():
    doc = live()
    doc["fedramp_security_inbox"]["history"][0]["basis"] = ""
    assert any("basis" in p for p in mod.check(doc, today=TODAY))


def test_a_missing_inbox_block_fails():
    assert mod.check({}, today=TODAY)
