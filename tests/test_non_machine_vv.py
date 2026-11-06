"""VDR-TFR-NMV: every non-machine resource is verified and validated by machine
checks on every deploy and every night (scripts/_nonmachine.py,
scripts/check-non-machine-vv.py): the file exists, the paths and DEC IDs it
cites resolve, it names no retired mechanism, and every tagged count matches
the code. No person attests anything (DEC-190 is superseded)."""
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "non-machine"
sys.path.insert(0, str(REPO / "scripts"))
import _decisions  # noqa: E402
import _nonmachine  # noqa: E402

REG = _decisions.load()
NOW = datetime(2026, 11, 6, 7, tzinfo=timezone.utc)


def _probs(name):
    return _nonmachine.problems(_nonmachine.load(FIX / name), REG)


def test_every_committed_resource_passes_its_machine_checks():
    doc = _nonmachine.load()
    assert _nonmachine.problems(doc, REG) == []
    st = _nonmachine.status(doc, REG, NOW)
    assert st["status"] == "ok" and st["verifiedAt"] == NOW.isoformat()
    assert all(r["result"] == "pass" and r["lastVerified"] == "2026-11-06" for r in st["resources"])


def test_the_register_lists_every_policy_runbook_and_procedure():
    listed = {e["path"] for e in _nonmachine.load()["resources"]}
    for folder, skip in _nonmachine.MUST_LIST:
        for p in (REPO / folder).glob("*.md"):
            assert p.name in skip or f"{folder}/{p.name}" in listed
    assert ("docs/procedures", set()) in _nonmachine.MUST_LIST


def test_no_entry_carries_a_manual_attestation():
    doc = json.loads((REPO / "data" / "non-machine-resources.json").read_text())
    assert doc["schema"] == "non-machine-resources/2"
    assert not any("last_verified" in e or "operator" in e["verifies"] for e in doc["resources"])
    assert "DEC-190" not in json.dumps(doc["resources"])


# --- known-bad: the documents as they stood, each failing for its own reason -----------

@pytest.mark.parametrize("rid,reason", [
    ("NMR-KB-ROB", "retired mechanism (POA&M)"),
    ("NMR-KB-ROB", "retired mechanism (Duo-enforced MFA)"),
    ("NMR-KB-ROB", "retired mechanism (long-lived deploy keys)"),
    ("NMR-KB-ROB", "retired mechanism (no SCN-Type label)"),
    ("NMR-KB-IA", "retired mechanism (Duo-enforced MFA)"),
    ("NMR-KB-IA", "retired mechanism (long-lived deploy keys)"),
    ("NMR-KB-SLA", "retired mechanism (SSP)"),
    ("NMR-KB-SLA", "retired mechanism (POA&M)"),
    ("NMR-KB-CONMON", "retired mechanism (POA&M)"),
    ("NMR-KB-PTA", "retired mechanism (Basic Auth)"),
    ("NMR-KB-CA", "retired mechanism (SSP)"),
    ("NMR-KB-RECOVERY", "cites infrastructure/terraform.tfstate, which does not exist"),
    ("NMR-KB-PL", "cites ../../website/.well-known/ksi-signal.json, which does not exist"),
    ("NMR-KB-DEC", "cites DEC-999, which is not in the decision register"),
    ("NMR-KB-COUNT", "states watchdog-alarms = 4; the code has 5"),
    ("NMR-KB-UNSTATED", "tags watchdog-alarms = 5 but does not state it"),
])
def test_known_bad_documents_fail_for_their_reason(rid, reason):
    probs = [p for p in _probs("known-bad.json") if p.startswith(rid + ":")]
    assert any(reason in p for p in probs), probs


def test_a_line_that_says_the_thing_is_retired_may_name_it():
    p = REPO / "docs" / "x.md"
    ids = {r["id"] for r in REG["decisions"]}
    assert _nonmachine.text_problems("T", "The POA&M was replaced by the decision register.", p, REPO, ids) == []
    assert _nonmachine.text_problems("T", "Open POA&M items are listed here.", p, REPO, ids)


def test_a_listed_file_that_is_gone_fails():
    assert "NMR-POL-AC: docs/policies/no-such-policy.md does not exist" in _probs("missing-file.json")


def test_an_unlisted_policy_fails():
    assert "docs/policies/at-policy.md has no entry in the register" in _probs("missing-file.json")


def test_a_window_longer_than_the_rule_is_refused():
    with pytest.raises(SystemExit, match="max_age_days must be an integer from 1 to 92"):
        _nonmachine.load(FIX / "window-too-long.json")


def test_known_bad_an_entry_with_a_manual_attestation_is_refused():
    with pytest.raises(SystemExit, match="fields must be exactly"):
        _nonmachine.load(FIX / "malformed-entry.json")


def test_a_missing_register_fails_closed(tmp_path):
    with pytest.raises(SystemExit, match="not found"):
        _nonmachine.load(tmp_path / "absent.json")


def test_a_failing_check_publishes_the_epoch_so_the_window_is_red_at_once():
    st = _nonmachine.status(_nonmachine.load(FIX / "known-bad.json"), REG, NOW)
    assert st["status"] == "lapsed" and st["verifiedAt"] == _nonmachine.EPOCH
    assert {r["result"] for r in st["resources"]} == {"fail"}


# --- the CLI: the deploy enforces, the nightly publishes -------------------------------

def _run(*args):
    return subprocess.run([sys.executable, str(REPO / "scripts" / "check-non-machine-vv.py"), *args],
                          capture_output=True, text=True)


def test_enforce_fails_on_a_failing_check_and_writes_the_status(tmp_path):
    out = tmp_path / "vdr-non-machine-vv.json"
    r = _run("--register", str(FIX / "known-bad.json"), "--enforce", "--out", str(out))
    assert r.returncode == 1 and "::error::non-machine V&V" in r.stderr
    assert json.loads(out.read_text())["status"] == "lapsed"


def test_without_enforce_a_failing_check_is_published_not_failed(tmp_path):
    out = tmp_path / "s.json"
    r = _run("--register", str(FIX / "known-bad.json"), "--out", str(out))
    assert r.returncode == 0 and json.loads(out.read_text())["status"] == "lapsed"


def test_enforce_passes_the_real_register():
    assert _run("--enforce").returncode == 0


def test_the_deploy_enforces_it_and_the_nightly_publishes_it():
    deploy = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    nightly = (REPO / ".github" / "workflows" / "evidence-nightly.yml").read_text()
    assert "check-non-machine-vv.py --enforce --out vdr-non-machine-vv.json" in deploy
    assert "check-non-machine-vv.py --out vdr-non-machine-vv.json" in nightly
    fresh = json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json").read_text())
    entry = next(a for a in fresh["artifacts"] if a["path"] == ".well-known/vdr-non-machine-vv.json")
    assert entry["max_age_hours"] <= 92 * 24 and entry["timestamp"] == {"source": "json", "field": "verifiedAt"}
    assert entry["cadence"] == "nightly"
