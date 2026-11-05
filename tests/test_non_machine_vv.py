"""VDR-TFR-NMV: non-machine resources are verified and validated at least every
3 months, each under an in-force decision record (scripts/_nonmachine.py,
scripts/check-non-machine-vv.py)."""
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "non-machine"
sys.path.insert(0, str(REPO / "scripts"))
import _decisions  # noqa: E402
import _nonmachine  # noqa: E402

REG = _decisions.load()
DECIDED = date(2026, 11, 5)


def _probs(name, today=DECIDED):
    return _nonmachine.problems(_nonmachine.load(FIX / name), REG, today)


def test_the_register_is_current_on_the_day_it_was_verified():
    doc = _nonmachine.load()
    assert _nonmachine.problems(doc, REG, DECIDED) == []
    st = _nonmachine.status(doc, REG, DECIDED)
    assert st["status"] == "ok" and st["verifiedAt"].startswith("2026-11-05") and st["nextDueBy"] == "2027-02-05"


def test_the_register_lists_every_policy_and_runbook():
    listed = {e["path"] for e in _nonmachine.load()["resources"]}
    for folder, skip in _nonmachine.MUST_LIST:
        for p in (REPO / folder).glob("*.md"):
            assert p.name in skip or f"{folder}/{p.name}" in listed


def test_every_entry_cites_an_in_force_decision_decided_on_its_date():
    recs = _decisions.records(REG)
    for e in _nonmachine.load()["resources"]:
        d = recs[e["last_verified"]["decision"]]
        assert d["status"] == "in-force" and d["decided_on"] == e["last_verified"]["on"]


def test_the_register_lapses_after_92_days():
    doc = _nonmachine.load()
    assert _nonmachine.problems(doc, REG, date(2027, 2, 5)) == []
    late = _nonmachine.problems(doc, REG, date(2027, 2, 6))
    assert late and all("93 days ago (more than 92)" in p for p in late)
    assert _nonmachine.status(doc, REG, date(2027, 2, 6))["status"] == "lapsed"


# --- known-bad fixtures, each failing for its own reason ----------------------------

def test_a_stale_verification_fails():
    assert _probs("stale.json") == ["NMR-POL-AC: last verified 2026-05-08, 181 days ago (more than 92)",
                                    "NMR-POL-AC: verified 2026-05-08 but DEC-190 was decided 2026-11-05"] + \
        [p for p in _probs("stale.json") if "has no entry" in p]


def test_a_decision_not_in_the_register_fails():
    assert "NMR-POL-AC: DEC-199 is not in the decision register" in _probs("unknown-decision.json")


def test_a_listed_file_that_is_gone_fails():
    assert "NMR-POL-AC: docs/policies/no-such-policy.md does not exist" in _probs("missing-file.json")


def test_an_unlisted_policy_fails():
    # The fixtures list only the AC policy, so every other policy is unlisted.
    assert "docs/policies/at-policy.md has no entry in the register" in _probs("missing-file.json")


def test_a_window_longer_than_the_rule_is_refused():
    with pytest.raises(SystemExit, match="max_age_days must be an integer from 1 to 92"):
        _nonmachine.load(FIX / "window-too-long.json")


def test_a_malformed_entry_is_refused():
    with pytest.raises(SystemExit, match=r"last_verified must be \{on: YYYY-MM-DD, decision: DEC-NNN\}"):
        _nonmachine.load(FIX / "malformed-entry.json")


def test_a_missing_register_fails_closed(tmp_path):
    with pytest.raises(SystemExit, match="not found"):
        _nonmachine.load(tmp_path / "absent.json")


# --- the CLI: the deploy enforces, the nightly publishes -------------------------------

def _run(*args):
    return subprocess.run([sys.executable, str(REPO / "scripts" / "check-non-machine-vv.py"), *args],
                          capture_output=True, text=True)


def test_enforce_fails_on_a_lapsed_register_and_writes_the_status(tmp_path):
    out = tmp_path / "vdr-non-machine-vv.json"
    r = _run("--register", str(FIX / "stale.json"), "--today", "2026-11-05", "--enforce", "--out", str(out))
    assert r.returncode == 1 and "::error::non-machine V&V" in r.stderr
    assert json.loads(out.read_text())["status"] == "lapsed"


def test_without_enforce_a_lapsed_register_is_published_not_failed(tmp_path):
    out = tmp_path / "s.json"
    r = _run("--register", str(FIX / "stale.json"), "--today", "2026-11-05", "--out", str(out))
    assert r.returncode == 0 and json.loads(out.read_text())["status"] == "lapsed"


def test_enforce_passes_the_real_register_on_its_date():
    assert _run("--today", "2026-11-05", "--enforce").returncode == 0


def test_the_deploy_enforces_it_and_the_nightly_publishes_it():
    deploy = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    nightly = (REPO / ".github" / "workflows" / "evidence-nightly.yml").read_text()
    assert "check-non-machine-vv.py --enforce --out vdr-non-machine-vv.json" in deploy
    assert "check-non-machine-vv.py --out vdr-non-machine-vv.json" in nightly
    fresh = json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json").read_text())
    entry = next(a for a in fresh["artifacts"] if a["path"] == ".well-known/vdr-non-machine-vv.json")
    assert entry["max_age_hours"] == 92 * 24 and entry["timestamp"] == {"source": "json", "field": "verifiedAt"}
