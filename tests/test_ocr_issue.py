"""The quarterly issue of the Ongoing Certification Report (scripts/issue-ocr.py):
when one is due, the deploy freezes the OCR and the package beside it, records
each file's SHA-256 in a signed index, and never replaces an issued snapshot.

CCM-OCR-AVL and CDS-CSO-HAD cite these tests.
"""
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _ocr_calendar as oc  # noqa: E402


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


issue = _load("issue_ocr", "issue-ocr.py")
cpo = _load("build_cpo", "build-cpo.py")
CAL = oc.load()
NOV18 = datetime(2026, 11, 18, 12, tzinfo=timezone.utc)
WORKFLOW = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()


def _empty():
    return {"schema": "ocr-issues/1", "issues": []}


# --- when to issue ---------------------------------------------------------------------

def test_a_passed_due_date_is_issued_late_with_its_period():
    idx = _empty()
    new = issue.plan(idx, CAL, NOV18, "abc")
    assert {k: new[k] for k in ("id", "due", "issued_on", "days_late", "period_from", "period_to")} == {
        "id": "2026-Q4", "due": "2026-11-15", "issued_on": "2026-11-18", "days_late": 3,
        "period_from": "2026-11-04", "period_to": "2026-11-18"}
    assert new["files"] is None and new["path"] == ".well-known/ocr/2026-Q4/"
    assert idx["fedramp_id"].endswith("NOT-A-REAL-FEDRAMP-ID") and idx["calendar"]["decided_by"] == "Sam Aydlette"


def test_nothing_is_issued_before_the_next_due_date():
    idx = {"schema": "ocr-issues/1", "issues": [
        {"id": "2026-Q4", "due": "2026-11-15", "issued_on": "2026-11-18", "period_from": "2026-11-04",
         "period_to": "2026-11-18", "files": {"x": "y"}}]}
    assert issue.plan(idx, CAL, datetime(2027, 2, 14, tzinfo=timezone.utc)) is None
    assert len(idx["issues"]) == 1
    nxt = issue.plan(idx, CAL, datetime(2027, 2, 15, tzinfo=timezone.utc))
    assert nxt["id"] == "2027-Q1" and nxt["days_late"] == 0 and nxt["period_from"] == "2026-11-19"


def test_an_unfrozen_issue_in_the_published_index_fails_closed():
    idx = _empty()
    issue.plan(idx, CAL, NOV18)
    with pytest.raises(SystemExit, match="no frozen files"):
        issue.plan(idx, CAL, NOV18)


# --- the snapshot ----------------------------------------------------------------------

def _package(root):
    off = json.loads((REPO / "data" / "cds" / "offering.json").read_text())
    prof = json.loads((REPO / "data" / "system-profile.json").read_text())
    doc = cpo.build(off, prof, {"signal_id": "s", "components": []}, NOV18, "abc", None, CAL)
    (root / "certification-package-overview.json").write_text(json.dumps(doc))
    for n in issue.snapshot_files(root):
        if not (root / n).exists():
            (root / n).write_text(f"{n}\n")


def test_the_snapshot_is_the_package_the_cpo_lists_with_signatures_and_not_the_index(tmp_path):
    _package(tmp_path)
    names = issue.snapshot_files(tmp_path)
    for n in ("security-decision-record.json", "security-decision-record.bundle", "ksi-signal.json",
              "vdr-report.json", "ongoing-certification-report.json", "ongoing-certification-report.md",
              "availability.json", "policy-index.json", "certification-package-overview.json",
              "certification-package-overview.bundle"):
        assert n in names
    assert "ocr-issues.json" not in names


def test_freeze_copies_the_package_and_records_each_files_sha256(tmp_path):
    _package(tmp_path)
    idx = _empty()
    issue.plan(idx, CAL, NOV18)
    assert issue.freeze(idx, tmp_path, tmp_path / "ocr") == "2026-Q4"
    files = idx["issues"][0]["files"]
    assert set(files) == set(issue.snapshot_files(tmp_path))
    assert issue.check(idx, tmp_path / "ocr") == []
    assert issue.freeze(idx, tmp_path, tmp_path / "ocr") is None  # nothing pending: no second issue


def test_freeze_with_a_package_file_missing_fails_closed(tmp_path):
    _package(tmp_path)
    (tmp_path / "vdr-report.json").unlink()
    idx = _empty()
    issue.plan(idx, CAL, NOV18)
    with pytest.raises(SystemExit, match="vdr-report.json"):
        issue.freeze(idx, tmp_path, tmp_path / "ocr")


def test_freeze_never_writes_over_an_existing_snapshot(tmp_path):
    _package(tmp_path)
    (tmp_path / "ocr" / "2026-Q4").mkdir(parents=True)
    (tmp_path / "ocr" / "2026-Q4" / "x").write_text("earlier")
    idx = _empty()
    issue.plan(idx, CAL, NOV18)
    with pytest.raises(SystemExit, match="already holds files"):
        issue.freeze(idx, tmp_path, tmp_path / "ocr")


# --- verification ----------------------------------------------------------------------

def test_a_changed_or_missing_snapshot_file_fails_the_check(tmp_path):
    _package(tmp_path)
    idx = _empty()
    issue.plan(idx, CAL, NOV18)
    issue.freeze(idx, tmp_path, tmp_path / "ocr")
    (tmp_path / "ocr" / "2026-Q4" / "vdr-report.json").write_text("tampered")
    (tmp_path / "ocr" / "2026-Q4" / "policy-index.json").unlink()
    problems = issue.check(idx, tmp_path / "ocr")
    assert any("vdr-report.json differs" in p for p in problems)
    assert any("policy-index.json is not published" in p for p in problems)


@pytest.mark.parametrize("doc", [[], {"schema": "x", "issues": []}, {"schema": "ocr-issues/1"},
                                 {"schema": "ocr-issues/1", "issues": [{"id": "2026-Q4", "due": "soon"}]}])
def test_a_malformed_index_fails_closed(tmp_path, doc):
    p = tmp_path / "ocr-issues.json"
    p.write_text(json.dumps(doc))
    with pytest.raises(SystemExit, match="OCR calendar"):
        oc.load_issued(p)


# --- the deploy ------------------------------------------------------------------------

def test_the_deploy_verifies_the_published_index_before_it_builds_from_it():
    plan = WORKFLOW.index("- name: Plan the quarterly OCR issue")
    assert plan < WORKFLOW.index("- name: Build Ongoing Certification Report (CCM)")
    step = WORKFLOW[plan:WORKFLOW.index("- name: Build Ongoing Certification Report (CCM)")]
    assert "cosign verify-blob --bundle ocr-issues-published.bundle" in step
    assert "workflows/deploy-with-opa.yml@refs/heads/main" in step
    assert 'elif [ "$code" = 404 ]; then' in step  # only a missing index means none issued


def test_the_deploy_refuses_to_replace_an_issued_snapshot():
    publish = WORKFLOW[WORKFLOW.index("- name: Publish all signed artifacts to /.well-known/"):]
    assert "--prefix \".well-known/ocr/$id/\"" in publish
    assert 'if [ "$existing" != 0 ]; then' in publish and "exit 1" in publish


def test_the_freeze_runs_after_the_package_is_signed_and_before_the_gate():
    freeze = WORKFLOW.index("- name: Freeze the quarterly OCR issue and sign the index")
    assert WORKFLOW.index("- name: Sign CDS certification-data artifacts") < freeze
    assert WORKFLOW.index("- name: Sign Ongoing Certification Report") < freeze
    assert freeze < WORKFLOW.index("- name: Gates for the pre-publish stage")


def test_freeze_keeps_the_index_fields_plan_wrote(tmp_path):
    _package(tmp_path)
    idx_path = tmp_path / "ocr-issues.json"
    assert issue.main(["plan", "--index", str(idx_path)]) == 0
    assert issue.main(["freeze", "--index", str(idx_path), "--root", str(tmp_path),
                       "--out", str(tmp_path / "ocr")]) == 0
    idx = json.loads(idx_path.read_text())
    assert idx["fedramp_id"].endswith("NOT-A-REAL-FEDRAMP-ID") and idx["emitted_at"] and idx["calendar"]
    assert issue.main(["check", "--index", str(idx_path), "--root", str(tmp_path / "ocr")]) == 0
