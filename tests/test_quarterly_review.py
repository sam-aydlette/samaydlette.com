"""The Quarterly Review, held automatically with simulated attendees
(CCM-QTR-MTG, -ACT, -RTP, -RTR, -SRR, -NID; CCM-OCR-FBM, -AFS; DEC-194):
package-maintenance.yml holds each review on its date, the attendee policy is
enforced in code, the published transcript has every agency comment and name
removed, and the deploy (through the maintainer) and the nightly fail when a
review date has passed with no review."""
import hashlib
import importlib.util
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _ccm  # noqa: E402
import _engagement  # noqa: E402
import _quarterly_review as qr  # noqa: E402
import _sensitivity  # noqa: E402


def _load(name, script):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hold = _load("hold_quarterly_review", "hold-quarterly-review.py")
check = _load("check_quarterly_review", "check-quarterly-review.py")
ISSUE = date(2026, 11, 24)
REVIEW = date(2026, 12, 2)
HELD = datetime(2026, 12, 2, 18, tzinfo=timezone.utc)
OCR = {"reportPeriod": {"from": "2026-08-24", "to": "2026-11-24"}, "certificationDataChanges": [{"x": 1}],
       "transformativeChanges": [], "reportableIncidents": {"incidents": []},
       "acceptedVulnerabilities": "None accepted.", "plannedCertificationDataChanges": {"changes": []}}


def _cal(today=None):
    return _ccm.load(_ccm.CALENDAR_PATH, today or HELD.date())


def _review(now=HELD):
    return qr.build(_cal(now.date()), ISSUE, OCR, "a" * 64, now, "FR0000000000")


def test_the_review_is_simulated_says_so_and_invites_nobody():
    doc = _review()
    assert doc["simulated"] is True and doc["engagement"] == _engagement.STATEMENT
    assert doc["reviewDate"] == REVIEW.isoformat() and doc["late"] is False
    assert _engagement.require_none(doc, "t") is doc
    assert all(a["org"].endswith("(simulated)") for a in doc["roster"])


def test_the_published_transcript_removes_every_agency_comment_and_name():
    doc = _review()
    text = json.dumps(doc)
    for a in qr.ROSTER:
        if a["role"] == "agency":
            assert a["org"] not in text
    agency_lines = [x for x in doc["transcript"] if x["role"] == "agency"]
    assert agency_lines and all(x["line"] == qr.AGENCY_LINE_REMOVED for x in agency_lines)
    assert doc["transcriptSupplied"]["fullTranscriptSha256"] != hashlib.sha256(
        json.dumps(doc["transcript"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_the_review_passes_the_sensitivity_screen():
    doc = _review()
    assert _sensitivity.screen({k: v for k, v in doc.items() if k != "sensitivityScreen"}) == []


@pytest.mark.parametrize("attendee,reason", [
    ({"seat": "AO", "org": "Bureau of Unmarked Attendees", "role": "agency"}, r"is not marked \(simulated\)"),
    ({"seat": "Vendor", "org": "Snack Vendor (simulated)", "role": "other"}, "no specific relevance recorded"),
])
def test_known_bad_the_attendee_policy_is_enforced_in_code(attendee, reason):
    with pytest.raises(SystemExit, match=reason):
        qr.check_roster([attendee])
    assert qr.check_roster([dict(attendee, org="X (simulated)", role="other", relevance="Brings the snacks.")])


def test_a_submission_not_from_a_simulated_party_is_refused():
    with pytest.raises(SystemExit, match="no real feedback is solicited"):
        qr.intake([{"ocr": "2026-11-24", "from": "A real person", "question": "q", "_answer": "a"}], "2026-11-24")


def test_the_ocr_summary_and_the_review_carry_the_same_qa():
    doc = _review()
    qa = qr.qa_summary(ISSUE.isoformat(), _cal().issues.index(ISSUE))
    assert doc["feedback"]["items"] == qa["items"] and doc["feedback"]["received"] == qa["received"]


def test_a_review_cannot_be_held_before_its_date():
    with pytest.raises(SystemExit, match="not before its date"):
        _review(datetime(2026, 12, 1, 18, tzinfo=timezone.utc))


# --- holding and the overdue check ---------------------------------------------------

def _issued(tmp_path):
    rep = tmp_path / f"ocr-issue-{ISSUE}.json"
    rep.write_text(json.dumps(OCR))
    sha = hashlib.sha256(rep.read_bytes()).hexdigest()
    return {"issues": [{"issueDate": ISSUE.isoformat(), "reportSha256": sha}]}


def test_the_maintainer_holds_a_due_review_and_indexes_it(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    index, new = hold.run(_cal(), _issued(tmp_path), [str(tmp_path)], {}, out, HELD, "FR0000000000")
    assert new == [f"quarterly-review-{ISSUE}.json", f"quarterly-review-{ISSUE}.md"]
    assert [r["ocrIssue"] for r in index["reviews"]] == [ISSUE.isoformat()]
    assert qr.missing(_cal(), index, date(2026, 12, 3)) == []
    again, new2 = hold.run(_cal(), _issued(tmp_path), [str(tmp_path)], index, out, HELD, "FR0000000000")
    assert new2 == [] and again["reviews"] == index["reviews"]


def test_known_bad_a_report_that_does_not_match_its_recorded_sha256_is_not_reviewed(tmp_path):
    issued = _issued(tmp_path)
    issued["issues"][0]["reportSha256"] = "0" * 64
    with pytest.raises(SystemExit, match="does not match the sha256"):
        hold.run(_cal(), issued, [str(tmp_path)], {}, tmp_path, HELD, "FR0000000000")


def test_known_bad_a_passed_review_date_with_no_review_fails_the_check(capsys):
    assert check.main(["--no-index", "--today", "2026-12-03"]) == 1
    assert "was due 2026-12-02 and is not published" in capsys.readouterr().out
    assert check.main(["--no-index", "--today", "2026-12-02"]) == 0   # on the day, it may still be held


def test_the_maintainer_and_the_nightly_fail_on_an_overdue_review():
    wf = REPO / ".github" / "workflows"
    maint = (wf / "package-maintenance.yml").read_text()
    assert "- name: Hold the Quarterly Review when due (simulated attendees)" in maint
    assert "check-quarterly-review.py --index infrastructure/out/quarterly-reviews.json" in maint
    nightly = (wf / "evidence-nightly.yml").read_text()
    assert "check-quarterly-review.py --index qr-index.json" in nightly and "--no-index" in nightly
    deploy = (wf / "deploy-with-opa.yml").read_text()
    assert "uses: ./.github/workflows/package-maintenance.yml" in deploy


def test_no_intake_form_exists():
    assert not list((REPO / ".github").glob("ISSUE_TEMPLATE/*.yml"))


def test_known_bad_a_malformed_previous_index_fails(tmp_path):
    bad = {"reviews": [{"ocrIssue": "../../etc", "reviewSha256": "x"}]}
    with pytest.raises(SystemExit, match="malformed entry"):
        hold.run(_cal(), _issued(tmp_path), [str(tmp_path)], bad, tmp_path, HELD, "FR0000000000")
