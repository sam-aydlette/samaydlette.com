"""The certification package and its quarterly cycle: the CPO in FedRAMP's
schema, the CCM calendar, the Ongoing Certification Report (rolling and
issued), snapshots, FedRAMP Certification Reports, the simulated package
submission, the FedRAMP ID gate and the unattended package maintainer.

Each gate here has a committed known-bad fixture under tests/fixtures/cycle/bad/
that fails for the reason the test names."""

import argparse
import copy
import fnmatch
import hashlib
import importlib.util
import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _assessor  # noqa: E402
import _ccm  # noqa: E402
import _decisions  # noqa: E402
import _engagement  # noqa: E402
import _fedramp_schema as fs  # noqa: E402
import _offering  # noqa: E402
import _quarterly_review  # noqa: E402
import _sensitivity  # noqa: E402

FIX = REPO / "tests" / "fixtures" / "cycle"
BAD = FIX / "bad"
NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
ISSUE_DAY = datetime(2026, 11, 24, 12, tzinfo=timezone.utc)
SIGNAL = json.loads((REPO / "tests" / "fixtures" / "clean" / "ksi-signal.json").read_text())
PROFILE = json.loads((REPO / "data" / "system-profile.json").read_text())
# The simulated assessor's signed set (signature check stubbed; tested in test_simulated_assessor.py).
def _assessment():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        s = Path(d) / "simulated-assessment.json"
        s.write_text((REPO / "tests" / "fixtures" / "assessor" / "simulated-set.json").read_text())
        return _assessor.load_assessment(s, s, verifier=lambda *_a: True, expect_commit="0" * 40,
                                         expect_signal_id="00000000-0000-4000-8000-000000000001")


ASSESSMENT = _assessment()


def _load(name, script):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cpo = _load("build_cpo", "build-cpo.py")
ocr = _load("build_ocr", "build-ocr.py")
issue_ocr = _load("issue_ocr", "issue-ocr.py")
frc = _load("publish_frc", "publish-certification-reports.py")
submit = _load("submit_package", "submit-package.py")
fid_gate = _load("check_fedramp_id", "check-fedramp-id.py")
maint = _load("check_package_maintainer", "check-package-maintainer.py")


def _json(p):
    return json.loads(Path(p).read_text())


def _cal(today=None, path=_ccm.CALENDAR_PATH):
    return _ccm.load(path, today or NOW.date())


def _off(path=_offering.OFFERING_PATH):
    return _offering.load(path)


def _cpo(off=None, prev=None, now=NOW):
    return cpo.build(off or _off(), PROFILE, SIGNAL, _cal(now.date()), prev or {}, now, cpo.boundary_groups(),
                     ASSESSMENT)


def _ocr(now=NOW, issue=None, incidents=None, scn_rows=(), prev=None, decisions=None):
    return ocr.build(_cal(now.date()), now.date(), None, decisions or _decisions.load(), list(scn_rows), incidents,
                     SIGNAL, PROFILE, _off(), prev or {}, now, issue)


# --- the CCM calendar (CCM-OCR-SOR, CCM-QTR-SAR, CCM-OCR-NRD, CCM-QTR-NRD) -----------

def test_the_committed_calendar_is_valid():
    cal = _cal()
    assert len(cal.issues) >= 4


def test_the_review_is_five_business_days_after_issue_skipping_thanksgiving():
    cal = _cal()
    # 2026-11-24 (Tue) + 5 business days, Thanksgiving (Thu 26th) excluded.
    assert cal.review_date(date(2026, 11, 24)) == date(2026, 12, 2)
    for d in cal.issues:
        r = cal.review_date(d)
        days = [x for x in (date.fromordinal(o) for o in range(d.toordinal() + 1, r.toordinal() + 1))
                if cal.is_business_day(x)]
        assert len(days) == cal.offset and 3 <= cal.offset <= 10


@pytest.mark.parametrize("fixture,today,reason", [
    ("calendar-mid-quarter.json", None, "beginning, middle or end of its quarter"),
    ("calendar-irregular-gap.json", None, "not a regular 3-month cycle"),
    ("calendar-review-too-soon.json", None, "must be 3 to 10"),
    ("calendar-runs-out.json", date(2026, 12, 1), "fewer than 2 issue dates"),
    ("calendar-issue-on-holiday.json", None, "is not a business day"),
])
def test_a_bad_calendar_fails_closed(fixture, today, reason):
    with pytest.raises(SystemExit, match=reason):
        _ccm.load(BAD / fixture, today or NOW.date())


def test_next_dates_hold_steady_between_issues_and_move_on_the_issue_date():
    cal = _cal()
    before = [_ccm.dates_summary(cal, date(2026, 11, d)) for d in (5, 12, 23)]
    assert all(b == before[0] for b in before)
    assert before[0]["nextOngoingCertificationReportDate"] == "2026-11-24"
    assert before[0]["nextQuarterlyReviewDate"] == "2026-12-02"
    on = _ccm.dates_summary(cal, date(2026, 11, 24))
    assert on["nextOngoingCertificationReportDate"] == "2027-02-23"
    assert on["nextQuarterlyReviewDate"] == "2026-12-02"  # the review of the report just issued


def test_the_review_calendar_file_is_rfc5545():
    text = _ccm.ics(_cal(), NOW.date())
    assert text.startswith("BEGIN:VCALENDAR\r\n") and text.endswith("END:VCALENDAR\r\n")
    assert "\n" not in text.replace("\r\n", "")
    assert all(len(line.encode()) <= 75 for line in text.split("\r\n"))
    assert text.count("BEGIN:VEVENT") == len(_cal().issues)
    assert "DTSTART:20261202T170000Z" in text
    unfolded = text.replace("\r\n ", "")
    assert f"URL:{_ccm.review_url(_cal().issues[0])}" in unfolded
    # no engagement (DEC-194): the event is simulated and invites nobody
    assert "LOCATION:Simulated (package-maintenance.yml)" in unfolded and "Simulated (DEC-194)" in unfolded
    assert _engagement.invitations(unfolded) == []
    assert _ccm.ics(_cal(), NOW.date()) == text  # deterministic


# --- the CPO (CPO-CSO-OVR, CPO-CSO-MTD, CDS-CSO-SVC, CDS-CSO-FID, FRC-CSO-POP) -------

@pytest.fixture(scope="module")
def built_cpo():
    return _cpo()


def test_the_cpo_validates_against_fedramps_schema(built_cpo):
    assert fs.validate(built_cpo, "cpo") == []


def test_the_cpo_seeks_20x_only(built_cpo):
    assert built_cpo["serviceIdentification"]["certificationType"] == "20x"
    assert "Rev5" not in built_cpo["providerExtensions"]["certification"]["program"].replace(" ", "")
    assert "Rev 5" not in built_cpo["providerExtensions"]["certification"]["program"]


def test_the_cpo_json_says_the_system_is_not_certified(built_cpo):
    assert built_cpo["providerExtensions"]["certification"]["status"] == "not certified (proof of concept)"
    assert "not certified (proof of concept)" in cpo.render_markdown(built_cpo)


def test_no_cpo_or_ocr_label_names_rev5_as_a_program(built_cpo, rolling):
    """FRC-CSO-POP (DEC-107). The only Rev5 the package names is the Moderate
    control baseline the SDR maps 20x evidence onto, never a certification."""
    for text in (json.dumps(built_cpo), cpo.render_markdown(built_cpo), json.dumps(rolling), ocr.render_markdown(rolling)):
        assert re.findall(r"Rev ?5(?! Moderate control)", text) == []


def test_the_fedramp_id_and_uei_are_the_offerings_and_flagged_simulated(built_cpo):
    off = _off()
    si = built_cpo["serviceIdentification"]
    assert si["fedRampPackageId"] == off["fedramp_id"] == built_cpo["providerExtensions"]["fedRampId"]
    assert off["provider_name"] in si["fedRampPackageId"] and off["service_acronym"] in si["fedRampPackageId"]
    assert "NOT-A-REAL" in si["fedRampPackageId"] and "NOT-A-REAL" in si["ueiNumber"]
    sim = {s["field"]: s["counterparty"] for s in built_cpo["providerExtensions"]["simulated"]}
    assert sim == {"serviceIdentification.fedRampPackageId": "fedramp", "serviceIdentification.ueiNumber": "sam-gov",
                   "providerExtensions.independentAssessment.overallSummary": "assessor"}


@pytest.mark.parametrize("fixture,reason", [
    ("offering-placeholder-id-unflagged.json", "fedramp_id_simulated"),
    ("offering-id-without-provider-name.json", "provider name and acronym"),
])
def test_a_bad_fedramp_id_in_the_offering_fails(fixture, reason):
    with pytest.raises(SystemExit, match=reason):
        _offering.load(BAD / fixture)


def test_each_service_has_its_own_category_and_the_list_says_what_is_not_included(built_cpo):
    services = built_cpo["providerExtensions"]["services"]
    assert len(services) == len(built_cpo["certifiedServices"]) >= 2
    cats = {json.dumps(s["securityCategory"], sort_keys=True) for s in services}
    assert len(cats) == len(services)  # not one uniform label
    assert all(s["boundaryGroups"] for s in services)
    assert built_cpo["providerExtensions"]["notIncluded"]


@pytest.mark.parametrize("fixture,reason", [
    ("offering-service-above-system.json", "exceeds the system's"),
    ("offering-unknown-boundary-group.json", "not in the boundary classification"),
])
def test_a_bad_service_list_fails(fixture, reason):
    with pytest.raises(SystemExit, match=reason):
        _cpo(off=_off(BAD / fixture))


def test_no_contact_email_field_holds_anything_but_an_address(built_cpo):
    fsi = _cpo(off=_off(FIX / "offering-fsi-url.json"))
    for doc in (built_cpo, fsi):
        for c in doc["contactInformation"]:
            if "contactEmail" in c:
                assert re.fullmatch(r"[^@\s/]+@[^@\s/]+\.[a-z]+", c["contactEmail"])
    entry = next(c for c in fsi["contactInformation"] if c["contactType"] == "FedRAMP Security Inbox")
    assert "contactEmail" not in entry
    good = _off(FIX / "offering-fsi-url.json")
    good["fedramp_security_inbox"]["address"] = "security@samaydlette.com"
    entry = next(c for c in _cpo(off=good)["contactInformation"] if c["contactType"] == "FedRAMP Security Inbox")
    assert entry["contactEmail"] == "security@samaydlette.com"


def test_the_cpo_version_is_semver_and_bumps_only_on_change(built_cpo):
    md = built_cpo["metadata"]
    assert md["version"] == "1.0.0" and md["lastUpdated"] == NOW.isoformat() and md["updateSource"]
    later = datetime(2026, 11, 6, 12, tzinfo=timezone.utc)
    assert _cpo(prev=built_cpo, now=later)["metadata"]["version"] == "1.0.0"
    prev = copy.deepcopy(built_cpo)
    prev["metadata"]["version"] = "1.0.4"
    prev["providerExtensions"]["contentSha256"] = "0" * 64
    assert _cpo(prev=prev)["metadata"]["version"] == "1.0.5"


def test_the_cpo_publishes_the_fixed_cycle_dates(built_cpo):
    cal = _cal()
    assert built_cpo["serviceProperties"]["nextOngoingCertificationReportDate"] == cal.next_issue(NOW.date()).isoformat()
    cm = built_cpo["providerExtensions"]["continuousMonitoring"]
    assert cm["quarterlyReviewCalendar"] == _ccm.ICS_URL and cm["quarterlyReviews"] == _ccm.REVIEWS_INDEX_URL
    assert "quarterlyReviewRegistration" not in cm


# --- the OCR (CCM-OCR-*, CCM-QTR-*) ---------------------------------------------------

@pytest.fixture(scope="module")
def rolling():
    return _ocr()


def test_the_rolling_ocr_validates_and_carries_the_cycle(rolling):
    assert fs.validate(rolling, "ocr") == []
    pe = rolling["providerExtensions"]
    assert pe["report"]["kind"] == "rolling"
    assert pe["fedRampId"] == _offering.fedramp_id()
    assert pe["continuousMonitoring"]["nextOngoingCertificationReportDate"] == "2026-11-24"
    assert pe["quarterlyReview"]["date"] == "2026-12-02"
    assert pe["quarterlyReview"]["agenda"] == ocr.STANDING_AGENDA and len(ocr.STANDING_AGENDA) >= 3
    assert pe["publicRelease"]["decision"] == ocr.PUBLIC_RELEASE_DECISION
    assert pe["feedback"]["channel"] == _quarterly_review.INTAKE
    assert pe["engagement"] == _engagement.STATEMENT
    assert pe["sensitivityScreen"] == {"checks": list(_sensitivity.CHECKS), "findings": 0}


def test_the_decisions_the_ocr_cites_are_in_force():
    ids = {d["id"] for d in _decisions.in_force(_decisions.load())}
    assert {ocr.PUBLIC_RELEASE_DECISION, ocr.ENGAGEMENT_DECISION} <= ids


def test_an_issued_ocr_covers_the_quarter_and_is_marked_frozen():
    doc = _ocr(now=ISSUE_DAY, issue=date(2026, 11, 24))
    assert fs.validate(doc, "ocr") == []
    assert doc["reportPeriod"] == {"from": "2026-08-25", "to": "2026-11-24"}
    assert doc["providerExtensions"]["report"]["kind"] == "issued"
    assert doc["providerExtensions"]["report"]["late"] is False


def test_an_issue_cannot_be_built_before_its_date_or_off_the_calendar():
    with pytest.raises(SystemExit, match="in the future"):
        _ocr(issue=date(2026, 11, 24))
    with pytest.raises(SystemExit, match="not a calendar issue date"):
        _ocr(now=ISSUE_DAY, issue=date(2026, 11, 23))


@pytest.mark.parametrize("check", sorted(_json(BAD / "sensitive-values.json")))
def test_the_sensitivity_screen_catches_each_kind(check):
    doc = _json(BAD / "sensitive-values.json")[check]
    assert {c for _, c in _sensitivity.screen(doc)} == {check}
    with pytest.raises(SystemExit, match="must not be published"):
        _sensitivity.require_clean(doc, "the fixture")


def test_the_sensitivity_screen_catches_a_token_and_allows_the_systems_own_domain():
    token = "ghp_" + "A1b2C3d4" * 5
    assert _sensitivity.screen({"x": f"used {token}"}) == [("/x", "token")]
    assert _sensitivity.screen({"x": "write to security@samaydlette.com"}) == []


def test_an_ocr_carrying_a_personal_address_is_never_built():
    row = {"scn_id": "SCN-T-1", "scn_type": "adaptive", "date_finished": "2026-11-01",
           "short_description": "Asked by jane.doe@example.org"}
    with pytest.raises(SystemExit, match="sensitivity screen"):
        _ocr(scn_rows=[row])


def test_reportable_incidents_come_from_the_register_and_exercises_say_so():
    reg = {"incidents": [
        {"id": "INC-1", "title": "Exercise: tabletop", "exercise": True, "started_at": "2026-10-01T00:00:00Z",
         "resolved_at": "2026-10-01T02:00:00Z", "evaluation": {"reportable": True}, "lessons_learned": ["Drill it"]},
        {"id": "INC-2", "title": "Not reportable", "started_at": "2026-10-02T00:00:00Z",
         "evaluation": {"reportable": False}}]}
    got = _ocr(incidents=reg)["reportableIncidents"]["incidents"]
    assert [i["summary"] for i in got] == ["INC-1: Exercise, not a real incident: tabletop"]
    assert got[0]["incidentLessonsLearned"] == ["Drill it"]


def test_the_feedback_summary_covers_the_previous_issue():
    """Once the previous issue's review date has passed, the OCR carries the
    review's anonymized Q&A, built by the same function as the review."""
    before = datetime(2026, 12, 1, 12, tzinfo=timezone.utc)   # the review is 2026-12-02
    s0 = _ocr(now=before)["providerExtensions"]["feedback"]["summaryOfPreviousReport"]
    assert "once it is held" in s0["statement"] and "items" not in s0
    later = datetime(2026, 12, 10, 12, tzinfo=timezone.utc)
    s = _ocr(now=later)["providerExtensions"]["feedback"]["summaryOfPreviousReport"]
    qa = _quarterly_review.qa_summary("2026-11-24", 0)
    assert s["ocr"] == "2026-11-24" and s["received"] == qa["received"] and s["items"] == qa["items"]
    assert "simulated" in s["statement"]


def test_a_feedback_summary_never_carries_a_name_or_an_agency():
    for n in range(8):
        qa = _quarterly_review.qa_summary(f"2027-0{1 + n % 8}-01", n)
        text = json.dumps(qa)
        assert _sensitivity.screen(qa) == []
        assert "Department of" not in text and "Bureau of" not in text


# --- issuing and snapshots (CCM-OCR-AVL, CDS-CSO-HAD) ---------------------------------

def _issue_args(tmp_path, work, prev=None):
    sig = tmp_path / "ksi-signal.json"
    sig.write_text(json.dumps(SIGNAL))
    return argparse.Namespace(
        work=str(work), out=str(tmp_path / "out"), previous_index=str(prev) if prev else None,
        new_files=str(tmp_path / "issued.txt"), calendar=str(_ccm.CALENDAR_PATH),
        offering=str(_offering.OFFERING_PATH), profile=str(REPO / "data" / "system-profile.json"),
        vdr=str(tmp_path / "none.json"), decisions=str(REPO / "data" / "decisions.json"),
        scn_register=str(tmp_path / "none.csv"), ksi_signal=str(sig), incidents=str(tmp_path / "none.json"))


def _work(tmp_path, names=issue_ocr.REQUIRED):
    w = tmp_path / "work"
    w.mkdir(exist_ok=True)
    for n in names:
        (w / n).write_text(json.dumps({"file": n}))
    return w


def test_the_first_run_on_an_issue_date_freezes_the_report_and_snapshots_the_package(tmp_path):
    index, new = issue_ocr.run(_issue_args(tmp_path, _work(tmp_path)), ISSUE_DAY)
    out = tmp_path / "out"
    assert [i["issueDate"] for i in index["issues"]] == ["2026-11-24"]
    assert {"ocr-issue-2026-11-24.json", "ocr-issue-2026-11-24.md", "snapshot-2026-11-24.json"} <= set(new)
    assert fs.validate(_json(out / "ocr-issue-2026-11-24.json"), "ocr") == []
    manifest = _json(out / "snapshot-2026-11-24.json")
    assert sorted(f["name"] for f in manifest["files"]) == sorted(issue_ocr.REQUIRED)
    assert index["issues"][0]["quarterlyReviewDate"] == "2026-12-02"
    assert index["fedRampId"] == _offering.fedramp_id()
    # Every new file is one the maintenance role may write.
    keys = _bootstrap_keys()
    assert all(any(fnmatch.fnmatch(".well-known/" + f, k) for k in keys) for f in new)


def test_an_issued_report_is_carried_over_and_never_rebuilt(tmp_path):
    index, _ = issue_ocr.run(_issue_args(tmp_path, _work(tmp_path)), ISSUE_DAY)
    prev = tmp_path / "prev.json"
    prev.write_text(json.dumps(index))
    again, new = issue_ocr.run(_issue_args(tmp_path, _work(tmp_path), prev), datetime(2026, 11, 25, tzinfo=timezone.utc))
    assert new == [] and again["issues"] == index["issues"]


def test_no_issue_without_the_certification_data_to_snapshot(tmp_path):
    with pytest.raises(SystemExit, match="ksi-signal.json missing"):
        issue_ocr.run(_issue_args(tmp_path, _work(tmp_path, issue_ocr.REQUIRED[:-1])), ISSUE_DAY)


@pytest.mark.parametrize("fixture,reason", [
    ("ocr-issues-not-a-calendar-date.json", "not a calendar issue date"),
    ("ocr-issues-out-of-order.json", "out of order"),
])
def test_a_tampered_issue_index_fails(fixture, reason):
    with pytest.raises(SystemExit, match=reason):
        issue_ocr.check_index(_json(BAD / fixture), _cal())


# --- FedRAMP Certification Reports (CDS-CSO-FRC, simulated FedRAMP) -------------------

SCN_ROWS = [{"scn_id": "SCN-2026-001", "scn_type": "adaptive"}, {"scn_id": "SCN-2026-002", "scn_type": "adaptive"}]


def _submit(previous, when, scn_rows=SCN_ROWS, content=None):
    docs, paths = _pkg()
    if content:
        docs["ocr"]["providerExtensions"]["contentSha256"] = content
    return submit.build(docs, paths, previous, when, "abc", PKG_RULES, PKG_ID, scn_rows)


def _reports(log):
    return [e["certificationReport"] for e in log["entries"] if e.get("certificationReport")]


def test_the_first_submission_gets_a_simulated_report_and_ordinary_deploys_do_not():
    log = _submit({}, NOW)
    (r,) = _reports(log)
    assert r["receivedOn"] == "2026-11-05" and r["trigger"].startswith("initial")
    assert r["scnsCovered"] == ["SCN-2026-001", "SCN-2026-002"]
    # An ordinary deploy, even one whose package changed, re-issues nothing.
    later = _submit(log, datetime(2027, 2, 1, tzinfo=timezone.utc), content="e" * 64)
    assert len(later["entries"]) == 2 and len(_reports(later)) == 1


def test_an_adaptive_or_transformative_scn_brings_a_new_report():
    log = _submit({}, NOW)
    rows = SCN_ROWS + [{"scn_id": "SCN-2026-009", "scn_type": "transformative"},
                       {"scn_id": "SCN-2026-010", "scn_type": "routine-recurring"}]
    later = _submit(log, datetime(2026, 12, 1, tzinfo=timezone.utc), rows)
    assert len(_reports(later)) == 2 and "SCN-2026-009" in _reports(later)[-1]["trigger"]
    assert "SCN-2026-010" not in _reports(later)[-1]["trigger"]
    again = _submit(later, datetime(2026, 12, 2, tzinfo=timezone.utc), rows)
    assert len(_reports(again)) == 2  # that SCN is covered now


def test_a_report_is_issued_annually_even_when_the_package_is_unchanged():
    log = _submit({}, NOW)
    assert len(_reports(_submit(log, datetime(2027, 11, 4, tzinfo=timezone.utc)))) == 1
    annual = _submit(log, datetime(2027, 11, 5, tzinfo=timezone.utc))
    assert len(_reports(annual)) == 2 and _reports(annual)[-1]["trigger"].startswith("annual")


def test_the_report_says_first_that_it_is_simulated_not_issued_by_fedramp_and_not_certified():
    (r,) = _reports(_submit({}, NOW))
    first = submit.report_bytes(r["report"]).decode().splitlines()[1]
    assert first.startswith('  "title": "SIMULATED REPORT, NOT ISSUED BY FEDRAMP')
    assert "NOT FedRAMP certified" in first
    assert r["report"]["certificationStatus"] == "not certified (proof of concept)"
    assert r["report"]["simulated"] is True and r["report"]["notIssuedByFedRAMP"] is True


def test_logged_reports_are_published_byte_identical_and_their_first_date_kept(tmp_path):
    log = _submit({}, NOW)
    idx = frc.build(log, {}, NOW, tmp_path)
    (e,) = idx["reports"]
    raw = (tmp_path / "fedramp-certification-reports" / e["file"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == e["sha256"] == _reports(log)[0]["sha256"]
    assert e["daysToPublish"] == 0 and e["withinTwoWeeks"] and idx["certificationStatus"].startswith("not certified")
    again = frc.build(log, idx, datetime(2026, 12, 31, tzinfo=timezone.utc), tmp_path)
    assert again["reports"][0]["firstPublished"] == "2026-11-05"


def test_known_bad_a_report_published_more_than_two_weeks_after_receipt_fails_the_deploy(tmp_path, monkeypatch):
    class Late(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW
    monkeypatch.setattr(frc, "datetime", Late)
    with pytest.raises(SystemExit, match="past the 14-day window"):
        frc.main(["--submission-log", str(BAD / "submission-log-late-report.json"), "--out", str(tmp_path)])
    assert not (tmp_path / "fedramp-certification-reports.json").exists()


@pytest.mark.parametrize("fixture,reason", [
    ("submission-log-report-modified.json", "differs from the sha256 logged"),
    ("submission-log-report-not-labelled.json", "NOT ISSUED BY FEDRAMP"),
])
def test_known_bad_a_modified_or_unlabelled_report_is_never_published(tmp_path, fixture, reason):
    with pytest.raises(SystemExit, match=reason):
        frc.build(_json(BAD / fixture), {}, NOW, tmp_path)


@pytest.mark.parametrize("over,needle", [({"cpo": "cpo-without-not-certified-status.json"}, "the CPO does not state"),
                                         ({"sdr": "sdr-without-not-certified-status.json"}, "the SDR does not state")])
def test_known_bad_a_cpo_or_sdr_without_the_not_certified_status_is_never_submitted(over, needle):
    docs, paths = _pkg(**over)
    with pytest.raises(SystemExit, match=needle):
        submit.build(docs, paths, {}, NOW, "abc", PKG_RULES, PKG_ID)


# --- the simulated package submission (FRC-CSO-PKG, FRC-CSO-POP) ----------------------

PKG_ID = "Example Provider (EXD)"
PKG_RULES = ["VDR-CSO-DET"]


def _pkg(**over):
    paths = {k: FIX / "package" / f"{k}.json" for k in ("cpo", "sdr", "ocr")}
    paths.update({k: BAD / v for k, v in over.items()})
    return {k: _json(p) for k, p in paths.items()}, paths


def test_a_complete_package_is_logged_once_per_content_change():
    docs, paths = _pkg()
    log = submit.build(docs, paths, {}, NOW, "abc", PKG_RULES, PKG_ID)
    assert log["nothingSent"] is True and log["simulated"]["counterparty"] == "fedramp"
    assert len(log["entries"]) == 1 and log["entries"][0]["receipt"]["receiptId"].startswith("SIM-")
    assert len(submit.build(docs, paths, log, NOW, "abc", PKG_RULES, PKG_ID)["entries"]) == 1
    docs["ocr"]["providerExtensions"]["contentSha256"] = "f" * 64
    assert len(submit.build(docs, paths, log, NOW, "abd", PKG_RULES, PKG_ID)["entries"]) == 2


@pytest.mark.parametrize("over,rules,reason", [
    ({"cpo": "../../cr26/bad/cpo-no-sales-contact.json"}, PKG_RULES, "does not validate against FedRAMP's schema"),
    ({"cpo": "cpo-rev5-program.json"}, PKG_RULES, "FRC-CSO-POP"),
    ({"cpo": "cpo-without-assessment-summary.json"}, PKG_RULES, "CPO-CSO-OVR"),
    ({"sdr": "sdr-repeats-a-rule.json"}, PKG_RULES, "every applicable FedRAMP rule exactly once"),
    ({}, PKG_RULES + ["CCM-OCR-AVL"], "every applicable FedRAMP rule exactly once"),
    ({"ocr": "ocr-other-fedramp-id.json"}, PKG_RULES, "CDS-CSO-FID"),
])
def test_an_incomplete_or_inconsistent_package_is_not_submitted(over, rules, reason):
    docs, paths = _pkg(**over)
    with pytest.raises(SystemExit, match=reason):
        submit.build(docs, paths, {}, NOW, "abc", rules, PKG_ID)


def test_a_malformed_previous_log_is_not_overwritten():
    docs, paths = _pkg()
    with pytest.raises(SystemExit, match="malformed entry"):
        submit.build(docs, paths, _json(BAD / "submission-log-malformed.json"), NOW, "abc", PKG_RULES, PKG_ID)


# --- the FedRAMP ID gate (CDS-CSO-FID) -------------------------------------------------

def test_the_gate_covers_the_three_reports_by_default():
    assert fid_gate.REPORTS[:3] == ("certification-package-overview.json", "security-decision-record.json",
                                    "ongoing-certification-report.json")
    step = _step("deploy-with-opa.yml", "FedRAMP ID in every FedRAMP report (CDS-CSO-FID)")
    assert "check-fedramp-id.py" in step


@pytest.mark.parametrize("fixture,ok", [
    (FIX / "package" / "cpo.json", True), (FIX / "package" / "ocr.json", True),
    (BAD / "ocr-other-fedramp-id.json", False), (BAD / "cpo-other-package-id.json", False),
])
def test_the_gate_fails_a_report_with_another_fedramp_id(monkeypatch, fixture, ok):
    monkeypatch.setattr(fid_gate._offering, "fedramp_id", lambda *a: PKG_ID)
    assert fid_gate.main([str(fixture)]) == (0 if ok else 1)


def test_the_gate_fails_an_unreadable_report(tmp_path):
    assert fid_gate.main([str(tmp_path / "missing.json")]) == 1


# --- the unattended maintainer (CPO-CSX-CPM, SDR-CSX-KMT) -----------------------------

WORKFLOWS = REPO / ".github" / "workflows"


def _step(workflow, name):
    text = (WORKFLOWS / workflow).read_text()
    start = text.index(f"- name: {name}")
    end = text.find("\n    - name:", start + 1)
    return text[start:end if end > 0 else None]


def _bootstrap_keys():
    tf = (REPO / "infrastructure" / "bootstrap" / "package-maintenance.tf").read_text()
    block = re.search(r"package_maintenance_keys = \[(.*?)\]", tf, re.S).group(1)
    return re.findall(r'"([^"]+)"', block)


def _maintenance_publishes():
    step = _step("package-maintenance.yml", "Publish the certification package to /.well-known/")
    names = set(re.findall(r"^\s*put ([\w.-]+)\s", step, re.M))
    for var, items, body in re.findall(r"for (\w+) in ([^;\n]+); do(.*?)\n\s*done", step, re.S):
        for suffix in re.findall(r"put \"\$" + var + r"(\.[\w.]+)\"", body):
            names |= {i + suffix for i in items.split()}
    return {".well-known/" + n for n in names}


def test_the_maintenance_role_may_write_exactly_what_the_workflow_publishes():
    keys = _bootstrap_keys()
    literal = {k for k in keys if "*" not in k}
    assert literal == _maintenance_publishes()
    assert {k for k in keys if "*" in k} == {".well-known/ocr-issue-*", ".well-known/snapshot-*",
                                              ".well-known/snapshots/*", ".well-known/quarterly-review-*"}


def test_the_maintainer_runs_daily_and_the_package_windows_are_two_weeks_at_most():
    wf = (WORKFLOWS / "package-maintenance.yml").read_text()
    assert re.search(r"cron: '\d+ \d+ \* \* \*'", wf)
    assert "environment: package-maintenance" in wf and "workflow_call:" in wf
    cfg = {a["path"]: a for a in _json(REPO / "infrastructure" / "schemas" / "freshness-config.json")["artifacts"]}
    for p in ("security-decision-record.json", "certification-package-overview.json",
              "ongoing-certification-report.json"):
        assert cfg[".well-known/" + p]["max_age_hours"] <= 14 * 24


def test_the_deploy_checks_the_maintainer_before_building_and_proves_it_after():
    wf = (WORKFLOWS / "deploy-with-opa.yml").read_text()
    assert wf.index("- name: Package maintainer preflight") < wf.index("- name: Build Security Decision Record")
    assert "uses: ./.github/workflows/package-maintenance.yml" in wf


def test_the_maintainer_preflight_passes_when_in_place():
    assert maint.main(["--fixture", str(FIX / "maintainer-good.json")]) == 0


@pytest.mark.parametrize("fixture,reason", [
    ("maintainer-no-variable.json", "is not set"),
    ("maintainer-wrong-role.json", "names a role other than"),
    ("maintainer-any-branch.json", "not only main"),
    ("maintainer-no-environment.json", "does not exist"),
])
def test_the_maintainer_preflight_fails_when_not_in_place(fixture, reason, capsys):
    assert maint.main(["--fixture", str(BAD / fixture)]) == 1
    assert reason in capsys.readouterr().out


# --- every link the package gives resolves to something this repo publishes (FRC-CSO-MRA)

def _resolves(url):
    site = "https://samaydlette.com"
    if re.fullmatch(re.escape(site) + r"/\.well-known/quarterly-review-\d{4}-\d{2}-\d{2}\.(json|md)", url):
        return ".well-known/quarterly-review-*" in _bootstrap_keys()   # published by the maintainer once held
    if url.startswith(site + "/.well-known/"):
        name = url[len(site + "/.well-known/"):]
        governed = {a["path"] for a in _json(REPO / "infrastructure" / "schemas" / "freshness-config.json")["artifacts"]}
        twin = name[:-3] + ".json" if name.endswith(".md") else name  # a governed artifact's Markdown twin
        return (f".well-known/{name}" in governed or f".well-known/{twin}" in governed
                or (REPO / "website" / ".well-known" / name).is_file())
    if url in (site, site + "/"):
        return (REPO / "website" / "index.html").is_file()
    if url.startswith(site + "/"):
        return (REPO / "website" / url[len(site) + 1:].split("#")[0]).is_file()
    if url.startswith(_ccm.REPO_URL + "/blob/main/"):
        return (REPO / url[len(_ccm.REPO_URL + "/blob/main/"):].split("#")[0]).is_file()
    if url.startswith("https://fedramp.gov/schemas/"):
        return any((REPO / "infrastructure" / "schemas").glob("fedramp-*/" + url.rsplit("/", 1)[1]))
    return False


# The one deliberate outside link: the operator's LinkedIn profile, in the
# simulated FedRAMP Security Inbox's contact line (AFC-CSO-INB) and the
# no-engagement statement (DEC-194).
DELIBERATE_EXTERNAL = {"https://www.linkedin.com/in/sa2/"}


def test_every_link_in_the_cpo_and_ocr_resolves(built_cpo, rolling):
    # Third-party resources' own websites (MAS-CSO-TPR) are outside this site by design.
    cpo_own = {k: v for k, v in built_cpo.items() if k != "thirdPartyInformationResources"}
    for doc in (cpo_own, rolling):
        urls = set(re.findall(r"https://[^\s\"')<>]+", json.dumps(doc)))
        assert urls
        bad = sorted(u.rstrip(".,") for u in urls
                     if u.rstrip(".,") not in DELIBERATE_EXTERNAL and not _resolves(u.rstrip(".,")))
        assert not bad, bad


def test_a_link_to_nothing_is_caught():
    assert not _resolves("https://samaydlette.com/.well-known/not-published.json")
    assert not _resolves(_ccm.REPO_URL + "/blob/main/docs/no-such-file.md")
