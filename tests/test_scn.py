"""Significant Change Notifications (SCN-*): the evaluation gate, the register,
the notice deadlines in business days, the append-only evaluation log, the
never-pruned notification index and feed, and the scheduled deadline check.

Every gate invariant has a committed known-bad fixture under
tests/fixtures/scn/bad/ that fails for its own reason."""

import importlib.util
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "scn"
sys.path.insert(0, str(REPO / "scripts"))
import _bizdays  # noqa: E402
import _fedramp_schema  # noqa: E402
import _scn  # noqa: E402

TODAY = date(2026, 11, 5)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


build = _load("build_scn", REPO / "scripts" / "build-scn.py")
evaluate = _load("scn_evaluate", REPO / "scripts" / "scn-evaluate.py")
deadlines = _load("scn_deadlines", REPO / "scripts" / "check-scn-deadlines.py")


# --- business days ------------------------------------------------------------------

def test_federal_holidays_2026_are_the_observed_eleven():
    assert sorted(_bizdays.federal_holidays(2026)) == [date(2026, m, d) for m, d in (
        (1, 1), (1, 19), (2, 16), (5, 25), (6, 19), (7, 3), (9, 7), (10, 12), (11, 11), (11, 26), (12, 25))]


@pytest.mark.parametrize("day,observed", [
    (date(2026, 7, 4), date(2026, 7, 3)),     # Saturday -> Friday
    (date(2027, 6, 19), date(2027, 6, 18)),   # Saturday -> Friday
    (date(2027, 7, 4), date(2027, 7, 5)),     # Sunday -> Monday
    (date(2027, 12, 25), date(2027, 12, 24)),
    (date(2028, 1, 1), date(2027, 12, 31)),   # New Year's on a Saturday: observed the year before
])
def test_weekend_holidays_move_to_the_observed_day(day, observed):
    assert observed in _bizdays.federal_holidays(observed.year)
    assert day not in _bizdays.federal_holidays(day.year)


def test_business_day_arithmetic_skips_weekends_and_holidays():
    assert _bizdays.add_business_days(date(2026, 11, 25), 1) == date(2026, 11, 27)  # Thanksgiving
    assert _bizdays.add_business_days(date(2026, 11, 6), 1) == date(2026, 11, 9)    # weekend
    assert _bizdays.add_business_days(date(2026, 11, 10), 1) == date(2026, 11, 12)  # Veterans Day
    assert _bizdays.add_business_days(date(2027, 1, 4), -1) == date(2026, 12, 31)   # New Year's Day
    assert _bizdays.add_business_days(date(2026, 6, 6), 10) == date(2026, 6, 22)    # Juneteenth in the span
    assert _bizdays.add_business_days(date(2026, 11, 5), 0) == date(2026, 11, 5)


def test_timeframes_come_from_the_vendored_rules():
    assert {r: _scn.timeframe(r) for r in ("SCN-ADP-NTF", "SCN-TRF-NIP", "SCN-TRF-NFP", "SCN-TRF-NAF",
                                           "SCN-TRF-NAV", "SCN-TRF-UPD")} == {
        "SCN-ADP-NTF": 10, "SCN-TRF-NIP": 30, "SCN-TRF-NFP": 10, "SCN-TRF-NAF": 5, "SCN-TRF-NAV": 5,
        "SCN-TRF-UPD": 30}


# --- the evaluation gate (SCN-CSO-EVA) ----------------------------------------------------

BAD = {
    "missing-type.md": "no 'SCN-Type:' line",
    "missing-rationale.md": "no 'SCN-Rationale:' line",
    "placeholder-rationale.md": "empty or a placeholder",
    "unknown-type.md": "is not one of",
    "class-change.md": "class-change blocks the merge",
    "adaptive-no-record.md": "needs an 'SCN-Record: SCN-YYYY-NNN' line",
    "routine-with-record.md": "names no SCN-Record",
    "two-types.md": "2 'SCN-Type:' lines",
    "transformative-too-soon.md": "may start on or after",
}


@pytest.mark.parametrize("name,why", sorted(BAD.items()))
def test_each_known_bad_evaluation_fails_for_its_reason(name, why):
    index = json.loads((FIX / "index.json").read_text())
    errors, _, _ = _scn.gate((FIX / "bad" / name).read_text(), index, TODAY)
    assert errors and any(why in e for e in errors), errors


@pytest.mark.parametrize("name,kind", [
    ("not-significant.md", "not-significant"), ("routine-recurring-legacy-spelling.md", "routine-recurring"),
    ("adaptive.md", "adaptive"), ("emergency.md", "emergency"), ("transformative-ready.md", "transformative")])
def test_each_good_evaluation_passes(name, kind):
    index = json.loads((FIX / "index.json").read_text())
    errors, _, ev = _scn.gate((FIX / "good" / name).read_text(), index, TODAY)
    assert errors == [] and ev["type"] == kind


def test_an_empty_description_fails_there_is_no_default():
    errors, _, ev = _scn.gate("", None, TODAY)
    assert ev is None and "no 'SCN-Type:' line" in errors[0]


def test_transformative_fails_closed_without_the_published_index():
    errors, _, _ = _scn.gate((FIX / "good" / "transformative-ready.md").read_text(), None, TODAY)
    assert "fail closed" in errors[0]


def test_the_cli_exits_nonzero_on_every_known_bad_fixture(capsys):
    for name in BAD:
        rc = evaluate.main(["--text-file", str(FIX / "bad" / name), "--index-file", str(FIX / "index.json"),
                            "--today", TODAY.isoformat()])
        assert rc == 1, name
    assert evaluate.main(["--text-file", str(FIX / "good" / "adaptive.md"), "--today", TODAY.isoformat()]) == 0
    assert "::error::" in capsys.readouterr().out


def test_the_workflow_runs_the_tested_gate_with_no_default():
    text = (REPO / ".github" / "workflows" / "scn-tag.yml").read_text()
    assert "python3 scripts/scn-evaluate.py --text-env SCN_TEXT" in text
    assert "defaulting" not in text and "routine-recurring)" not in text
    # The job keeps the name branch protection requires.
    assert re.search(r"^  scn-tag:$", text, re.M)
    # Untrusted text only through the environment.
    assert "${{ github.event.pull_request.body }}" in text.split("env:", 1)[1].split("run:", 1)[0]


def test_every_type_has_a_documented_example():
    doc = (REPO / "docs" / "scn" / "evaluation-examples.md").read_text()
    for t in _scn.TYPES:
        block = doc.split(f"## {t}\n", 1)
        assert len(block) == 2, t
        example = block[1].split("## ", 1)[0]
        errors, _, ev = _scn.gate(example.split("```")[1], json.loads((FIX / "index.json").read_text()), TODAY)
        assert ev and ev["type"] == t, (t, errors)


# --- the register (SCN-CSO-INF, SCN-RTR-NNR, transformative template) -----------------------

def test_the_committed_register_is_valid():
    header, rows = _scn.read_register()
    assert _scn.validate_register(header, rows) == []
    assert len(rows) >= 6


@pytest.mark.parametrize("name,why", [
    ("register-routine.csv", "only adaptive and transformative changes get a notification record (SCN-RTR-NNR)"),
    ("register-transformative-incomplete.csv", "tpr_human_validation must be yes or no"),
    ("register-adaptive-no-risks.csv", "new_risks_summary is empty (SCN-ADP-NTF)"),
    ("register-dates-out-of-order.csv", "is before date_initiated"),
])
def test_each_known_bad_register_fails_for_its_reason(name, why):
    header, rows = _scn.read_register(FIX / "bad" / name)
    errors = _scn.validate_register(header, rows)
    assert any(why in e for e in errors), errors


def test_an_incomplete_transformative_row_names_every_template_field():
    header, rows = _scn.read_register(FIX / "bad" / "register-transformative-incomplete.csv")
    text = " ".join(_scn.validate_register(header, rows))
    for field in ("date_started", "plan_final", "tpr_human_validation", "tpr_assessor_or_reason"):
        assert field in text


def test_transformative_notices_and_deadlines():
    header, rows = _scn.read_register(FIX / "good" / "register-transformative.csv")
    assert _scn.validate_register(header, rows) == []
    due = {n["stage"]: n["deadline"] for n in _scn.notices_due(rows[0])}
    assert due == {
        "initial-plan": date(2026, 9, 18),        # 30 business days before 2026-11-02 (Labor Day, Columbus Day)
        "final-plan": date(2026, 10, 19),         # 10 before
        "after-finish": date(2026, 11, 20),       # 5 after 2026-11-13
        "after-verification": date(2026, 11, 30),  # 5 after 2026-11-20, over Thanksgiving
    }
    assert _scn.docs_update_deadline(rows[0]) == _bizdays.add_business_days(date(2026, 11, 13), 30)


def test_emergency_notices_are_retroactive_within_five_business_days():
    _, rows = _scn.read_register(FIX / "good" / "register-transformative.csv")
    row = dict(rows[0], emergency="yes")
    for n in _scn.notices_due(row):
        assert n["deadline"] == date(2026, 11, 20) and n["kind"] == "retroactive"
        assert "SCN-CSO-EMG" in n["rule"]


def test_adaptive_notice_is_due_ten_business_days_after_finishing():
    _, rows = _scn.read_register()
    by_id = {r["scn_id"]: r for r in rows}
    assert _scn.notices_due(by_id["SCN-2026-001"]) == [
        {"stage": "after-finish", "rule": "SCN-ADP-NTF", "deadline": date(2026, 6, 22), "kind": "by"}]


# --- publication: index, feed, retention (SCN-CSO-HIS/HRM/NOM/INF) --------------------------

def _build(tmp_path, *extra, new_entries=None):
    (tmp_path / "new.json").write_text(json.dumps(new_entries or []))
    return build.main(["--out-dir", str(tmp_path), "--commit", "abc123", "--new-evaluations",
                       str(tmp_path / "new.json"), *extra])


def test_build_publishes_every_register_row_in_the_fedramp_schema(tmp_path):
    assert _build(tmp_path) == 0
    _, rows = _scn.read_register()
    index = json.loads((tmp_path / "significant-change-notifications.json").read_text())
    assert [d["scnId"] for d in index["notifications"]] == [r["scn_id"] for r in rows]
    for d in index["notifications"]:
        assert _fedramp_schema.validate(d, "scn") == []
        assert (tmp_path / "scn" / f"{d['scnId']}.json").is_file()
        assert d["certificationPackageOverviewUri"] == _fedramp_schema.CPO_URI
        # SCN-CSO-ARI: more than the required fields.
        assert d["additionalInformation"]["record"].startswith(_scn.SOURCE_URL)
    # Human-readable view (SCN-CSO-HRM) carries each one.
    md = (tmp_path / "significant-change-notifications.md").read_text()
    assert all(d["scnId"] in md for d in index["notifications"])
    assert {m["mechanism"] for m in index["notificationMechanisms"]} == {
        "Atom feed", "Signed JSON index", "Human-readable view"}


def test_a_new_notice_is_dated_today_and_late_ones_say_so(tmp_path):
    assert _build(tmp_path) == 0
    index = json.loads((tmp_path / "significant-change-notifications.json").read_text())
    n = index["notifications"][0]["notices"][0]
    assert n["publishedOn"] == build._today().isoformat()
    assert n["onTime"] is (date.fromisoformat(n["publishedOn"]) <= date.fromisoformat(n["deadline"]))
    assert "SCN-2026-001 after-finish" in index["lateNotices"]


def test_a_published_notice_keeps_its_first_publication_date(tmp_path):
    prev = {"notifications": [{"scnId": "SCN-2026-001", "notices": [
        {"stage": "after-finish", "rule": "SCN-ADP-NTF", "deadline": "2026-06-22", "publishedOn": "2026-06-15",
         "onTime": True}]}]}
    (tmp_path / "prev.json").write_text(json.dumps(prev))
    assert _build(tmp_path, "--previous-index", str(tmp_path / "prev.json")) == 0
    index = json.loads((tmp_path / "significant-change-notifications.json").read_text())
    n = index["notifications"][0]["notices"][0]
    assert n["publishedOn"] == "2026-06-15" and n["onTime"] is True


def test_a_build_that_would_drop_a_published_notification_fails(tmp_path):
    with pytest.raises(SystemExit, match="SCN-2025-001 was published and would be dropped"):
        _build(tmp_path, "--previous-index", str(FIX / "bad" / "index-previous-with-dropped.json"))


def test_the_feed_is_atom_with_one_entry_per_notice(tmp_path):
    assert _build(tmp_path) == 0
    index = json.loads((tmp_path / "significant-change-notifications.json").read_text())
    root = ET.parse(tmp_path / "significant-change-notifications.atom").getroot()
    ns = {"a": "http://www.w3.org/2005/Atom"}
    assert root.tag == "{http://www.w3.org/2005/Atom}feed"
    ids = [e.findtext("a:id", namespaces=ns) for e in root.findall("a:entry", ns)]
    assert len(ids) == sum(len(d["notices"]) for d in index["notifications"]) == len(set(ids))


def test_a_run_id_in_published_text_fails_the_build(tmp_path):
    reg = tmp_path / "reg.csv"
    reg.write_text((REPO / "docs" / "scn" / "scn-register.csv").read_text().replace(
        "Implemented and verified 2026-10-27", "Implemented and verified 2026-10-27 (run 36434974425)"))
    assert _build(tmp_path, "--register", str(reg)) == 1


def test_the_published_outputs_are_listed_signed_and_governed():
    deploy = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    step = deploy[deploy.index("- name: Build Significant Change Notifications"):]
    assert "build-scn.py --previous-index previous-scn-index.json" in step
    assert deploy.index("- name: Build Significant Change Notifications") < deploy.index(
        "- name: Sign CDS certification-data artifacts")
    sign = deploy[deploy.index("- name: Sign CDS certification-data artifacts"):]
    sign = sign[:sign.index("\n    - name:")]
    assert "for a in significant-change-notifications scn-evaluations" in sign
    assert "significant-change-notifications.atom.bundle significant-change-notifications.atom" in sign
    # A successful deploy means they are out: the build step has no `|| true`
    # escape, and the post-publish round-trip compares the served bytes.
    assert "|| true" not in step[:step.index("\n    - name:")] and "continue-on-error" not in step[:step.index("\n    - name:")]
    rt = deploy[deploy.index("- name: Post-publish round-trip verify"):]
    rt = rt[:rt.index("\n    - name:")]
    for f in ("significant-change-notifications.json", "significant-change-notifications.atom", "scn-evaluations.json"):
        assert f"check {f} .well-known/{f}" in rt
    cfg = {a["path"] for a in json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json")
                                         .read_text())["artifacts"]}
    assert {".well-known/significant-change-notifications.json", ".well-known/significant-change-notifications.atom",
            ".well-known/scn-evaluations.json"} <= cfg


def _cpo_doc():
    """The CPO as the deploy builds it, in FedRAMP's schema (the same inputs
    tests/test_cpo_trust_fields.py uses)."""
    import tempfile
    from datetime import datetime, timezone
    import _assessor
    import _ccm
    import _offering
    cpo = _load("build_cpo_scn", REPO / "scripts" / "build-cpo.py")
    with tempfile.TemporaryDirectory() as d:
        s = Path(d) / "simulated-assessment.json"
        s.write_text((REPO / "tests" / "fixtures" / "assessor" / "simulated-set.json").read_text())
        assessment = _assessor.load_assessment(s, s, verifier=lambda *_a: True)
    now = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
    doc = cpo.build(_offering.load(), json.loads((REPO / "data" / "system-profile.json").read_text()),
                    json.loads((REPO / "tests" / "fixtures" / "clean" / "ksi-signal.json").read_text()),
                    _ccm.load(_ccm.CALENDAR_PATH, now.date()), {}, now, cpo.boundary_groups(), assessment)
    assert _fedramp_schema.validate(doc, "cpo") == []
    return doc, cpo.render_markdown(doc)


def test_the_cpo_lists_the_notification_mechanism():
    doc, md = _cpo_doc()
    scn = doc["providerExtensions"]["significantChangeNotifications"]
    urls = {m["url"] for m in scn["mechanisms"]}
    assert _scn.BASE + _scn.FEED_NAME in urls
    published = {r["url"].rsplit("/", 1)[-1] for r in doc["serviceProperties"]["additionalRepositories"]}
    assert {"significant-change-notifications.json", "significant-change-notifications.atom",
            "scn-evaluations.json"} <= published
    assert "Significant Change Notifications (SCN-CSO-NOM)" in md


# --- the evaluation log (SCN-CSO-MAR) -------------------------------------------------------

def test_the_log_appends_to_the_previous_published_version(tmp_path):
    prev = json.loads((FIX / "log-previous.json").read_text())
    new = [dict(prev["entries"][0], commit="3" * 40, merged_on="2026-11-10", pull_request=503)]
    (tmp_path / "prev.json").write_text(json.dumps(prev))
    assert _build(tmp_path, "--previous-log", str(tmp_path / "prev.json"), new_entries=new) == 0
    log = json.loads((tmp_path / "scn-evaluations.json").read_text())
    assert log["entries"] == prev["entries"] + new
    assert log["genesis_commit"] == prev["genesis_commit"]
    assert "#503" in (tmp_path / "scn-evaluations.md").read_text()


@pytest.mark.parametrize("name,why", [("log-rewritten.json", "entry 1 (2222"), ("log-truncated.json", "dropped")])
def test_the_append_only_check_fails_each_known_bad_log(name, why):
    prev = json.loads((FIX / "log-previous.json").read_text())["entries"]
    cur = json.loads((FIX / "bad" / name).read_text())["entries"]
    errors = _scn.append_only_errors(prev, cur, "commit")
    assert any(why in e for e in errors), errors


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def history(tmp_path):
    """main: an old commit, then a merge of PR #7 that adds the builder, then a
    direct push, then a merge of PR #8 with no evaluation."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "tester")
    (repo / "a").write_text("a")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "before the log")
    for n, path in ((7, build.GENESIS_PATH), (8, "c")):
        _git(repo, "checkout", "-qb", f"b{n}")
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(str(n))
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", f"work {n}")
        _git(repo, "checkout", "-q", "main")
        _git(repo, "merge", "-q", "--no-ff", f"b{n}", "-m", f"Merge pull request #{n} from x/b{n}")
        if n == 7:
            (repo / "d").write_text("d")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-qm", "direct push\n\nSCN-Type: not-significant\n"
                                       "SCN-Rationale: content-only change to a public page here.")
    return repo


def _lookup(n):
    bodies = {7: "SCN-Type: adaptive\nSCN-Rationale: adds a new internal alarm, no ingress.\nSCN-Record: SCN-2026-007",
              8: "Forgot the evaluation."}
    return {"body": bodies[n], "merged_by": "sam-aydlette", "author": "someone"}


def test_collect_logs_every_first_parent_commit_from_the_builder_onward(history):
    entries = build.collect([], root=history, lookup=_lookup)
    assert [(e["pull_request"], e["scn_type"]) for e in entries] == [
        (7, "adaptive"), (None, "not-significant"), (8, None)]
    assert entries[0]["scn_record"] == "SCN-2026-007" and entries[0]["evaluator"] == "sam-aydlette"
    assert entries[1]["evaluator"] == "tester"
    assert entries[2]["problem"].startswith("no valid evaluation")
    # Next deploy: only what came after the last entry.
    assert build.collect(entries, root=history, lookup=_lookup) == []
    assert build.collect(entries[:1], root=history, lookup=_lookup) == entries[1:]


def test_collect_fails_when_the_last_logged_commit_left_history(history):
    with pytest.raises(SystemExit, match="not an ancestor"):
        build.collect([{"commit": "f" * 40}], root=history, lookup=_lookup)
    with pytest.raises(SystemExit, match="no valid commit"):
        build.collect([{"commit": "--output=/tmp/x"}], root=history, lookup=_lookup)


def test_free_text_is_scrubbed_before_it_is_published():
    e = build.evaluation_entry("a" * 40, "direct", "SCN-Type: not-significant\nSCN-Rationale: fixes run 36434974425 "
                               "for account 123456789012 docs", "2026-11-05", "x", _lookup)
    assert "36434974425" not in e["rationale"] and "123456789012" not in e["rationale"]


# --- the scheduled deadline check -----------------------------------------------------------

def _entry(kind, record, merged):
    return {"commit": "9" * 40, "merged_on": merged, "scn_type": kind, "scn_record": record}


def test_an_adaptive_change_with_no_record_is_overdue_after_ten_business_days():
    _, rows = _scn.read_register()
    index = {"notifications": [{"scnId": r["scn_id"], "notices": [{"stage": "after-finish"}]} for r in rows]}
    log = [_entry("adaptive", "SCN-2026-007", "2026-11-02")]
    assert _scn.overdue(rows, index, log, date(2026, 11, 17)) == []   # due 2026-11-17 (Veterans Day)
    late = _scn.overdue(rows, index, log, date(2026, 11, 18))
    assert len(late) == 1 and "SCN-2026-007" in late[0] and "not in the register" in late[0]


def test_an_emergency_change_owes_its_record_within_five_business_days():
    _, rows = _scn.read_register()
    index = {"notifications": [{"scnId": r["scn_id"], "notices": [{"stage": "after-finish"}]} for r in rows]}
    log = [_entry("emergency", "SCN-2026-099", "2026-11-20")]
    assert _scn.overdue(rows, index, log, date(2026, 11, 30)) == []  # Thanksgiving: due 11-30
    assert _scn.overdue(rows, index, log, date(2026, 12, 1))


def test_an_unpublished_notice_is_overdue_until_a_deploy_publishes_it():
    _, rows = _scn.read_register()
    late = _scn.overdue(rows, {}, [], TODAY)
    assert any("SCN-2026-001: after-finish notice (SCN-ADP-NTF) not published" in x for x in late)
    published = {"notifications": [{"scnId": r["scn_id"], "notices": [{"stage": "after-finish"}]} for r in rows]}
    assert _scn.overdue(rows, published, [], TODAY) == []


def test_transformative_notices_after_finish_and_verification_are_overdue_unpublished():
    _, rows = _scn.read_register(FIX / "good" / "register-transformative.csv")
    index = {"notifications": [{"scnId": "SCN-2099-003", "notices": [
        {"stage": "initial-plan"}, {"stage": "final-plan"}]}]}
    assert _scn.overdue(rows, index, [], date(2026, 11, 20)) == []
    late = _scn.overdue(rows, index, [], date(2026, 11, 23))
    assert len(late) == 1 and "after-finish notice (SCN-TRF-NAF)" in late[0]
    late = _scn.overdue(rows, index, [], date(2026, 12, 1))
    assert any("after-verification notice (SCN-TRF-NAV)" in x for x in late)


def test_transformative_documentation_update_is_overdue_after_thirty_business_days():
    _, rows = _scn.read_register(FIX / "good" / "register-transformative.csv")
    stages = ["initial-plan", "final-plan", "after-finish", "after-verification"]
    index = {"notifications": [{"scnId": "SCN-2099-003", "notices": [{"stage": s} for s in stages]}]}
    due = _scn.docs_update_deadline(rows[0])
    assert _scn.overdue(rows, index, [], due) == []
    assert "SCN-TRF-UPD" in _scn.overdue(rows, index, [], _bizdays.add_business_days(due, 1))[0]
    done = [dict(rows[0], docs_updated_on="2026-12-01")]
    assert _scn.overdue(done, index, [], _bizdays.add_business_days(due, 1)) == []


def test_the_deadline_cli(tmp_path):
    _, rows = _scn.read_register()
    index = {"notifications": [{"scnId": r["scn_id"], "notices": [{"stage": "after-finish"}]} for r in rows]}
    (tmp_path / "i.json").write_text(json.dumps(index))
    (tmp_path / "l.json").write_text(json.dumps({"entries": [_entry("adaptive", "SCN-2026-007", "2026-11-02")]}))
    args = ["--index-file", str(tmp_path / "i.json"), "--log-file", str(tmp_path / "l.json")]
    assert deadlines.main([*args, "--today", "2026-11-17"]) == 0
    assert deadlines.main([*args, "--today", "2026-11-18"]) == 1
