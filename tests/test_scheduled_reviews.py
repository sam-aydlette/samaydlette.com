"""The scheduled reviews that replace recurring manual reviews (DEC-195):
the nightly audit-log review, the monthly recovery exercise with its annual
tabletop, the Annual Security Review with the rules-of-behavior
acknowledgement, and the overdue check that fails a run once a due date passes
with nothing published. Every person in them is simulated (DEC-194)."""
import copy
import hashlib
import importlib.util
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "scheduled-reviews"
sys.path.insert(0, str(REPO / "scripts"))
import _engagement  # noqa: E402
import _scheduled_review as sr  # noqa: E402


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


alr = _load("audit_log_review_t", "audit-log-review.py")
rec = _load("hold_recovery_exercise_t", "hold-recovery-exercise.py")
sec = _load("hold_security_review_t", "hold-security-review.py")
chk = _load("check_scheduled_review_t", "check-scheduled-review.py")

NOW = datetime(2026, 11, 6, 6, tzinfo=timezone.utc)
START = datetime(2026, 11, 5, 18, tzinfo=timezone.utc)


def _json(name):
    return json.loads((FIX / name).read_text())


# --- the calendar --------------------------------------------------------------------------

def test_due_dates_monthly_and_annual():
    rv, sv = sr.REVIEWS["recovery-exercise"], sr.REVIEWS["security-review"]
    assert sr.due_dates(rv, date(2027, 1, 15)) == [date(2026, 11, 1), date(2026, 12, 1), date(2027, 1, 1)]
    assert sr.due_dates(sv, date(2028, 11, 6)) == [date(2026, 11, 6), date(2027, 11, 6), date(2028, 11, 6)]
    assert sr.next_due(rv, date(2026, 12, 1)) == date(2027, 1, 1)


def test_a_malformed_index_is_refused():
    with pytest.raises(SystemExit, match="fail-closed"):
        sr.held(sr.REVIEWS["security-review"], {"schema": "scheduled-reviews/1", "review": "recovery-exercise",
                                                "reviews": []})


# --- the overdue check ---------------------------------------------------------------------

def _index(key, *dues, result="pass"):
    return {"schema": sr.INDEX_SCHEMA, "review": key,
            "reviews": [{"dueDate": d, "sha256": "0" * 64, "result": result} for d in dues]}


def test_known_bad_no_review_after_its_due_date_fails_the_run():
    assert chk.problems("security-review", {}, date(2026, 11, 7)) == [
        "Annual Security Review due 2026-11-06 is not published"]
    assert chk.main(["--review", "security-review", "--no-index", "--today", "2026-11-07"]) == 1


def test_the_due_date_itself_is_not_yet_overdue():
    assert chk.problems("security-review", {}, date(2026, 11, 6)) == []


def test_a_held_review_clears_its_due_date_and_the_next_month_is_watched():
    idx = _index("recovery-exercise", "2026-11-01")
    assert chk.problems("recovery-exercise", idx, date(2026, 12, 1)) == []
    assert chk.problems("recovery-exercise", idx, date(2026, 12, 2)) == ["Recovery exercise due 2026-12-01 is not "
                                                                         "published"]


def test_known_bad_the_current_rules_of_behavior_unacknowledged_fails(tmp_path):
    rob = tmp_path / "rob.md"
    rob.write_text("Rules.\n")
    sha = hashlib.sha256(rob.read_bytes()).hexdigest()
    idx = _index("security-review", "2026-11-06")
    assert chk.problems("security-review", idx, date(2026, 11, 7), rob) == [
        f"the current rules of behavior ({sha[:12]}) have no acknowledgement in security-reviews.json"]
    idx["rulesOfBehavior"] = {"acknowledgements": [{"sha256": sha}]}
    assert chk.problems("security-review", idx, date(2026, 11, 7), rob) == []


# --- the audit-log review ------------------------------------------------------------------

def _review(events="cloudtrail-expected.json", gh="github-clean.json"):
    return alr.build(_json(events), _json(gh), START, NOW, "FR-TEST")


def test_ci_roles_aws_and_app_users_are_expected_and_unwatched_writes_ignored():
    doc = _review()
    assert doc["unexpected"] == [] and doc["result"] == "pass"
    assert doc["expected"] == {"aws-service": 1, "ci-role:deploy": 2, "cognito-app-user": 1}
    assert alr.enforce(doc) == 0


def test_the_planted_intruder_is_caught_on_every_run():
    doc = _review()
    assert doc["exercise"]["caught"] and doc["exercise"]["planted"] == 2
    assert {c["event"] for c in doc["exercise"]["events"]} == {"StopLogging", "CreateAccessKey"}
    assert all(c["evaluation"]["reportable"] for c in doc["exercise"]["events"])
    assert "(simulated)" in doc["exercise"]["intruder"]


def test_known_bad_rules_that_miss_the_intruder_fail_the_review(monkeypatch):
    monkeypatch.setattr(alr, "REPORTABLE", {})
    doc = _review()
    assert not doc["exercise"]["caught"] and doc["result"] == "fail"
    assert alr.enforce(doc) == 1


def test_known_bad_an_unknown_principal_is_unexpected_and_a_key_creation_reportable():
    doc = _review("cloudtrail-unknown-principal.json")
    by_event = {u["event"]: u for u in doc["unexpected"]}
    assert set(by_event) == {"PutBucketPolicy", "CreateAccessKey"}
    assert not by_event["PutBucketPolicy"]["evaluation"]["reportable"]
    assert by_event["CreateAccessKey"]["evaluation"]["reportable"]
    assert doc["findings"] == {"unexpected": 2, "reportable": 1, "processFinding": "process-audit-log.unexpected"}
    assert alr.enforce(doc) == 1


def test_no_principal_name_is_published():
    text = json.dumps(_review("cloudtrail-unknown-principal.json"))
    for name in ("somebody-elses-role", "a-real-looking-user", "github-actions-deploy-oidc"):
        assert name not in text


def test_known_bad_a_direct_push_and_a_setting_changed_outside_a_pr_are_unexpected():
    doc = _review(gh="github-direct-push.json")
    events = [u["event"] for u in doc["unexpected"]]
    assert events == ["a workflow change on main with no merged pull request",
                      "the environment 'production' changed outside a pull request"]
    assert doc["findings"]["reportable"] == 0


def test_an_unreadable_github_fails_the_review():
    doc = alr.build(_json("cloudtrail-expected.json"), None, START, NOW, "FR-TEST", ())
    assert doc["result"] == "fail"


def test_the_window_follows_the_previous_review_and_is_bounded():
    prev = {"window": {"to": "2026-11-05T18:00:00+00:00"}}
    assert alr.window(prev, NOW)[0] == START
    old = {"window": {"to": "2026-10-01T00:00:00+00:00"}}
    assert (NOW - alr.window(old, NOW)[0]).total_seconds() == 36 * 3600


def test_unexpected_events_are_recorded_as_a_gate_event(tmp_path, monkeypatch):
    events = tmp_path / "gate-events.jsonl"
    monkeypatch.setenv("GATE_EVENTS_FILE", str(events))
    out = tmp_path / "r.json"
    assert alr.main(["--out", str(out), "--cloudtrail-events", str(FIX / "cloudtrail-unknown-principal.json"),
                     "--github-records", str(FIX / "github-clean.json"), "--now", NOW.isoformat()]) == 0
    assert "audit-log.unexpected" in events.read_text()
    assert alr.main(["--enforce", str(out)]) == 1


def test_the_review_carries_the_engagement_statement():
    doc = _review()
    assert doc["engagement"] == _engagement.STATEMENT and doc["humanActs"] == "DEC-195"


# --- the recovery exercise -----------------------------------------------------------------

TREE = {"index.html": b'<link href="/a.css?v=111">', "a.css": b"body{}", "assets/LICENSE": b"MIT"}


def _get(served):
    return lambda url: (200, served[url.split("samaydlette.com/", 1)[1]]) if url.split(
        "samaydlette.com/", 1)[1] in served else (404, b"")


def test_the_restore_point_matches_ignoring_the_cache_bust_and_skips_extensionless_files():
    live = {"index.html": b'<link href="/a.css?v=999">', "a.css": b"body{}"}
    c = rec.restore_point(TREE, _get(live))
    assert c["result"] == "pass" and c["notAddressable"] == ["assets/LICENSE"]


def test_known_bad_a_live_page_that_differs_from_git_fails():
    live = {"index.html": b'<link href="/a.css?v=999">', "a.css": b"body{color:red}"}
    c = rec.restore_point(TREE, _get(live))
    assert c["result"] == "fail" and c["differ"] == ["a.css"]


def test_known_bad_a_page_not_served_fails():
    c = rec.restore_point(TREE, _get({"index.html": b'<link href="/a.css?v=1">'}))
    assert c["result"] == "fail" and c["notServed"] == ["a.css"]


def _runtime(tmp_path, commit="a" * 40, validations=None, verified=True):
    p = tmp_path / "rt.json"
    p.write_text(json.dumps({"provenance": {"source": {"commit": commit}},
                             "components": [{"component_id": "aws::s3::site", "type": "object_store"},
                                            {"component_id": "aws::ddb::lock", "type": "kv_table"},
                                            {"component_id": "aws::fn::x", "type": "function"}]}))
    vals = validations if validations is not None else [
        {"result": "pass", "component_refs": ["aws::s3::site"]}, {"result": "pass", "component_refs": ["aws::ddb::lock"]}]

    def loader(path, now=None):
        return {"verified": verified, "fresh": True, "reason": None if verified else "signature does not verify",
                "validations": vals, "emitted_at": "2026-11-06T05:00:00Z"}
    return p, loader


def test_versioning_and_pitr_are_re_read_from_the_runtime_signal(tmp_path):
    p, loader = _runtime(tmp_path)
    assert rec.configuration(p, "a" * 40, NOW, loader)["result"] == "pass"


def test_known_bad_a_table_without_a_passing_validation_fails(tmp_path):
    p, loader = _runtime(tmp_path, validations=[{"result": "pass", "component_refs": ["aws::s3::site"]}])
    c = rec.configuration(p, "a" * 40, NOW, loader)
    assert c["result"] == "fail" and "aws::ddb::lock" in c["detail"]


def test_known_bad_a_runtime_signal_of_another_commit_or_unverified_fails(tmp_path):
    p, loader = _runtime(tmp_path, commit="b" * 40)
    assert rec.configuration(p, "a" * 40, NOW, loader)["result"] == "fail"
    p, loader = _runtime(tmp_path, verified=False)
    assert rec.configuration(p, "a" * 40, NOW, loader)["result"] == "fail"


def test_the_tabletop_walks_every_scenario_of_the_real_plan():
    chk_, record = rec.tabletop((REPO / "docs" / "recovery-plan.md").read_text())
    assert chk_["result"] == "pass" and len(record["scenarios"]) >= 3
    assert all("(simulated)" in p for p in record["participants"])


def test_known_bad_a_plan_with_a_scenario_without_recovery_fails_the_tabletop():
    chk_, _ = rec.tabletop((FIX / "recovery-plan-gap.md").read_text())
    assert chk_["result"] == "fail"
    assert "The intern unplugs the cloud" in chk_["detail"] and "Recovery procedure" in chk_["detail"]


def test_the_tabletop_runs_only_in_november(tmp_path):
    p, loader = _runtime(tmp_path)
    live = {"index.html": b'<link href="/a.css?v=9">', "a.css": b"body{}"}
    plan = (REPO / "docs" / "recovery-plan.md").read_text()
    nov = rec.build(date(2026, 11, 1), NOW, "FR-TEST", TREE, _get(live), p, "a" * 40, plan, loader)
    dec = rec.build(date(2026, 12, 1), NOW, "FR-TEST", TREE, _get(live), p, "a" * 40, plan, loader)
    assert "tabletop" in nov and "tabletop" not in dec
    assert nov["result"] == dec["result"] == "pass"


def test_a_failing_exercise_is_not_frozen_and_the_index_is_still_written(tmp_path, monkeypatch):
    p, loader = _runtime(tmp_path, validations=[])
    monkeypatch.setattr(rec, "site_tree", lambda commit, repo=None: TREE)
    live = {"index.html": b'<link href="/a.css?v=9">', "a.css": b"body{}"}
    out = tmp_path / "out"
    out.mkdir()
    index, entries, files, failed = rec.run({}, out, NOW, "FR-TEST", "a" * 40, p, get=_get(live),
                                            runtime_loader=loader)
    assert failed == [date(2026, 11, 1)] and entries == [] and files == []
    assert (out / "vdr-recovery-exercises.json").is_file()
    assert not list(out.glob("vdr-recovery-exercise-*.json"))


# --- the Annual Security Review ------------------------------------------------------------

THREAT = (REPO / "docs" / "architecture-decisions.md").read_text()


def test_the_first_review_takes_the_current_types_as_its_baseline():
    c, types = sec.component_types({"components": [{"type": "function"}, {"type": "brand_new_thing"}]}, None, THREAT)
    assert c["result"] == "pass" and types == ["brand_new_thing", "function"]


def test_known_bad_a_new_component_type_not_named_in_the_threat_model_fails():
    prev = {"componentTypes": ["function"]}
    c, _ = sec.component_types({"components": [{"type": "function"}, {"type": "quantum_teleporter"}]}, prev, THREAT)
    assert c["result"] == "fail" and "quantum_teleporter" in c["detail"]


def test_a_new_type_named_in_the_threat_model_passes():
    prev = {"componentTypes": ["function"]}
    c, _ = sec.component_types({"components": [{"type": "function"}, {"type": "cdn_distribution"}]}, prev, THREAT)
    assert c["result"] == "pass"


def test_the_committed_recurring_costs_are_valid_and_marked_ai_drafted():
    doc = sec.validate_costs(json.loads((REPO / "data" / "recurring-costs.json").read_text()))
    assert doc["status"] == "AI-drafted estimate; operator to correct"
    assert all((x["estimate_usd_per_year"] is None) == (x["estimate"] == "unknown") for x in doc["lines"])


@pytest.mark.parametrize("name,reason", [("costs-no-source.json", "neither a repository path"),
                                         ("costs-number-not-unknown.json", "must say 'unknown'")])
def test_known_bad_cost_lines_are_refused(name, reason):
    with pytest.raises(SystemExit, match=reason):
        sec.validate_costs(_json(name))


def test_known_bad_a_recurring_incident_pattern_fails_the_review():
    reg = {"decisions": []}
    incs = {"incidents": [{"detected_at": "2026-10-01", "evaluation": {"basis": "same-thing"}},
                          {"detected_at": "2026-10-02", "evaluation": {"basis": "same-thing"}}]}
    checks, summary = sec.operations(reg, incs, {}, date(2026, 11, 6))
    by = {c["id"]: c["result"] for c in checks}
    assert by["incident-patterns"] == "fail" and summary["incidents"]["recurring"] == ["same-thing"]


def test_exercises_do_not_make_a_pattern():
    incs = {"incidents": [{"detected_at": "2026-10-01", "exercise": True, "evaluation": {"basis": "x"}},
                          {"detected_at": "2026-10-02", "exercise": True, "evaluation": {"basis": "x"}}]}
    checks, _ = sec.operations({"decisions": []}, incs, {}, date(2026, 11, 6))
    assert all(c["result"] == "pass" for c in checks)


def test_the_rules_of_behavior_are_acknowledged_each_year_and_on_change():
    a = sec.acknowledgements(None, "s1", date(2026, 11, 6), held_now=True)
    assert [x["reason"] for x in a["acknowledgements"]] == ["annual acknowledgement with the security review"]
    assert "(simulated)" in a["acknowledgedBy"]
    same = sec.acknowledgements({"rulesOfBehavior": a}, "s1", date(2026, 11, 7), held_now=False)
    assert len(same["acknowledgements"]) == 1
    changed = sec.acknowledgements({"rulesOfBehavior": a}, "s2", date(2026, 12, 1), held_now=False)
    assert changed["acknowledgements"][-1]["reason"] == "the rules of behavior changed"
    assert sec.rob_acknowledged({"rulesOfBehavior": changed}, "s2")


def test_the_full_review_runs_on_the_repository_and_signs_off(tmp_path):
    signal = {"components": [{"type": "function"}, {"type": "object_store"}]}
    runs = [{"workflowName": "Deploy", "createdAt": "2026-11-01T00:00:00Z", "updatedAt": "2026-11-01T00:10:00Z"}]
    index, entries, files = sec.run({}, tmp_path, NOW, "FR-TEST", signal, {"findings": []}, runs, [])
    assert files == ["security-review-2026-11-06.json"] and entries[0]["result"] == "pass"
    doc = json.loads((tmp_path / files[0]).read_text())
    assert {s["by"] for s in doc["signOff"]} == {"Rev Yewer (simulated)"}
    assert doc["investment"]["pipelineMinutes"]["total"] == 10
    assert (tmp_path / "security-review-2026-11-06.view.md").is_file()
    assert index["rulesOfBehavior"]["acknowledgements"]
    # A second run on the same day holds nothing new and carries the index forward.
    again, entries2, _ = sec.run(index, tmp_path, NOW, "FR-TEST", signal, {"findings": []}, runs, [tmp_path])
    assert entries2 == [] and again["reviews"] == index["reviews"]


def test_known_bad_a_failing_review_fails_the_run_and_is_not_written(tmp_path, monkeypatch):
    monkeypatch.setattr(sec, "investment", lambda costs, runs, today: (
        {"id": "investment", "title": "t", "result": "fail", "detail": "no run history"}, {}))
    with pytest.raises(SystemExit, match="did not pass"):
        sec.run({}, tmp_path, NOW, "FR-TEST", {"components": [{"type": "function"}]}, {}, None, [])
    assert not list(tmp_path.glob("security-review-*.json"))


# --- the SDR's methods ---------------------------------------------------------------------

def test_method_status_needs_a_current_passing_record():
    good = {"schema": "audit-log-review/1", "generated_at": NOW.isoformat(), "result": "pass",
            "exercise": {"caught": True}}
    assert sr.method_status("audit-log-review", good, NOW) == (True, None)
    stale = copy.deepcopy(good)
    stale["generated_at"] = "2026-11-01T00:00:00+00:00"
    assert not sr.method_status("audit-log-review", stale, NOW)[0]
    missed = copy.deepcopy(good)
    missed["exercise"]["caught"] = False
    assert sr.method_status("audit-log-review", missed, NOW) == (False, "the planted simulated intruder was not "
                                                                        "caught")
    assert sr.method_status("security-review", _index("security-review", "2026-11-06"), NOW) == (True, None)
    assert not sr.method_status("security-review", _index("security-review", "2026-11-06", result="fail"), NOW)[0]
    late = sr.method_status("recovery-exercise", _index("recovery-exercise", "2026-11-01"),
                            datetime(2026, 12, 3, tzinfo=timezone.utc))
    assert late == (False, "the review due 2026-12-01 is not published")
