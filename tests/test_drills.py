"""The drills (scripts/_drills.py, scripts/_phishing.py, scripts/hold-drill.py)
and the incident log's after-action and pattern checks (scripts/_incidents.py):
each a real check that would work unchanged with real people or events, run
against a plainly simulated cast, with a planted bad case that must be caught
on every run (DEC-194, DEC-195)."""
import copy
import importlib.util
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "drills"
sys.path.insert(0, str(REPO / "scripts"))
import _decisions  # noqa: E402
import _drills  # noqa: E402
import _engagement  # noqa: E402
import _evaluation  # noqa: E402
import _incidents  # noqa: E402
import _ksi_methods  # noqa: E402
import _phishing  # noqa: E402
import _scheduled_review as sr  # noqa: E402
import _signers  # noqa: E402
import _training  # noqa: E402


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


hold = _load("hold_drill_t", "hold-drill.py")
chk = _load("check_scheduled_review_drills_t", "check-scheduled-review.py")
scc = _load("check_secure_config_drills_t", "check-secure-config.py")
NOW = datetime(2026, 11, 6, 6, tzinfo=timezone.utc)
REG = _decisions.load(REPO / "data" / "decisions.json")
DEC_IDS = set(_decisions.by_any_id(REG))
IR = (REPO / "docs" / "incident-response.md").read_text()
PLAN = (REPO / "docs" / "recovery-plan.md").read_text()


# --- the calendar and the cast ------------------------------------------------------------

def test_quarterly_and_monthly_drills_fall_due_on_the_first():
    assert sr.due_dates(sr.REVIEWS["board-meeting"], date(2027, 6, 1)) == [
        date(2026, 11, 1), date(2027, 2, 1), date(2027, 5, 1)]
    assert sr.next_due(sr.REVIEWS["tabletop"], date(2026, 11, 6)) == date(2026, 12, 1)


def test_every_drill_is_published_by_the_nightly_under_its_prefix():
    for key in sr.DRILLS:
        rv = sr.REVIEWS[key]
        assert rv.publisher == "nightly" and rv.prefix.startswith("vdr-drill-") and rv.index.startswith("vdr-drill-")
        assert _signers.signers(rv.index) == ["nightly"]
        assert _signers.signers(f"{rv.prefix}2026-11-01.json") == ["nightly"]


def test_every_cast_member_and_scenario_says_it_is_simulated():
    for name in [*sr.CAST.values(), *sr.SCENARIOS.values()]:
        assert name.endswith("(simulated)"), name


# --- The Board of Sam (KSI-PIY-RES) -------------------------------------------------------

def _meeting(due=date(2026, 11, 1), endorsed=()):
    return _drills.board_meeting(due, _decisions.in_force(REG), REG["decisions"], list(endorsed), None)


def test_the_board_endorses_every_in_force_acceptance_decided_by_the_meeting():
    checks, record, every = _meeting()
    assert all(c["result"] == "pass" for c in checks), checks
    decided = [a for a in record["acceptances"] if a["decided_on"] <= "2026-11-01"]
    assert decided and {e["decision"] for e in every} == {a["id"] for a in decided}


def test_known_bad_the_board_flags_an_acceptance_left_off_the_agenda():
    accepts = _drills.acceptances(_decisions.in_force(REG))
    _, _, every = _meeting()
    forgotten = dict(_drills.FORGOTTEN, decided_on="2026-10-31", review_by="2027-10-31")
    assert _drills.endorsement_gaps(accepts, every, date(2026, 11, 1)) == []
    assert _drills.endorsement_gaps([*accepts, forgotten], every, date(2026, 11, 1)) == [forgotten["id"]]


def test_endorsement_gaps_reads_any_endorsement_list():
    """A real board's endorsements, recorded in the same shape, are read the same way."""
    a = {"id": "DEC-001", "decided_on": "2026-10-01", "review_by": "2027-10-01"}
    real = [{"decision": "DEC-001", "decidedOn": "2026-10-01", "endorsedAt": "2026-10-15", "by": "a real board"}]
    assert _drills.endorsement_gaps([a], real, date(2026, 11, 1)) == []
    early = [dict(real[0], endorsedAt="2026-09-01")]
    assert _drills.endorsement_gaps([a], early, date(2026, 11, 1)) == ["DEC-001"]


def test_known_bad_the_board_refuses_a_lapsed_acceptance():
    lapsed = {"id": "DEC-900", "title": "t", "decided_on": "2025-01-01", "review_by": "2026-01-01"}
    new, refused = _drills.endorse([lapsed], date(2026, 11, 1), set())
    assert not new and refused[0]["decision"] == "DEC-900"


def test_a_planted_case_not_caught_fails_the_board(monkeypatch):
    monkeypatch.setattr(_drills, "endorsement_gaps", lambda accepts, e, m: [])
    checks, _, _ = _meeting()
    assert {c["id"]: c["result"] for c in checks}["planted-forgotten-acceptance"] == "fail"


# --- The CFO (KSI-PIY-RIS) ----------------------------------------------------------------

def _costs():
    return hold._costs(REPO)


def test_the_committed_costs_fund_every_method_within_the_ceiling():
    checks, record = _drills.cfo_review(_ksi_methods.load(), _costs())
    assert all(c["result"] == "pass" for c in checks), checks
    assert record["knownUsdPerYear"] <= record["ceiling"]["usd_per_year"]


def test_known_bad_the_cfo_refuses_an_unfunded_mechanism():
    costs = copy.deepcopy(_costs())
    for line in costs["lines"]:
        line["funds"] = [k for k in line.get("funds", []) if k != "phishing-drill"]
    checks, record = _drills.cfo_review(_ksi_methods.load(), costs)
    funded = next(c for c in checks if c["id"] == "funded")
    assert funded["result"] == "fail" and "phishing-drill" in funded["detail"]


def test_known_bad_a_total_over_the_ceiling_fails():
    costs = copy.deepcopy(_costs())
    costs["ceiling"] = {"usd_per_year": 1, "basis": "t"}
    checks, _ = _drills.cfo_review(_ksi_methods.load(), costs)
    assert {c["id"]: c["result"] for c in checks}["ceiling"] == "fail"


# --- Choose-Your-Own-Disaster (KSI-INR-RIR, KSI-RPL-ARP, KSI-INR-AAR) -------------------------

def test_every_real_tabletop_card_maps_each_step_to_a_runbook_section():
    for card in _drills.DECK:
        steps = _drills.map_steps(card, IR, PLAN)
        assert all(s["section"] for s in steps), (card["card"], steps)


def test_known_bad_the_tabletop_flags_a_card_no_runbook_covers():
    steps = _drills.map_steps(_drills.ALIEN, IR, PLAN)
    assert any(s["section"] is None for s in steps)
    checks, record = _drills.tabletop(date(2026, 11, 1), IR, PLAN, DEC_IDS)
    assert all(c["result"] == "pass" for c in checks), checks
    assert record["planted"]["caught"] and record["planted"]["orphanCaught"]


def test_known_bad_a_runbook_that_lost_a_containment_entry_fails_the_tabletop():
    bad = (FIX / "incident-response-no-supply-chain.md").read_text()
    checks, _ = _drills.tabletop(date(2026, 11, 1), bad, PLAN, DEC_IDS)
    deck = next(c for c in checks if c["id"] == "deck")
    assert deck["result"] == "fail" and "Supply-chain compromise: contain" in deck["detail"]


def test_the_featured_card_rotates_monthly():
    assert _drills.draw(date(2026, 11, 1)) != _drills.draw(date(2026, 12, 1))


# --- the disclosure drill (KSI-PIY-RVD) ---------------------------------------------------

def test_a_complete_report_is_accepted_with_an_acknowledgement_clock():
    out = _drills.intake(_drills.ima_report(), NOW, 1)
    assert out["triage"] == "accepted" and out["finding"]["tracking_id"] == "DISC-2026-11-06-1"
    assert out["acknowledgeBy"] == "2026-11-12"  # three business days after a Friday, Veterans Day skipped


def test_known_bad_an_incomplete_disclosure_report_is_triaged_needs_info():
    out = _drills.intake((FIX / "disclosure-no-repro.txt").read_text(), NOW, 2)
    assert out["triage"] == "needs-info" and out["finding"] is None and out["missing"] == ["Steps to reproduce"]


def test_a_report_about_another_system_is_out_of_scope():
    text = _drills.ima_report().replace("https://samaydlette.com/favicon.ico", "https://example.org/")
    assert _drills.intake(text, NOW, 3)["triage"] == "out-of-scope"


# --- the phishing drill (KSI-CED-RAT) -----------------------------------------------------

def test_the_rules_find_the_lures_indicators_and_none_in_the_control():
    assert set(_phishing.detect(_phishing.lure())) == set(_phishing.INDICATORS)
    assert _phishing.detect(_phishing.control()) == []


def test_known_bad_a_click_fails_and_assigns_the_remedial_lesson():
    found = _phishing.detect(_phishing.lure())
    assert _phishing.grade("reported", found)["grade"] == "pass"
    clicked = _phishing.grade("clicked", found)
    lesson = clicked["remedial"]
    assert clicked["grade"] == "fail" and lesson is not None
    pkt = _training.packet(REG, {"incidents": []}, 1, 1, NOW.date())
    assert lesson["covers"] in {x["covers"] for x in pkt["lessons"]}


def test_pat_clicks_every_nth_drill():
    assert [_phishing.respond(n) for n in range(1, 5)] == ["reported"] * 3 + ["clicked"]
    checks, record = _phishing.drill(4)
    assert all(c["result"] == "pass" for c in checks) and record["grade"]["grade"] == "fail"


# --- the incident log's checks (KSI-INR-AAR, KSI-INR-RPI) ----------------------------------

def test_the_committed_register_passes_the_after_action_check():
    out = _incidents.lessons_check(_incidents.load(), DEC_IDS)
    assert out["result"] == "pass" and out["resolved"] == 2 and out["planted"]["caught"]


def test_known_bad_an_orphan_lesson_fails_the_after_action_check():
    reg = _incidents.load(FIX / "incidents-orphan-lesson.json")
    out = _incidents.lessons_check(reg, DEC_IDS)
    assert out["result"] == "fail" and out["failing"] == ["INC-2026-002"]
    assert "DEC-000 is not in the decision register" in out["incidents"][1]["problems"][0]


def test_known_bad_a_resolved_incident_without_lessons_fails():
    reg = copy.deepcopy(_incidents.load())
    del reg["incidents"][0]["lessons_learned"]
    assert _incidents.lessons_check(reg, DEC_IDS)["failing"] == ["INC-2026-001"]


def test_known_bad_three_stale_caches_are_a_recurrence():
    out = _incidents.groundhog_day(_incidents.load(), NOW.date())
    assert out["result"] == "pass" and out["planted"]["caught"]
    seeded = _incidents.patterns(_incidents.seeded_incidents(NOW.date()), NOW.date())
    assert len(seeded["recurring"]) == 1 and len(seeded["recurring"][0]["incidents"]) == 3


def test_exercises_never_make_a_pattern():
    assert _incidents.patterns(_incidents.load()["incidents"], NOW.date())["groups"] == []


def test_real_incidents_with_one_root_cause_open_a_process_finding():
    reg = _incidents.load(FIX / "incidents-recurring.json")
    rec = _incidents.patterns(reg["incidents"], NOW.date())["recurring"]
    assert [r["incidents"] for r in rec] == [["INC-2026-003", "INC-2026-004"]]
    found = _evaluation.process_findings([], [], rec)
    assert [f["tool_id"] for f in found] == ["incident.recurrence"]
    assert found[0]["source"] == "process" and found[0]["detected_at"] == "2026-10-01T10:00:00Z"


def test_the_incident_log_publishes_both_checks(tmp_path):
    build = _load("build_incident_report_drills_t", "build-incident-report.py")
    log = build.build(_incidents.load(now=NOW), None, NOW, tmp_path)
    assert log["lessons_learned"]["result"] == "pass" and log["patterns"]["planted"]["caught"]
    assert "Lessons learned (KSI-INR-AAR)" in (tmp_path / "incident-reports.md").read_text()


# --- security.txt (KSI-PIY-RVD) -----------------------------------------------------------

def test_the_committed_security_txt_is_valid():
    out = scc.security_txt((REPO / "website" / ".well-known" / "security.txt").read_text(), NOW)
    assert out["result"] == "pass", out


@pytest.mark.parametrize("name,failing", [("security-txt-expired.txt", {"contact", "expires"}),
                                          ("security-txt-too-far.txt", {"expires"})])
def test_known_bad_security_txt_fails(name, failing):
    out = scc.security_txt((FIX / name).read_text(), NOW)
    assert out["result"] == "fail" and {c["id"] for c in out["checks"] if not c["ok"]} == failing


# --- hold-drill.py end to end ---------------------------------------------------------------

@pytest.mark.parametrize("key", sr.DRILLS)
def test_each_drill_is_held_published_and_screened(key, tmp_path):
    index, entries, files, failed = hold.run(key, {}, tmp_path, NOW, "TEST-ID")
    assert not failed and [e["dueDate"] for e in entries] == ["2026-11-01"]
    doc = json.loads((tmp_path / files[0]).read_text())
    assert doc["result"] == "pass" and doc["late"] and doc["simulated"]
    assert _engagement.carries_statement(doc) and _engagement.names_simulated(doc)
    assert any(c["id"].startswith("planted") for c in doc["checks"])
    assert (tmp_path / files[0].replace(".json", ".view.md")).is_file()
    assert (tmp_path / sr.REVIEWS[key].index).is_file()
    # the method verifier counts it
    assert _ksi_methods.CHECKS[key](index, NOW) == (True, None)


def test_known_bad_a_failing_drill_is_not_written_and_fails_the_run(tmp_path, monkeypatch):
    monkeypatch.setattr(_phishing, "PASS_MARK", 99)
    index, entries, files, failed = hold.run("phishing-drill", {}, tmp_path, NOW, "TEST-ID")
    assert failed == [date(2026, 11, 1)] and not files and index["reviews"] == []
    with pytest.raises(SystemExit, match="did not pass"):
        hold.main(["--review", "phishing-drill", "--out", str(tmp_path), "--now", NOW.isoformat()])


def test_known_bad_no_drill_after_its_due_date_fails_the_overdue_check():
    assert chk.problems("tabletop", {}, date(2026, 11, 2)) == ["Choose-Your-Own-Disaster tabletop due 2026-11-01 "
                                                               "is not published"]


def test_board_endorsements_carry_forward_in_the_index(tmp_path):
    first, *_ = hold.run("board-meeting", {}, tmp_path, NOW, "TEST-ID")
    later = datetime(2027, 2, 2, tzinfo=timezone.utc)
    second, entries, _, failed = hold.run("board-meeting", first, tmp_path, later, "TEST-ID")
    assert not failed and [e["dueDate"] for e in entries] == ["2027-02-01"]
    assert len(second["endorsements"]) >= len(first["endorsements"]) > 0


def test_the_nightly_holds_publishes_and_checks_every_drill():
    wf = (REPO / ".github" / "workflows" / "evidence-nightly.yml").read_text()
    assert "- name: Hold the drills when due (simulated participants)" in wf
    for key in sr.DRILLS:
        stem = sr.REVIEWS[key].index[:-5]
        assert wf.count(stem) >= 5, stem
    assert 'python3 scripts/check-scheduled-review.py --review "$key"' in wf


def test_the_deploy_and_maintainer_pass_every_published_method_record():
    table = _ksi_methods.published_keys(_ksi_methods.load())
    for wf in ("deploy-with-opa.yml", "package-maintenance.yml"):
        text = (REPO / ".github" / "workflows" / wf).read_text()
        for key, name in table.items():
            assert f"{key}:{name[:-5]}" in text, (wf, key)
