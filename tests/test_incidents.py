"""Incident evaluation and reporting (IEC-CSO-EFR/DPR/EFI/IIR/OIR/FIR/AIR,
VER-TFR-IRI, VER-TFR-NRI).

- the register (data/incidents.json) loads, matches its schema, and every
  known-bad register fails closed for its own reason;
- the Class C report clocks and the Incident Rating scale are read from the
  pinned FedRAMP rules, and a changed rule fails closed;
- the clocks: default N5 until estimated (DPR), the IIR/OIR/FIR deadlines,
  business days, overdue detection;
- the exercise runs end to end, IIR -> OIR -> FIR, every report validates
  against FedRAMP's schema, restates every earlier item and was on time;
- a VDR finding that VER-TFR-IRI/NRI makes reportable with no incident is due
  an Initial report, and the clock check fails once it is late;
- reconciliation invariant (m) and the unattended reporting workflow.
"""

import copy
import hashlib
import importlib.util
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _fedramp_schema as fs  # noqa: E402
import _incidents  # noqa: E402
import _rules  # noqa: E402

FIX = REPO / "tests" / "fixtures" / "incidents"
REGISTER = REPO / "data" / "incidents.json"
SCHEMA = REPO / "infrastructure" / "schemas" / "incidents.schema.json"
RULES_DIR = REPO / "infrastructure" / "schemas" / "fedramp-rules"
WF = REPO / ".github" / "workflows"
NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


bir = _load("bir", "scripts/build-incident-report.py")
rec = _load("rec_incidents", "scripts/reconcile.py")


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def good():
    return json.loads((FIX / "good.json").read_text())


# ---- the register ----------------------------------------------------------------

def test_the_committed_register_loads_and_matches_its_schema():
    _incidents.load(REGISTER, now=datetime.now(timezone.utc))
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(json.loads(REGISTER.read_text()), json.loads(SCHEMA.read_text()))
    jsonschema.validate(good(), json.loads(SCHEMA.read_text()))


def test_the_committed_register_adopts_both_vulnerability_rules_and_publishes_only():
    """docs/policies/ir-policy.md adopts VER-TFR-NRI (a MAY) and IRI; nothing is sent."""
    p = json.loads(REGISTER.read_text())["policy"]
    assert set(p["adopted_vulnerability_rules"]) == {"VER-TFR-IRI", "VER-TFR-NRI"}
    assert p["notification"] == "published-only"
    assert "not authorized" in p["notification_text"]


BAD = {
    "not-evaluated": "evaluation must have exactly",
    "empty-reason": "reason must be a non-empty string",
    "rating-off-rubric": "is N3 under IEC-CSO-EFI",
    "first-not-initial": "first report is the Initial Incident Report",
    "initial-without-description": "must describe the incident",
    "final-before-recovery": "needs resolved_at and recovery_complete_at",
    "final-not-last": "nothing follows the Final Incident Report",
    "not-reportable-with-report": "carries no rating or report",
    "vuln-basis-not-adopted": "is not an adopted rule",
    "vuln-basis-no-finding": "names no finding",
    "evaluated-before-detected": "evaluated before it was detected",
    "report-before-evaluation": "before the evaluation or the previous report",
    "notification-sends": "no other delivery is built",
    "personal-email": "names an email address outside",
    "unknown-field": "unknown field",
    "duplicate-id": "duplicate id",
    "future-report": "records a time after now",
}


def test_every_known_bad_fixture_is_listed():
    assert {p.stem for p in (FIX / "bad").glob("*.json")} == set(BAD)


@pytest.mark.parametrize("name,why", sorted(BAD.items()))
def test_each_known_bad_register_fails_closed_for_its_reason(name, why):
    _incidents.load(FIX / "good.json", now=NOW)  # the base it was made from is valid
    with pytest.raises(SystemExit) as exc:
        _incidents.load(FIX / "bad" / f"{name}.json", now=NOW)
    assert why in str(exc.value), str(exc.value)


@pytest.mark.parametrize("name", ["not-evaluated", "empty-reason", "notification-sends", "unknown-field"])
def test_the_schema_refuses_the_structural_ones(name):
    jsonschema = pytest.importorskip("jsonschema")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(json.loads((FIX / "bad" / f"{name}.json").read_text()), json.loads(SCHEMA.read_text()))


def test_a_missing_or_unparseable_register_fails_closed(tmp_path):
    with pytest.raises(SystemExit):
        _incidents.load(tmp_path / "absent.json")
    (tmp_path / "x.json").write_text("{")
    with pytest.raises(SystemExit):
        _incidents.load(tmp_path / "x.json")


# ---- rules as data --------------------------------------------------------------

def _corpus():
    return json.loads((RULES_DIR / "fedramp-consolidated-rules.json").read_text())


def test_report_clocks_equal_the_pinned_rules():
    cso = _corpus()["FRR"]["IEC"]["data"]["all"]["CSO"]
    got = _rules.incident_report_timeframes(RULES_DIR)
    for kind, rid in (("iir", "IEC-CSO-IIR"), ("oir", "IEC-CSO-OIR"), ("fir", "IEC-CSO-FIR")):
        table = cso[rid]["varies_by_class"]["c"]["pain_timeframes"]
        assert got[kind] == {int(n): (c[kind]["timeframe_type"], c[kind]["timeframe_num"]) for n, c in table.items()}
    # The Class C values the reports rely on, as published on 2026-06-24.
    assert got["iir"][5] == ("hours", 1) and got["oir"][5] == ("hours", 6) and got["fir"][1] == ("bizdays", 1)


def test_rating_scale_and_default_come_from_the_rules():
    rubric = _rules.incident_rating_rubric(RULES_DIR)
    assert rubric[("debilitating", "multiple")] == 5 and rubric[("disruptive", "multiple")] == 4
    assert rubric[("debilitating", "single")] == 4 and rubric[("minimal", "single")] == 1
    assert _rules.default_incident_rating(RULES_DIR) == 5


def test_no_clock_is_typed_into_the_incident_code():
    for rel in ("scripts/_incidents.py", "scripts/build-incident-report.py"):
        src = (REPO / rel).read_text()
        assert not re.search(r"timedelta\(hours=(1|6|24)\)", src), rel


def _mutated_rules(tmp_path, mutate):
    d = tmp_path / "rules"
    d.mkdir()
    corpus = _corpus()
    mutate(corpus)
    raw = json.dumps(corpus).encode()
    (d / "fedramp-consolidated-rules.json").write_bytes(raw)
    src = json.loads((RULES_DIR / "SOURCES.json").read_text())
    src["sha256"] = hashlib.sha256(raw).hexdigest()
    (d / "SOURCES.json").write_text(json.dumps(src))
    return d


def test_a_changed_rating_scale_fails_closed(tmp_path):
    def drop(c):
        c["FRR"]["IEC"]["data"]["all"]["CSO"]["IEC-CSO-EFI"]["following_information_bullets"].pop()
    with pytest.raises(SystemExit, match="does not rate every customer effect"):
        _rules.incident_rating_rubric(_mutated_rules(tmp_path, drop))


def test_a_missing_report_clock_fails_closed(tmp_path):
    def drop(c):
        c["FRR"]["IEC"]["data"]["all"]["CSO"]["IEC-CSO-OIR"]["varies_by_class"]["c"]["pain_timeframes"]["5"] = {}
    with pytest.raises(SystemExit, match="IEC-CSO-OIR Class C N5 oir"):
        _rules.incident_report_timeframes(_mutated_rules(tmp_path, drop))


# ---- clocks (IEC-CSO-DPR, IIR, OIR, FIR) ------------------------------------------

TF = _rules.incident_report_timeframes(RULES_DIR)


def _open(evaluated="2026-11-02T10:00:00Z", reports=(), estimates=()):
    inc = copy.deepcopy(good()["incidents"][0])
    inc["evaluation"]["evaluated_at"] = evaluated
    inc["reports"] = list(reports)
    inc["estimates"] = list(estimates)
    return inc


def test_an_unrated_incident_is_n5_and_its_initial_report_is_due_in_an_hour():
    inc = _open()
    assert _incidents.rating_at(inc, ts("2026-11-02T10:00:00Z"), 5) == (5, "default (IEC-CSO-DPR)")
    (o,) = _incidents.obligations(inc, TF, 5, ts("2026-11-02T10:30:00Z"))
    assert o["report"] == "Initial" and o["due_at"] == "2026-11-02T11:00:00+00:00" and not o["overdue"]
    (o,) = _incidents.obligations(inc, TF, 5, ts("2026-11-02T11:01:00Z"))
    assert o["overdue"]


def test_a_prompt_estimate_replaces_the_default_and_its_clock():
    est = {"estimated_at": "2026-11-06T10:00:00Z", "rating": 1, "customer_effect": "minimal",
           "agencies": "single", "reason": "x"}
    # Evaluated on a Friday, rated N1 at once: one business day, so Monday.
    inc = _open(evaluated="2026-11-06T10:00:00Z", estimates=[est])
    (o,) = _incidents.obligations(inc, TF, 5, ts("2026-11-06T12:00:00Z"))
    assert o["due_at"] == "2026-11-09T10:00:00+00:00"


def test_business_days_skip_the_weekend():
    assert _incidents.add_clock(ts("2026-11-06T23:00:00Z"), "bizdays", 1) == ts("2026-11-09T23:00:00Z")
    assert _incidents.add_clock(ts("2026-11-04T08:00:00Z"), "bizdays", 1) == ts("2026-11-05T08:00:00Z")


def test_ongoing_reports_are_due_every_oir_period_until_resolved():
    reports = [{"type": "Initial", "at": "2026-11-02T10:30:00Z", "set": {"description": "d"}}]
    obs = _incidents.obligations(_open(reports=reports), TF, 5, ts("2026-11-02T17:00:00Z"))
    assert [o["report"] for o in obs] == ["Initial", "Ongoing"]
    assert obs[1]["due_at"] == "2026-11-02T16:30:00+00:00" and obs[1]["overdue"]


def test_the_final_report_is_due_after_recovery_and_ongoing_reports_stop():
    inc = _open(reports=[{"type": "Initial", "at": "2026-11-02T10:30:00Z", "set": {"description": "d"}}])
    inc["resolved_at"], inc["recovery_complete_at"] = "2026-11-02T12:00:00Z", "2026-11-02T13:00:00Z"
    obs = _incidents.obligations(inc, TF, 5, ts("2026-11-02T20:00:00Z"))
    assert [o["report"] for o in obs] == ["Initial", "Final"]
    assert obs[1]["due_at"] == "2026-11-02T19:00:00+00:00" and obs[1]["overdue"]


def test_a_not_reportable_incident_has_no_clock():
    inc = _open()
    inc["evaluation"]["reportable"] = False
    assert _incidents.obligations(inc, TF, 5, NOW) == []


# ---- the exercise, end to end (IIR -> OIR -> FIR) ---------------------------------

@pytest.fixture(scope="module")
def exercise(tmp_path_factory):
    out = tmp_path_factory.mktemp("incident-reports")
    reg = _incidents.load(REGISTER, now=ts("2026-11-05T19:00:00Z"))
    log = bir.build(reg, None, ts("2026-11-05T19:00:00Z"), out)
    return reg, log, out


def test_exercise_runs_initial_ongoing_final_all_on_time(exercise):
    _, log, _ = exercise
    inc = next(i for i in log["incidents"] if i["id"] == "INC-2026-001")
    assert inc["exercise"] is True and inc["status"] == "closed"
    assert [r["type"] for r in inc["reports"]] == ["Initial", "Ongoing", "Ongoing", "Final"]
    assert [o["report"] for o in inc["obligations"]] == ["Initial", "Ongoing", "Ongoing", "Final"]
    assert all(o["on_time"] for o in inc["obligations"])
    assert log["obligations_due"] == [] and log["clock_status"] == "ok"


def test_exercise_shows_the_default_rating_then_the_estimate(exercise):
    _, log, out = exercise
    initial = json.loads((out / "incident-INC-2026-001-01-initial.json").read_text())
    final = json.loads((out / "incident-INC-2026-001-04-final.json").read_text())
    assert initial["potentialImpact"]["currentRating"] == 5
    assert "IEC-CSO-DPR" in initial["potentialImpact"]["evaluationNotes"]
    assert final["potentialImpact"]["historicalRating"] == [5, 3] and final["potentialImpact"]["currentRating"] == 3
    assert initial["incidentDescription"].startswith("EXERCISE")


def test_exercise_logs_a_not_reportable_evaluation_with_its_reason(exercise):
    _, log, _ = exercise
    inc = next(i for i in log["incidents"] if i["id"] == "INC-2026-002")
    assert inc["status"] == "not-reportable" and inc["reports"] == [] and inc["rating"] is None
    assert "not federal customer data" in inc["evaluation"]["reason"]


def test_every_report_validates_against_fedramps_schema_and_is_listed_with_its_hash(exercise):
    _, log, out = exercise
    files = sorted(p.name for p in out.glob("incident-INC-*.json"))
    listed = [r for i in log["incidents"] for r in i["reports"]]
    assert sorted(r["file"] for r in listed) == files
    for r in listed:
        doc = json.loads((out / r["file"]).read_text())
        assert fs.validate(doc, "incident") == []
        assert hashlib.sha256((out / r["file"]).read_bytes()).hexdigest() == r["sha256"]


def test_ongoing_and_final_reports_restate_every_earlier_item(exercise):
    _, log, out = exercise
    inc = next(i for i in log["incidents"] if i["id"] == "INC-2026-001")
    first = json.loads((out / inc["reports"][0]["file"]).read_text())
    for r in inc["reports"][1:]:
        doc = json.loads((out / r["file"]).read_text())
        assert set(first) <= set(doc), r["file"]
        # Every item is either updated or explicitly "no update".
        assert set(r["changes"].values()) <= {"updated", "no update"}, r["changes"]
    assert inc["reports"][2]["changes"]["root_cause"] == "no update"
    assert inc["reports"][2]["changes"]["response_and_recovery_activities"] == "updated"
    final = json.loads((out / inc["reports"][-1]["file"]).read_text())
    assert final["reportType"] == "Final" and final["resolvedAt"] == "2026-11-05T17:00:00Z"


def test_reports_are_deterministic_and_say_they_are_published_only(exercise, tmp_path):
    reg, log, out = exercise
    again = bir.build(reg, None, ts("2026-11-05T19:30:00Z"), tmp_path)
    for a, b in zip(log["incidents"], again["incidents"], strict=True):
        assert [r["sha256"] for r in a["reports"]] == [r["sha256"] for r in b["reports"]]
    md = (out / "incident-reports.md").read_text()
    assert "published-only" in md and "not authorized" in md and "(no update)" in md
    assert log["notification"]["mode"] == "published-only"


def test_the_cli_builds_and_checks(tmp_path):
    assert bir.main(["--incidents", str(REGISTER), "--out-dir", str(tmp_path),
                     "--now", "2026-11-05T19:00:00Z"]) == 0
    assert bir.main(["--check", str(tmp_path / "incident-reports.json"), "--now", "2026-11-05T19:00:00Z"]) == 0


# ---- vulnerabilities as incidents (VER-TFR-IRI / VER-TFR-NRI) ----------------------

pytestmark_opa = pytest.mark.skipif(shutil.which("opa") is None, reason="opa not available")


def _vdr(**patch):
    f = {"tracking_id": "grype-CVE-2099-0777-api", "cve": "CVE-2099-0777", "pain": "N4",
         "internet_reachable": True, "likely_exploitable": True, "fully_mitigated": False,
         "final_disposition": "open", "first_evaluated": "2026-11-02T10:00:00+00:00"}
    f.update(patch)
    return {"emitted_at": "2026-11-02T12:00:00+00:00", "report_id": "r", "findings": [f]}


def _empty_register(adopted=("VER-TFR-IRI", "VER-TFR-NRI")):
    reg = good()
    reg["incidents"] = []
    reg["policy"]["adopted_vulnerability_rules"] = list(adopted)
    return _incidents.validate(reg)


@pytestmark_opa
def test_an_irv_lev_n4_finding_with_no_incident_is_due_an_initial_report(tmp_path):
    log = bir.build(_empty_register(), _vdr(), ts("2026-11-02T10:30:00Z"), tmp_path)
    (t,) = log["vulnerability_triggers"]
    assert t["rule"] == "VER-TFR-IRI" and t["adopted"] and t["incident"] is None
    (d,) = log["obligations_due"]
    assert d["report"] == "Initial" and d["due_at"] == "2026-11-02T11:00:00+00:00" and not d["overdue"]
    assert bir.check(tmp_path / "incident-reports.json", ts("2026-11-02T10:59:00Z")) == 0
    assert bir.check(tmp_path / "incident-reports.json", ts("2026-11-02T11:01:00Z")) == 1


@pytestmark_opa
def test_an_nirv_lev_n5_finding_opens_under_nri_and_n4_does_not(tmp_path):
    log = bir.build(_empty_register(), _vdr(internet_reachable=False, pain="N5"), NOW, tmp_path)
    assert log["vulnerability_triggers"][0]["rule"] == "VER-TFR-NRI"
    log = bir.build(_empty_register(), _vdr(internet_reachable=False, pain="N4"), NOW, tmp_path)
    assert log["vulnerability_triggers"] == []


@pytestmark_opa
def test_a_partially_mitigated_finding_at_n3_is_no_longer_an_incident(tmp_path):
    log = bir.build(_empty_register(), _vdr(pain="N3"), NOW, tmp_path)
    assert log["vulnerability_triggers"] == [] and log["obligations_due"] == []


@pytestmark_opa
def test_an_unadopted_rule_is_shown_but_starts_no_clock(tmp_path):
    log = bir.build(_empty_register(adopted=("VER-TFR-IRI",)), _vdr(internet_reachable=False, pain="N5"),
                    NOW, tmp_path)
    assert log["vulnerability_triggers"][0]["adopted"] is False and log["obligations_due"] == []


@pytestmark_opa
def test_an_open_incident_naming_the_finding_covers_it(tmp_path):
    reg = good()
    reg["incidents"][0]["findings"] = ["CVE-2099-0777"]
    log = bir.build(_incidents.validate(reg), _vdr(), ts("2026-11-02T10:40:00Z"), tmp_path)
    assert log["vulnerability_triggers"][0]["incident"] == "INC-2026-101"
    assert [d["incident"] for d in log["obligations_due"]] == ["INC-2026-101"]  # its next Ongoing report


# ---- reconciliation (m) ----------------------------------------------------------

def _cr26_vdr():
    return json.loads((REPO / "tests" / "fixtures" / "cr26" / "vdr-report.json").read_text())


def test_reconcile_m_passes_when_every_named_finding_is_in_the_vdr():
    assert rec.check_m_incident_findings(_cr26_vdr(), _incidents.validate(good())) == []


def test_reconcile_m_fails_the_known_bad_register():
    reg = _incidents.load(FIX / "reconcile-m-bad.json")
    v = rec.check_m_incident_findings(_cr26_vdr(), reg)
    assert v == ["(m) incident INC-2026-101 names 'CVE-2099-9999', which is not in the VDR report"]


def test_reconcile_m_exempts_exercises_and_resolved_incidents():
    reg = json.loads((FIX / "reconcile-m-bad.json").read_text())
    reg["incidents"][0]["exercise"] = True
    assert rec.check_m_incident_findings(_cr26_vdr(), _incidents.validate(reg)) == []
    reg["incidents"][0]["exercise"] = False
    reg["incidents"][0]["resolved_at"] = "2026-11-02T11:00:00Z"
    assert rec.check_m_incident_findings(_cr26_vdr(), _incidents.validate(reg)) == []


def test_reconcile_m_holds_for_the_committed_register():
    assert rec.check_m_incident_findings(_cr26_vdr(), _incidents.load(REGISTER)) == []


# ---- the unattended reporting workflow (IEC-CSO-AIR) --------------------------------

def _wf():
    return (WF / "incident-reports.yml").read_text()


def test_air_workflow_runs_on_register_change_by_hand_and_on_a_schedule():
    yaml = pytest.importorskip("yaml")
    on = yaml.safe_load(_wf())[True]
    assert on["push"]["paths"] == ["data/incidents.json"] and on["push"]["branches"] == ["main"]
    assert "workflow_dispatch" in on and on["schedule"]


def test_air_workflow_validates_builds_signs_publishes_and_checks_the_clock_in_order():
    names = re.findall(r"^    - name: (.+)$", _wf(), re.M)
    order = ["Fetch and verify the published VDR report", "Build incident reports (IIR, OIR, FIR)",
             "Sign incident reports", "Publication redaction gate (no AWS account ID)",
             "Publish incident reports to /.well-known/",
             "Incident report clocks (fail when a report is due and missing)"]
    assert [n for n in names if n in order] == order


def test_air_workflow_writes_only_incident_objects_and_sends_nothing():
    text = _wf()
    keys = re.findall(r'--key "\.well-known/([^"]+)"', text)
    assert keys == ["$1"]
    puts = [p.strip('"') for p in re.findall(r"^\s*put (\S+) ", text, re.M)]
    assert puts and all(p.startswith(("incident-", "$f", "${f")) for p in puts), puts
    assert "for f in incident-INC-*.json; do" in text
    assert "environment: incident-reports" in text and "AWS_INCIDENT_REPORTS_ROLE_ARN" in text
    assert not re.search(r"\b(ses|sendmail|send-email|smtp)\b", text, re.I)
    assert "aws s3 sync" not in text and "aws s3 rm" not in text and not re.search(r"^\s*terraform ", text, re.M)


def test_air_role_is_scoped_to_incident_objects():
    tf = (REPO / "infrastructure" / "bootstrap" / "incident-reports.tf").read_text()
    assert '"arn:aws:s3:::${var.domain_name}/.well-known/incident-*"' in tf
    actions = set(re.findall(r'"((?:s3|cloudfront):[A-Za-z*]+)"', tf))
    assert actions == {"s3:PutObject", "cloudfront:CreateInvalidation"}
    assert 'environment:${var.incident_reports_environment}' in tf


def test_all_three_workflows_pin_the_same_opa():
    def pins(name):
        text = (WF / name).read_text()
        return {k: re.search(rf"^  {k}: (\S+)", text, re.M).group(1) for k in ("OPA_VERSION", "OPA_SHA256")}
    assert pins("incident-reports.yml") == pins("deploy-with-opa.yml") == pins("evidence-nightly.yml")


# ---- the Ongoing Certification Report's incident summary (CCM-OCR-AVL item 7) -------

def test_ocr_attests_none_when_only_exercises_are_recorded():
    ocr = _load("ocr_inc", "scripts/build-ocr.py")
    text = ocr.incident_summary(_incidents.load(REGISTER), "2026-08-01")
    assert text.startswith("No FedRAMP Reportable Incidents occurred") and "incident-reports.json" in text


def test_ocr_lists_a_real_reportable_incident_in_the_period():
    ocr = _load("ocr_inc2", "scripts/build-ocr.py")
    text = ocr.incident_summary(_incidents.validate(good()), "2026-08-01")
    assert text.startswith("1 FedRAMP Reportable Incident(s) this period: INC-2026-101 (open)")
    assert ocr.incident_summary(_incidents.validate(good()), "2026-11-03").startswith("No FedRAMP")
