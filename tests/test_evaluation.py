"""The evaluation record (VER-EVA-*) and the decisions that read it.

N0 for a fully mitigated finding (VER-EVA-EPA); a group evaluated at its most
exposed member, with one clock (VER-EVA-GRV); early acceptance when the
projected remediation is past the maximum period (VER-TFR-MAV); evaluation
time (VER-TFR-EVU); the automatable assumption (VER-EVA-AIA); the exploitation
assessment (VDR-CSO-RES); the disclosure determination and the redaction it
drives (VER-RPT-NID, VER-RPT-RPD).
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "tests" / "fixtures" / "triage"))
import _evaluation  # noqa: E402
import _rules  # noqa: E402
import _triage  # noqa: E402
import golden_cases  # noqa: E402

NOW = golden_cases.NOW
NS = _triage.to_ns(NOW)
DAY = 86400 * 10**9
FIX = REPO / "tests" / "fixtures" / "evaluation"
FLOOR = {"AV": "N", "PR": "N", "UI": "N", "C": "H", "I": "N", "A": "N"}


def item(**kw):
    base = {"id": "f1", "kind": "finding", "pain": "N2", "is_kev": False, "exploitation": None, "metrics": FLOOR,
            "epss": None, "fully_mitigated": False,
            "reach": {"observed": False, "component_id": "c", "is_package": False, "declared": True},
            "mitigation": None, "check_decision": None, "register": None, "advisory": "CVE-0000-0001",
            "resource": "r", "fix_state": None, "clock": {"start_ns": NS, "first_evaluated_ns": NS}}
    base.update(kw)
    return base


def decide(items, **kw):
    return _triage.decide(items, now=NOW, epss_threshold=0.1, margin_days=5, lev_overrides=None,
                          evaluation_days=kw.get("evaluation_days"))


# --- VER-EVA-EPA: N0 ---------------------------------------------------------------

def test_fully_mitigated_takes_n0_from_the_rules_scale():
    d = decide([item(fully_mitigated=True, pain="N4")])[0]
    assert d["pain"] == "N0" and d["sla_days"] is None and d["needs_remediation"] is False


# --- VER-EVA-GRV: the group is the unit ------------------------------------------------

def _group_items():
    fx = json.loads((FIX / "group-overdue.json").read_text())
    old_ns = NS - fx["old_days"] * DAY
    old, new = fx["items"]
    return [item(id=old["id"], group=old["group"], clock={"start_ns": old_ns, "first_evaluated_ns": old_ns}),
            item(id=new["id"], group=new["group"])]


def test_known_bad_new_instance_of_an_old_group_is_on_the_groups_clock_and_blocks():
    old, new = decide(_group_items())
    assert old["sla_days"] == 48 and old["is_overdue"] and old["block_rule"] == "past-deadline"
    assert new["due_ns"] > NS and new["group_due_ns"] == old["due_ns"]
    assert new["is_overdue"] is True and new["blocking"] and new["block_rule"] == "past-deadline"


def test_without_a_group_the_new_instance_is_on_its_own_clock():
    items = _group_items()
    for i in items:
        i.pop("group")
    assert decide(items)[1]["blocking"] is False


def test_group_is_evaluated_at_its_most_exposed_open_member():
    a = item(id="a", group="g", pain="N2", reach={"observed": False, "component_id": "c", "is_package": False,
                                                   "declared": False})
    b = item(id="b", group="g", pain="N3")
    da, db = decide([a, b])
    assert da["irv"] is False and da["group_irv"] is True and da["group_pain"] == "N3"
    assert da["group_due_ns"] == db["due_ns"]


def test_a_closed_member_does_not_set_the_groups_rating():
    closed = item(id="c", group="g", pain="N5", fully_mitigated=True)
    d = decide([closed, item(id="o", group="g", pain="N2")])
    assert d[1]["group_pain"] == "N2"


# --- VER-TFR-MAV: will not be remediated in time ------------------------------------------

def test_projected_remediation_past_the_maximum_period_is_accepted_now():
    late = NS + 200 * DAY
    d = decide([item(projected_ns=late)])[0]
    assert d["accepted"] is True and d["accepted_basis"] == "projected-past-maximum-period"
    ok = decide([item(projected_ns=NS + 30 * DAY)])[0]
    assert ok["accepted"] is False and ok["accepted_basis"] is None


def test_a_closed_finding_is_never_accepted_early():
    d = decide([item(projected_ns=NS + 400 * DAY, fully_mitigated=True)])[0]
    assert d["accepted"] is False


# --- VER-TFR-EVU ----------------------------------------------------------------------------

def test_evaluation_days_come_from_the_rules():
    assert _rules.evaluation_days() == 5


def test_evaluated_more_than_five_days_after_detection_is_late():
    d = decide([item(detected_ns=NS - 9 * DAY)], evaluation_days=5)[0]
    assert d["evaluation_late"] == "evaluated-late"
    assert decide([item(detected_ns=NS - 2 * DAY)], evaluation_days=5)[0]["evaluation_late"] is None


def test_a_decision_before_the_pipeline_saw_it_counts_as_the_evaluation():
    d = decide([item(detected_ns=NS - 9 * DAY, evaluated_ns=NS - 8 * DAY)], evaluation_days=5)[0]
    assert d["evaluation_late"] is None


def test_still_on_a_default_after_the_window_is_late():
    it = item(metrics={}, default_evaluation=True, detected_ns=NS - 6 * DAY,
              clock={"start_ns": NS - 6 * DAY, "first_evaluated_ns": NS - 6 * DAY})
    assert decide([it], evaluation_days=5)[0]["evaluation_late"] == "default-after-evaluation-window"


def test_no_evaluation_days_no_check():
    assert decide([item(detected_ns=NS - 90 * DAY)])[0]["evaluation_late"] is None


# --- VER-EVA-AIA ------------------------------------------------------------------------------

def test_automatable_by_default():
    assert _evaluation.automatable({}, {})["value"] == "yes"


def test_only_a_decision_with_evidence_says_not_automatable():
    dec = {"id": "DEC-999", "automatable": {"value": "no", "evidence": "needs a physical token"}}
    assert _evaluation.automatable({}, dec) == {"value": "no", "source": "decision DEC-999",
                                                "evidence": "needs a physical token"}
    assert _evaluation.automatable({}, {"id": "DEC-998", "automatable": {"value": "no"}})["value"] == "yes"


def test_cvss4_automatable_is_read():
    v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/AU:N"
    assert _evaluation.automatable({"cvss_vector": v}, {})["value"] == "no"


# --- VDR-CSO-RES -------------------------------------------------------------------------------

def test_an_incident_naming_the_finding_makes_exploitation_active():
    f = {"tracking_id": "grype-CVE-2099-1-x", "cve": "CVE-2099-1"}
    inc = [{"id": "INC-001", "vulnerability": {"cve": "CVE-2099-1"}}]
    assert _evaluation.exploitation(f, False, inc, "t")["value"] == "active"
    none = _evaluation.exploitation(f, False, [], "t")
    assert none["value"] == "none-observed" and _evaluation.EXPLOITATION_POLICY in none["basis"]


# --- VER-RPT-NID / RPD -------------------------------------------------------------------------

def _row(**kw):
    r = {"final_disposition": "open", "internet_reachable": True, "likely_exploitable": True, "pain": "N3",
         "fully_mitigated": False, "description": "how to exploit it", "locations": ["https://x/p"],
         "fix_versions": ["1.2.3"], "supplementary_info": "", "tracking_id": "t"}
    r.update(kw)
    return r


def test_open_irv_lev_n3_is_summarized_and_redacted():
    r = _row()
    r["public_disclosure"] = _evaluation.disclosure(r)
    assert r["public_disclosure"]["level"] == "summary"
    pub = _evaluation.redact(r)
    assert "how to exploit" not in json.dumps(pub)
    assert pub["locations"] is None and pub["fix_versions"] is None
    assert pub["tracking_id"] == "t" and pub["pain"] == "N3"


def test_dispositioned_or_lower_rated_findings_are_disclosed_in_full():
    for kw in ({"final_disposition": "false-positive"}, {"pain": "N2"}, {"internet_reachable": False},
               {"likely_exploitable": False}):
        r = _row(**kw)
        r["public_disclosure"] = _evaluation.disclosure(r)
        assert r["public_disclosure"]["level"] == "full", kw
        assert _evaluation.redact(r) == r


def test_the_policies_named_are_in_force_in_the_register():
    import _decisions
    live = {r["id"] for r in _decisions.in_force(_decisions.load())}
    assert {_evaluation.EXPLOITATION_POLICY, _evaluation.DISCLOSURE_POLICY} <= live


# --- grouping keys ----------------------------------------------------------------------------

def test_group_keys():
    assert _evaluation.group_key({"cve": "CVE-1"}, "DEC-1") == "cve:CVE-1"
    assert _evaluation.group_key({"source": "checkov", "tool_id": "CKV_1"}, "DEC-1") == "decision:DEC-1"
    assert _evaluation.group_key({"source": "checkov", "tool_id": "CKV_1"}, None) == "check:checkov:CKV_1"


# --- VER-EVA-EIR: a site root resolves to the page it serves -----------------------------------

def test_a_site_root_resolves_to_its_index_page():
    import importlib.util
    spec = importlib.util.spec_from_file_location("vdr_eval", REPO / "scripts" / "build-vdr-report.py")
    vdr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vdr)
    index = {"https://example.test/index.html": "html::index.html"}
    assert vdr.resolve_component({"resource": "https://example.test"}, index) == "html::index.html"
    assert vdr.resolve_component({"resource": "https://example.test/"}, index) == "html::index.html"
    assert vdr.resolve_component({"resource": "https://example.test/x"}, index) is None


# --- VDR-CSO-FAV: failures are vulnerabilities ------------------------------------------------

def test_a_detect_and_recover_event_becomes_one_process_finding_per_check():
    ev = [{"check": "runtime-divergence.observer-fault", "gate": "G7", "mode": "detect-and-recover",
           "detail": "observer unreachable", "at": "2026-11-05T01:00:00+00:00"}] * 2
    out = _evaluation.process_findings(ev, [])
    assert [f["tracking_id"] for f in out] == ["process-runtime-divergence.observer-fault"]
    assert out[0]["source"] == "process" and out[0]["detected_at"] == "2026-11-05T01:00:00+00:00"


def test_a_finding_on_a_default_past_the_window_becomes_a_process_finding():
    rows = [{"tracking_id": "t1", "source": "checkov", "evaluation_late": "default-after-evaluation-window"},
            {"tracking_id": "t2", "source": "checkov", "evaluation_late": "evaluated-late"},
            {"tracking_id": "t3", "source": "checkov", "evaluation_late": None}]
    assert [f["tracking_id"] for f in _evaluation.process_findings([], rows)] == ["process-evaluation-t1"]


def test_stopped_runs_on_main_since_the_previous_report_are_listed_without_ids():
    runs = [{"workflowName": "Evidence Nightly (VDR refresh)", "createdAt": "2026-11-05T07:17:00Z",
             "updatedAt": "2026-11-05T07:40:00Z", "event": "schedule", "headBranch": "main", "databaseId": 1},
            {"workflowName": "Evidence Nightly (VDR refresh)", "createdAt": "2026-11-01T07:17:00Z",
             "headBranch": "main"},
            {"workflowName": "Some PR check", "createdAt": "2026-11-05T08:00:00Z", "headBranch": "main"},
            {"workflowName": "ZAP DAST Scan", "createdAt": "2026-11-05T09:00:00Z", "headBranch": "feature"}]
    out = _evaluation.failed_runs(runs, "2026-11-04T19:00:00+00:00")
    assert len(out) == 1 and out[0]["failed_at"] == "2026-11-05T07:17:00Z"
    assert "databaseId" not in json.dumps(out) and "1" != out[0].get("id")


def test_the_deploy_and_nightly_pass_failed_runs_to_the_vdr_build():
    for wf in ("deploy-with-opa.yml", "evidence-nightly.yml"):
        t = (REPO / ".github" / "workflows" / wf).read_text()
        assert "Collect failed pipeline runs (VDR-CSO-FAV)" in t and "--failed-runs failed-runs.json" in t, wf


def test_zap_age_is_not_floored_to_whole_days(tmp_path):
    import importlib.util
    from datetime import datetime, timezone
    spec = importlib.util.spec_from_file_location("vdr_age", REPO / "scripts" / "build-vdr-report.py")
    vdr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vdr)
    p = tmp_path / "zap.json"
    p.write_text(json.dumps({"@generated": "Mon, 2 Nov 2026 00:00:00"}))
    age = vdr.zap_report_age_days(p, datetime(2026, 11, 5, 21, 36, tzinfo=timezone.utc))
    assert age > 3  # 3.9 days: past a 3-day window


# --- VDR-TFR-PCD: detection coverage per component -------------------------------------------

def test_known_bad_components_no_technique_reached_this_month_are_uncovered():
    from datetime import datetime
    fx = json.loads((FIX / "coverage-gap.json").read_text())
    cov = _evaluation.coverage(fx["components"], fx["detection"], None, datetime.fromisoformat(fx["now"]))
    assert cov["uncovered"] == ["pkg:npm/a@1", "x::unknown::thing"]
    rows = {r["component_id"]: r for r in cov["components"]}
    assert rows["aws::object_store::site"]["last_detection"] == "2026-11-05T11:00:00+00:00"
    assert "external" in rows["ext::svc"] and cov["covered"] == 1


def test_a_fresh_feed_covers_its_components():
    from datetime import datetime
    fx = json.loads((FIX / "coverage-gap.json").read_text())
    fx["detection"]["feeds"][0]["source_date"] = "2026-11-04T00:00:00+00:00"
    cov = _evaluation.coverage(fx["components"], fx["detection"], None, datetime.fromisoformat(fx["now"]))
    assert cov["uncovered"] == ["x::unknown::thing"]


def test_coverage_and_unresolved_components_are_governed_detect_and_recover_checks():
    import _gates
    reg = _gates.load_gate_modes()
    for check in ("vdr.coverage", "vdr.unresolved-component"):
        assert _gates.mode_of(reg, check) == "detect-and-recover" and reg["checks"][check]["reason"]


def test_an_unresolved_finding_becomes_a_process_finding_in_the_build(tmp_path):
    import os
    import shutil
    import subprocess
    work = tmp_path / "w"
    shutil.copytree(REPO / "tests" / "fixtures" / "gates" / "g3-past-deadline", work)
    g = json.loads((work / "grype.json").read_text())
    g["matches"][0]["artifact"].update(name="zzz", version="9", purl="pkg:npm/zzz@9")
    (work / "grype.json").write_text(json.dumps(g))
    env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_ACTIONS", "GATE_EVENTS_FILE")}
    subprocess.run([sys.executable, str(REPO / "scripts" / "build-vdr-report.py"),
                    "--grype", "grype.json", "--kev", "kev.json", "--previous-vdr", "previous-vdr.json",
                    "--ksi-signal", "ksi-signal.json", "--checkov-yaml", "absent.yaml", "--opa", "absent.json",
                    "--md-output", "", "--output", "out.json"], cwd=work, capture_output=True, text=True, env=env)
    rep = json.loads((work / "out.json").read_text())
    proc = [f for f in rep["findings"] if f["source"] == "process"]
    assert [f["tracking_id"] for f in proc] == ["process-vdr.unresolved-component"]
    assert proc[0]["remediation_due_at"] and rep["summary"]["unresolved_components"] == 1
    assert "coverage" in rep


def test_the_vdr_carries_the_runtime_run_history_only_from_a_verified_signal():
    import importlib.util
    spec = importlib.util.spec_from_file_location("vdr_rt", REPO / "scripts" / "build-vdr-report.py")
    vdr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vdr)
    hist = [{"signal_id": "a", "emitted_at": "2026-11-05T01:00:00Z", "validations": 3, "failed": 0}]
    ok = vdr.runtime_verification_summary({"verified": True, "validations": [], "run_history": hist})
    assert ok["run_history"][0]["signal_id"] == "a"
    bad = vdr.runtime_verification_summary({"verified": False, "run_history": hist})
    assert "run_history" not in bad
