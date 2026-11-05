"""CR26 vulnerability reports from the VDR report (scripts/build-cr26-vdr.py).

Pins:
- every VDR finding lands in exactly one of the VDT or the AVI, and the accepted
  ones are those FRD-ACV calls accepted (accepted / risk-accepted /
  operational-requirement decisions, and findings past VER-TFR-MAV);
- the AVI rationale is the decision record's justification; an accepted finding
  without one stops the build and writes nothing;
- every output validates against its vendored FedRAMP schema, here and under
  jsonschema;
- each record carries the joins the schemas have no field for (component, CVE,
  check, decision) under providerExtensions;
- report periods run from the previous report's end (VER-RPT-PER), and each
  period report summarizes the period's activity, linking the runtime results;
- records carry the historical rating and rating history, the decision's
  planned reduction (else the deadline), supplementary information from the
  decision, an overdue explanation about the overdue status, and a detection
  time from a decision that names the record;
- the history keeps a finding that left the VDR for a year, with a final
  disposition only from evidence, and carries closed decisions.
"""
import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "cr26"
SCRIPT = REPO / "scripts" / "build-cr26-vdr.py"
sys.path.insert(0, str(REPO / "scripts"))
import _decisions  # noqa: E402
import _fedramp_schema as fs  # noqa: E402

spec = importlib.util.spec_from_file_location("build_cr26_vdr", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

VDR = json.loads((FIX / "vdr-report.json").read_text())
REGISTER = _decisions.load(FIX / "decisions.json")
NOW = datetime(2026, 11, 5, 15, 0, tzinfo=timezone.utc)


def _build(vdr=VDR, prev_vdt=None, prev_avi=None, prev_mrh=None, now=NOW):
    return mod.build(vdr, REGISTER, prev_vdt, prev_avi, prev_mrh, now)


def _ids(records, accepted=False):
    return [(r["vulnerabilityDetail"] if accepted else r)["providerTrackingId"] for r in records]


def test_every_finding_lands_once_and_accepted_means_frd_acv():
    vdt, avi, _ = _build()
    active, accepted = _ids(vdt["vulnerabilities"]), _ids(avi["acceptedVulnerabilities"], True)
    every = [f["tracking_id"] for f in VDR["findings"]] + [r["tracking_id"] for r in VDR["risk_accepted"]]
    assert sorted(active + accepted) == sorted(every)
    assert not set(active) & set(accepted)
    assert set(accepted) == {"checkov-CKV_AWS_310-website",       # risk-accepted decision
                             "checkov-CKV_AWS_20-site",           # operational requirement
                             "dependabot-GHSA-xxxx-yyyy-zzzz",    # past VER-TFR-MAV
                             "CKV_AWS_68"}                        # suppressed check, risk-accepted


def test_the_rationale_is_the_decision_justification():
    _, avi, _ = _build()
    why = {a["vulnerabilityDetail"]["providerTrackingId"]: a["acceptanceRationale"]
           for a in avi["acceptedVulnerabilities"]}
    recs = _decisions.records(REGISTER)
    assert why["checkov-CKV_AWS_310-website"] == recs["DEC-101"]["justification"]
    assert why["checkov-CKV_AWS_20-site"] == recs["DEC-102"]["justification"]
    assert why["CKV_AWS_68"] == recs["DEC-104"]["justification"]
    assert why["dependabot-GHSA-xxxx-yyyy-zzzz"].startswith("Not remediated within 192 days")


def test_an_accepted_finding_without_a_justification_writes_nothing(tmp_path):
    vdr = json.loads(json.dumps(VDR))
    vdr["findings"][1]["decision_id"] = "DEC-999"
    (tmp_path / "vdr.json").write_text(json.dumps(vdr))
    r = subprocess.run([sys.executable, str(SCRIPT), "--vdr", str(tmp_path / "vdr.json"),
                        "--decisions", str(FIX / "decisions.json"), "--out-dir", str(tmp_path)],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "no decision justification" in r.stderr
    assert not list(tmp_path.glob("vdr-*"))


def test_dispositions_map_to_fedramp_final_dispositions():
    vdt, _, _ = _build()
    by = {r["providerTrackingId"]: r for r in vdt["vulnerabilities"]}
    assert by["zap-10099-article"]["finalDisposition"] == "False Positive"
    assert by["grype-CVE-2099-0002-api"]["finalDisposition"] == "Fully Mitigated"
    open_ = by["grype-CVE-2099-0001-thumbnailer"]
    assert "finalDisposition" not in open_
    assert open_["projectedNextReduction"] == {"estimatedAt": "2026-11-20T00:00:00+00:00", "targetRating": 0}
    assert open_["painReductionEvents"] == [{"reducedAt": "2026-10-14T10:00:00+00:00", "rating": 3}]
    assert open_["currentRating"] == 3 and open_["isInternetReachable"] and open_["isLikelyExploitable"]
    assert open_["supplementaryRiskInformation"].startswith("File preview")


def test_records_carry_the_joins_the_schemas_lack():
    vdt, avi, _ = _build()
    rec = next(r for r in vdt["vulnerabilities"] if r["providerTrackingId"] == "grype-CVE-2099-0001-thumbnailer")
    assert rec["providerExtensions"]["componentId"] == "pkg:npm/example-thumbnailer@3.1.0"
    assert rec["providerExtensions"]["cve"] == "CVE-2099-0001"
    assert rec["providerExtensions"]["isKev"] is True
    acc = next(a["vulnerabilityDetail"] for a in avi["acceptedVulnerabilities"]
               if a["vulnerabilityDetail"]["providerTrackingId"] == "checkov-CKV_AWS_310-website")
    assert acc["providerExtensions"]["decisionId"] == "DEC-101"
    assert acc["providerExtensions"]["componentId"] == "aws::cdn_distribution::website"


def _js_valid(doc, kind):
    res = []
    for f in fs.SCHEMA_DIR.glob("fedramp-*.json"):
        res.append(("https://fedramp.gov/schemas/" + f.name, Resource.from_contents(json.loads(f.read_text()))))
    schema = json.loads((fs.SCHEMA_DIR / fs.SCHEMAS[kind]).read_text())
    v = Draft202012Validator(schema, registry=Registry().with_resources(res), format_checker=FormatChecker())
    return [e.message for e in v.iter_errors(doc)]


def test_outputs_validate_and_name_their_schema(tmp_path):
    r = subprocess.run([sys.executable, str(SCRIPT), "--vdr", str(FIX / "vdr-report.json"),
                        "--decisions", str(FIX / "decisions.json"), "--out-dir", str(tmp_path)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    for name, kind in ((mod.VDT_OUT, "vdt"), (mod.AVI_OUT, "avi"), (mod.MRH_OUT, "mrh")):
        doc = json.loads((tmp_path / name).read_text())
        assert doc["$schema"] == "https://fedramp.gov/schemas/" + fs.SCHEMAS[kind]
        assert doc["certificationPackageOverviewUri"] == fs.CPO_URI
        assert fs.validate(doc, kind) == []
        assert _js_valid(doc, kind) == []
    assert (tmp_path / "vdr-detail-report.md").read_text().startswith("# Vulnerability Detail Report")


def test_periods_run_from_the_previous_report():
    prev = {"reportPeriod": {"from": "2026-11-01T00:00:00+00:00", "to": "2026-11-04T15:00:00+00:00"}}
    vdt, avi, _ = _build(prev_vdt=prev, prev_avi=prev)
    assert vdt["reportPeriod"] == {"from": "2026-11-04T15:00:00+00:00", "to": NOW.isoformat()}
    assert avi["reportPeriod"]["from"] == "2026-11-04T15:00:00+00:00"
    first, _, _ = _build()
    # The earliest detection: the suppressed CKV_AWS_68, known since DEC-104 was decided.
    assert first["reportPeriod"]["from"] == "2026-01-01T00:00:00+00:00"


def test_a_previous_report_ending_in_the_future_stops_the_build():
    prev = {"reportPeriod": {"from": "2026-11-01T00:00:00+00:00", "to": "2027-01-01T00:00:00+00:00"}}
    with pytest.raises(SystemExit, match="starts after it ends"):
        _build(prev_vdt=prev)


def _detection_ok(*feeds, checked_at="2026-11-06T14:59:00+00:00"):
    return {"schema": "detection/1", "checked_at": checked_at, "result": "ok",
            "feeds": [{"feed": f, "file": f"{f}.json", "status": "ok", "count": 0} for f in feeds]}


def test_history_keeps_a_finding_that_left_the_vdr_then_drops_it_after_a_year():
    _, _, mrh = _build()
    vdr = json.loads(json.dumps(VDR))
    vdr["findings"] = [f for f in vdr["findings"] if f["tracking_id"] != "grype-CVE-2099-0001-thumbnailer"]
    # Grype ran in the build that no longer reports it: remediated, from evidence.
    vdr["methodology"] = {"detection": _detection_ok("grype", "checkov")}
    _, _, later = _build(vdr=vdr, prev_mrh=mrh, now=NOW + timedelta(days=1))
    gone = next(r for r in later["activeVulnerabilities"]
                if r["providerTrackingId"] == "grype-CVE-2099-0001-thumbnailer")
    assert gone["finalDisposition"] == "Remediated"
    assert gone["providerExtensions"]["dispositionBasis"].startswith("grype ran in the VDR build checked")
    assert gone["providerExtensions"]["noLongerReportedAt"] == (NOW + timedelta(days=1)).isoformat()
    assert "projectedNextReduction" not in gone and gone["overdueStatus"]["isOverdue"] is False
    assert fs.validate(later, "mrh") == []
    # The time it left is kept, not reset, on later runs; after a year it is dropped.
    _, _, still = _build(vdr=vdr, prev_mrh=later, now=NOW + timedelta(days=200))
    kept = next(r for r in still["activeVulnerabilities"] if r["providerTrackingId"] == gone["providerTrackingId"])
    assert kept["providerExtensions"]["noLongerReportedAt"] == gone["providerExtensions"]["noLongerReportedAt"]
    _, _, aged = _build(vdr=vdr, prev_mrh=still, now=NOW + timedelta(days=400))
    assert gone["providerTrackingId"] not in _ids(aged["activeVulnerabilities"])


def test_each_report_names_the_profile_of_the_vdr_it_came_from():
    stamp = {"profile_version": "vdr-method/2026-11-04", "conformance_sha256": "a" * 64}
    vdr = {**json.loads(json.dumps(VDR)), "methodology": {"profile": stamp}}
    for doc in _build(vdr=vdr):
        assert doc["providerExtensions"]["profile"] == stamp
        assert doc["providerExtensions"]["vdrReportId"] == "vdr-fixture"


def test_a_malformed_rating_stops_the_build():
    vdr = json.loads(json.dumps(VDR))
    vdr["findings"][0]["current_pain"] = "high"
    with pytest.raises(SystemExit, match="not N0-N5"):
        _build(vdr=vdr)


# --- wiring: both publishers build, verify what they carry forward, sign, publish ---

def _steps(wf):
    import yaml
    jobs = yaml.safe_load((REPO / ".github" / "workflows" / wf).read_text())["jobs"]
    return [s for job in jobs.values() for s in job.get("steps", [])]


@pytest.mark.parametrize("wf", ["deploy-with-opa.yml", "evidence-nightly.yml"])
def test_each_publisher_verifies_the_previous_reports_before_carrying_them_forward(wf):
    steps = _steps(wf)
    build = next(s for s in steps if "scripts/build-cr26-vdr.py" in s.get("run", ""))
    run = build["run"]
    assert "set -euo pipefail" in run
    # The previous copy is read only after its signature verifies, against a
    # pinned identity; an unverifiable copy stops the run.
    assert run.index("cosign verify-blob") < run.index('prev+=("$flag"')
    assert "--certificate-identity" in run and "refusing to carry it forward" in run and "exit 1" in run
    assert run.index("build-cr26-vdr.py") < run.index("cosign sign-blob")
    vdr = next(s for s in steps if "scripts/build-vdr-report.py" in s.get("run", "") and "--output vdr-report.json" in s["run"])
    assert steps.index(vdr) < steps.index(build)


def test_the_deploy_publishes_and_round_trips_the_reports():
    steps = _steps("deploy-with-opa.yml")
    publish = next(s for s in steps if s.get("name") == "Publish all signed artifacts to /.well-known/")["run"]
    rt = next(s for s in steps if s.get("name") == "Post-publish round-trip verify")["run"]
    assert "for a in vdr-detail-report vdr-accepted-vulnerabilities vdr-history; do" in publish
    assert '"$a.bundle"' in publish
    assert 'check "$a.json" ".well-known/$a.json"' in rt


def test_the_nightly_publishes_them_under_its_vdr_prefix():
    steps = _steps("evidence-nightly.yml")
    publish = next(s for s in steps if s.get("name") == "Publish VDR + trend to /.well-known/")["run"]
    assert "for a in vdr-detail-report vdr-accepted-vulnerabilities vdr-history; do" in publish
    for name in (mod.VDT_OUT, mod.AVI_OUT, mod.MRH_OUT):
        assert name.startswith("vdr-"), "the nightly may write only .well-known/vdr-*"


def test_external_verification_checks_signature_and_schema():
    text = (REPO / "scripts" / "verify-published.sh").read_text()
    assert "for art in vdr-detail-report vdr-accepted-vulnerabilities vdr-history; do" in text
    assert "for pair in vdr-detail-report:vdt vdr-accepted-vulnerabilities:avi vdr-history:mrh; do" in text
    assert "fs.validate(" in text and "providerExtensions.vdrReportId" in text


def test_an_unreadable_previous_report_stops_the_build_rather_than_dropping_history(tmp_path):
    bad = tmp_path / "prev-mrh.json"
    bad.write_text("not json")
    r = subprocess.run([sys.executable, str(SCRIPT), "--vdr", str(FIX / "vdr-report.json"),
                        "--decisions", str(FIX / "decisions.json"), "--previous-mrh", str(bad),
                        "--out-dir", str(tmp_path)], capture_output=True, text=True)
    assert r.returncode != 0 and "unreadable" in r.stderr
    assert not list(tmp_path.glob("vdr-*"))


# --- what each record says (VER-RPT-VDT, VER-RPT-AVI) -------------------------------

def _register(edit):
    """The fixture register with `edit(records_by_id)` applied, validated like the real one."""
    doc = json.loads((FIX / "decisions.json").read_text())
    edit({r["id"]: r for r in doc["decisions"]})
    return _decisions.validate(doc)


def _by_id(doc, accepted=False):
    rows = doc["acceptedVulnerabilities"] if accepted else doc["vulnerabilities"]
    return {(r["vulnerabilityDetail"] if accepted else r)["providerTrackingId"]:
            (r["vulnerabilityDetail"] if accepted else r) for r in rows}


def test_records_carry_their_historical_rating_and_rating_history():
    vdr = json.loads(json.dumps(VDR))
    f = vdr["findings"][0]
    f["historical_pain"] = "N4"
    f["rating_history"] = [
        {"at": "2026-08-06T14:00:00+00:00", "pain": "N4", "lev": True, "irv": True, "reason": "first evaluation"},
        {"at": "2026-10-14T10:00:00+00:00", "pain": "N3", "lev": True, "irv": True, "reason": "re-evaluation: pain N4->N3"}]
    vdt, _, _ = _build(vdr=vdr)
    ext = _by_id(vdt)[f["tracking_id"]]["providerExtensions"]
    assert ext["historicalRating"] == 4
    assert [(h["at"], h["rating"], h["reason"]) for h in ext["ratingHistory"]] == [
        ("2026-08-06T14:00:00+00:00", 4, "first evaluation"),
        ("2026-10-14T10:00:00+00:00", 3, "re-evaluation: pain N4->N3")]
    assert fs.validate(vdt, "vdt") == []


def test_a_decision_sets_the_next_reduction_and_the_deadline_is_only_the_fallback():
    vdr = json.loads(json.dumps(VDR))
    vdr["findings"][0]["decision_id"] = "DEC-105"   # open N3 finding, deadline 2026-11-20

    def plan(target):
        def edit(recs):
            recs["DEC-105"]["planned_reduction"] = {"date": "2026-11-12", "target_pain": target}
        return _register(edit)
    vdt, _, _ = mod.build(vdr, plan("N1"), None, None, None, NOW)
    rec = _by_id(vdt)["grype-CVE-2099-0001-thumbnailer"]
    assert rec["projectedNextReduction"] == {"estimatedAt": "2026-11-12T00:00:00+00:00", "targetRating": 1}
    assert rec["providerExtensions"]["projectionBasis"] == "DEC-105 planned_reduction"
    # A plan that reduces nothing is not a reduction: the deadline stands, and says why.
    vdt, _, _ = mod.build(vdr, plan("N3"), None, None, None, NOW)
    rec = _by_id(vdt)["grype-CVE-2099-0001-thumbnailer"]
    assert rec["projectedNextReduction"] == {"estimatedAt": "2026-11-20T00:00:00+00:00", "targetRating": 0}
    assert "not below the current rating" in rec["providerExtensions"]["projectionBasis"]
    # No plan: the remediation deadline.
    vdt, _, _ = _build()
    assert _by_id(vdt)["grype-CVE-2099-0001-thumbnailer"]["providerExtensions"]["projectionBasis"] == \
        "remediation deadline (no planned reduction recorded)"


def test_supplementary_information_comes_from_the_decision():
    vdt, avi, _ = _build()
    fp = _by_id(vdt)["zap-10099-article"]["supplementaryRiskInformation"]
    assert fp.startswith("DEC-103 (false-positive; decided 2026-01-01, review by 2027-01-01): "
                         "The rule matches article prose, not code.")
    # The AVI carries the justification as the rationale; the supplementary
    # information is the rest of the decision, not a copy of it.
    acc = _by_id(avi, accepted=True)["CKV_AWS_68"]["supplementaryRiskInformation"]
    assert acc.startswith("DEC-104 (risk-accepted; decided 2026-01-01, review by 2027-01-01).")
    assert "Cost trade-off" not in acc
    assert all(a["vulnerabilityDetail"].get("supplementaryRiskInformation") for a in avi["acceptedVulnerabilities"]
               if a["vulnerabilityDetail"]["providerExtensions"]["decisionId"])


def test_overdue_explanations_explain_the_overdue_status_not_the_suppression():
    vdr = json.loads(json.dumps(VDR))
    vdr["findings"][1]["remediation_due_at"] = "2026-09-23T13:51:28+00:00"   # overdue, DEC-101 accepts it
    vdt, avi, _ = _build(vdr=vdr)
    every = list(_by_id(vdt).values()) + list(_by_id(avi, accepted=True).values())
    assert not any("documented suppression" in r["overdueStatus"].get("explanation", "") for r in every)
    over = _by_id(avi, accepted=True)["checkov-CKV_AWS_310-website"]["overdueStatus"]
    assert over == {"isOverdue": True, "explanation": (
        "Overdue: its remediation deadline, 2026-09-23, passed without remediation. It is still open because "
        "DEC-101 accepts it (risk-accepted, decided 2026-01-01), so no remediation is planned.")}
    assert _by_id(vdt)["zap-10099-article"]["overdueStatus"] == {
        "isOverdue": False, "explanation": "Not overdue: closed as False Positive under DEC-103."}
    mav = _by_id(avi, accepted=True)["dependabot-GHSA-xxxx-yyyy-zzzz"]["overdueStatus"]
    assert mav["isOverdue"] and mav["explanation"].startswith("Overdue: not fully mitigated or remediated within")


def test_detection_time_comes_from_a_decision_that_names_the_record():
    def edit(recs):
        # The ZAP finding was found in a manual scan before the pipeline's scanner saw it.
        recs["DEC-103"]["applies_to"] = {"check_ids": [], "vuln_ids": ["zap-10099-article"], "resources": []}
        recs["DEC-103"]["original_detection_date"] = "2026-07-01"
        # A decision about a check across resources dates the check, not each resource.
        recs["DEC-101"]["original_detection_date"] = "2026-02-01"
    vdt, avi, _ = mod.build(VDR, _register(edit), None, None, None, NOW)
    zap = _by_id(vdt)["zap-10099-article"]
    assert zap["detection"]["detectedAt"] == "2026-07-01T00:00:00+00:00"
    assert zap["providerExtensions"]["detectedAtBasis"].startswith("DEC-103 original_detection_date")
    assert zap["providerExtensions"]["firstReportedAt"] == "2026-08-06T13:51:28+00:00"
    acc = _by_id(avi, accepted=True)
    assert acc["checkov-CKV_AWS_310-website"]["detection"]["detectedAt"] == "2026-08-06T13:51:28+00:00"
    # A suppressed check is never reported by a scanner: its decision dates it.
    assert acc["CKV_AWS_68"]["detection"]["detectedAt"] == "2026-01-01T00:00:00+00:00"
    assert acc["CKV_AWS_68"]["providerExtensions"]["detectedAtBasis"].startswith("DEC-104 decided_on")


def test_a_suppression_names_the_resources_its_decision_affects():
    vdr = json.loads(json.dumps(VDR))
    vdr["risk_accepted"][0].update(affected_resources=["aws-cloudfront-distribution"],
                                   component_id="aws::cdn_distribution::website", irv_basis="inventory")
    _, avi, _ = _build(vdr=vdr)
    ext = _by_id(avi, accepted=True)["CKV_AWS_68"]["providerExtensions"]
    assert ext["affectedResources"] == ["aws-cloudfront-distribution"]
    assert ext["componentId"] == "aws::cdn_distribution::website"


# --- history: a final disposition only from evidence (VER-TFR-MRH) -------------------

def _gone(vdr_edit, prev=None, now=NOW + timedelta(days=1), register=None):
    """Build, drop the open grype finding, apply `vdr_edit`, rebuild with the first history."""
    _, _, mrh = _build()
    vdr = json.loads(json.dumps(VDR))
    vdr["findings"] = [f for f in vdr["findings"] if f["tracking_id"] != "grype-CVE-2099-0001-thumbnailer"]
    vdr_edit(vdr)
    _, _, later = mod.build(vdr, register or REGISTER, None, None, prev or mrh, now)
    assert fs.validate(later, "mrh") == []
    return vdr, later, next(r for r in later["activeVulnerabilities"]
                            if r["providerTrackingId"] == "grype-CVE-2099-0001-thumbnailer")


def test_a_record_that_vanished_without_evidence_has_no_final_disposition():
    vdr, later, gone = _gone(lambda v: None)          # no detection summary: coverage not shown
    assert "finalDisposition" not in gone
    assert gone["providerExtensions"]["noLongerReportedReason"] == "unknown"
    assert gone["providerExtensions"]["noLongerReportedBasis"].startswith("no evidence of why")
    # A failed scan is no evidence either.
    _, _, failed = _gone(lambda v: v.update(methodology={"detection": {
        **_detection_ok("grype"), "feeds": [{"feed": "grype", "status": "failed"}]}}))
    assert "finalDisposition" not in failed
    # A closed decision that arrives later settles it.
    def closed(recs):
        recs["DEC-105"].update(status="closed", disposition="remediated", closed_on="2026-11-07",
                               applies_to={"check_ids": [], "vuln_ids": ["CVE-2099-0001"], "resources": []})
    _, _, settled = _gone(lambda v: None, prev=later, now=NOW + timedelta(days=3), register=_register(closed))
    assert settled["finalDisposition"] == "Remediated"
    assert settled["providerExtensions"]["dispositionBasis"] == "DEC-105 closed as remediated on 2026-11-07"
    assert settled["providerExtensions"]["noLongerReportedAt"] == gone["providerExtensions"]["noLongerReportedAt"]


def test_an_unsupported_remediated_from_an_earlier_history_is_withdrawn():
    _, _, mrh = _build()
    vdr = json.loads(json.dumps(VDR))
    vdr["findings"] = [f for f in vdr["findings"] if f["tracking_id"] != "grype-CVE-2099-0001-thumbnailer"]
    old = json.loads(json.dumps(mrh))
    for r in old["activeVulnerabilities"]:
        if r["providerTrackingId"] == "grype-CVE-2099-0001-thumbnailer":
            r["finalDisposition"] = "Remediated"         # what the earlier builder wrote, with no evidence
            r["providerExtensions"]["noLongerReportedAt"] = NOW.isoformat()
    _, _, later = _build(vdr=vdr, prev_mrh=old, now=NOW + timedelta(days=1))
    gone = next(r for r in later["activeVulnerabilities"] if r["providerTrackingId"] == "grype-CVE-2099-0001-thumbnailer")
    assert "finalDisposition" not in gone and gone["providerExtensions"]["noLongerReportedReason"] == "unknown"


def test_a_check_that_became_a_suppression_is_not_remediated():
    _, _, mrh = _build()
    vdr = json.loads(json.dumps(VDR))
    vdr["findings"] = [f for f in vdr["findings"] if f["tracking_id"] != "checkov-CKV_AWS_20-site"]
    vdr["methodology"] = {"detection": _detection_ok("checkov")}
    vdr["risk_accepted"].append({**vdr["risk_accepted"][0], "tracking_id": "CKV_AWS_20", "tool_id": "CKV_AWS_20",
                                 "decision_id": "DEC-102"})
    _, _, later = _build(vdr=vdr, prev_mrh=mrh, now=NOW + timedelta(days=1))
    gone = next(r for r in later["activeVulnerabilities"] if r["providerTrackingId"] == "checkov-CKV_AWS_20-site")
    assert "finalDisposition" not in gone
    assert gone["providerExtensions"]["noLongerReportedReason"] == "suppressed"
    # A false-positive suppression is a final disposition, from the decision.
    vdr["risk_accepted"].pop()
    vdr["false_positives"] = [{"tracking_id": "CKV_AWS_20", "tool_id": "CKV_AWS_20", "decision_id": "DEC-103",
                               "current_disposition": "false-positive"}]
    _, _, later = _build(vdr=vdr, prev_mrh=mrh, now=NOW + timedelta(days=1))
    gone = next(r for r in later["activeVulnerabilities"] if r["providerTrackingId"] == "checkov-CKV_AWS_20-site")
    assert gone["finalDisposition"] == "False Positive"


def test_a_vanished_zap_finding_is_remediated_only_after_a_later_scan():
    def dast(when):
        return {"methodology": {"dast": {"scanner": "zap", "status": "ok", "generated_at": when}}}
    last = NOW.isoformat()
    assert mod._coverage("zap", dast("2026-11-04T00:00:00+00:00"), last) is None   # the scan that reported it
    assert mod._coverage("zap", dast("2026-11-06T00:00:00+00:00"), last).startswith("the ZAP scan of 2026-11-06")
    assert mod._coverage("zap", {"methodology": {}}, last) is None
    # A record that was a false positive when last reported keeps that disposition.
    _, _, mrh = _build()
    vdr = json.loads(json.dumps(VDR))
    vdr["findings"] = [f for f in vdr["findings"] if f["tracking_id"] != "zap-10099-article"]
    _, _, later = _build(vdr=vdr, prev_mrh=mrh, now=NOW + timedelta(days=1))
    fp = next(r for r in later["activeVulnerabilities"] if r["providerTrackingId"] == "zap-10099-article")
    assert fp["finalDisposition"] == "False Positive"


def test_closed_decisions_are_backfilled_into_the_history_once():
    def edit(recs):
        recs["DEC-105"].update(status="closed", disposition="remediated", closed_on="2026-06-18",
                               original_detection_date="2026-05-06", former_id="POAM-005",
                               source={"detector": "Manual review", "original_risk_rating": "moderate"})
    reg = _register(edit)
    vdr = json.loads(json.dumps(VDR))
    vdr["findings"] = [f for f in vdr["findings"] if f["decision_id"] != "DEC-105"]
    _, _, mrh = mod.build(vdr, reg, None, None, None, NOW)
    back = [r for r in mrh["activeVulnerabilities"] if r["providerTrackingId"] == "DEC-105"]
    assert len(back) == 1
    assert back[0]["finalDisposition"] == "Remediated"
    assert back[0]["detection"] == {"detectedAt": "2026-05-06T00:00:00+00:00", "detectionSource": "Manual review"}
    assert back[0]["providerExtensions"]["backfilledFromDecision"] is True
    assert back[0]["providerExtensions"]["formerId"] == "POAM-005"
    assert fs.validate(mrh, "mrh") == []
    # Carried forward: rebuilt from the register, never duplicated; dropped a year after closing.
    _, _, again = mod.build(vdr, reg, None, None, mrh, NOW + timedelta(days=1))
    assert [r["providerTrackingId"] for r in again["activeVulnerabilities"]].count("DEC-105") == 1
    _, _, aged = mod.build(vdr, reg, None, None, again, datetime(2027, 6, 20, tzinfo=timezone.utc))
    assert "DEC-105" not in _ids(aged["activeVulnerabilities"])


# --- the period's activity (VER-RPT-PER) ---------------------------------------------

def _with_activity():
    vdr = json.loads(json.dumps(VDR))
    vdr["emitted_at"] = NOW.isoformat()
    vdr["findings"][0].update(first_detected="2026-11-05T09:00:00+00:00", first_evaluated="2026-11-05T09:00:00+00:00",
                              completed_reductions=[{"at": "2026-11-05T10:00:00+00:00", "from": "N4", "to": "N3"}])
    vdr["methodology"] = {
        "detection": {**_detection_ok("grype", "checkov", checked_at="2026-11-05T14:59:00+00:00"),
                      "feeds": [{"feed": "grype", "file": "grype-js.json", "status": "ok", "count": 1,
                                 "source_date": "2026-11-05T06:00:00+00:00"},
                                {"feed": "kev", "file": "kev-catalog.json", "status": "ok", "count": 9,
                                 "source_date": "2026-11-04T20:00:00+00:00"},
                                {"feed": "previous-vdr", "file": "previous-vdr-report.json", "status": "ok"}]},
        "dast": {"scanner": "zap", "status": "ok", "generated_at": "2026-11-05T12:47:20+00:00", "alerts": 4},
        "runtime_verification": {"uri": "https://samaydlette.com/.well-known/ksi-signal-runtime.json",
                                 "verified": True, "fresh": True, "emitted_at": "2026-11-05T11:00:00Z",
                                 "signal_id": "rt-1", "validations": 5, "failed": 1, "divergence": "converged"}}
    return vdr


def test_each_period_report_summarizes_the_periods_activity():
    prev = {"reportPeriod": {"from": "2026-11-04T15:00:00+00:00", "to": "2026-11-05T03:00:00+00:00"}}
    vdt, avi, _ = _build(vdr=_with_activity(), prev_vdt=prev, prev_avi=prev)
    for doc in (vdt, avi):
        s = doc["providerExtensions"]["activitySummary"]
        assert s["period"] == doc["reportPeriod"]
        assert s["detections"] == [{"providerTrackingId": "grype-CVE-2099-0001-thumbnailer",
                                    "at": "2026-11-05T09:00:00+00:00"}]
        assert s["reductions"] == [{"providerTrackingId": "grype-CVE-2099-0001-thumbnailer",
                                    "at": "2026-11-05T10:00:00+00:00", "from": "N4", "to": "N3"}]
        scans = {x["activity"]: x for x in s["scans"]}
        assert scans["Grype software composition scan (grype-js.json)"]["at"] == "2026-11-05T14:59:00+00:00"
        assert scans["Grype software composition scan (grype-js.json)"]["vulnerabilityDatabaseBuiltAt"] == \
            "2026-11-05T06:00:00+00:00"
        assert scans["CISA KEV catalog (kev-catalog.json)"]["inPeriod"] is False   # published before the period
        assert scans["OWASP ZAP dynamic scan (weekly)"]["inPeriod"] is True
        assert not any("previous-vdr" in k for k in scans)
        rt = s["runtimeVerification"]
        assert rt["uri"] == "https://samaydlette.com/.well-known/ksi-signal-runtime.json" and rt["signalId"] == "rt-1"
        assert s["counts"]["runtimeRunsInPeriod"] == 1 and s["counts"]["runtimeFailuresInPeriod"] == 1
        assert s["counts"]["detections"] == 1 and s["counts"]["reductions"] == 1
    assert fs.validate(vdt, "vdt") == [] and fs.validate(avi, "avi") == []


def test_an_unverified_runtime_run_is_linked_but_not_counted():
    vdr = _with_activity()
    vdr["methodology"]["runtime_verification"].update(verified=False, validations=None, failed=None,
                                                      reason="runtime signal signature does not verify")
    vdt, _, _ = _build(vdr=vdr)
    s = vdt["providerExtensions"]["activitySummary"]
    assert s["counts"]["runtimeRunsInPeriod"] == 0 and "not verified" in s["runtimeVerification"]["note"]


def test_the_markdown_reports_carry_the_activity_and_link_the_runtime_results(tmp_path):
    vdr = tmp_path / "vdr.json"
    vdr.write_text(json.dumps(_with_activity()))
    r = subprocess.run([sys.executable, str(SCRIPT), "--vdr", str(vdr), "--decisions", str(FIX / "decisions.json"),
                        "--out-dir", str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    for name in ("vdr-detail-report.md", "vdr-accepted-vulnerabilities.md"):
        text = (tmp_path / name).read_text()
        assert "## Activity this period" in text and "| OWASP ZAP dynamic scan (weekly) |" in text
        assert "(https://samaydlette.com/.well-known/ksi-signal-runtime.json)" in text


def test_every_report_carries_the_offerings_fedramp_id(tmp_path):
    want = json.loads((REPO / "data" / "cds" / "offering.json").read_text())["fedramp_id"]
    vdt, avi, mrh = _build()
    for doc in (vdt, avi, mrh):
        assert doc["providerExtensions"]["fedRampId"] == want


def test_a_missing_fedramp_id_stops_the_build(tmp_path):
    p = tmp_path / "offering.json"
    p.write_text("{}")
    with pytest.raises(SystemExit, match="fedramp_id is missing"):
        mod.fedramp_id(p)
