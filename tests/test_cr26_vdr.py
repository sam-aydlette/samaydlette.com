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
- report periods run from the previous report's end (VER-RPT-PER);
- the history keeps a finding that left the VDR, closed as Remediated, for a
  year, then drops it.
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
    assert first["reportPeriod"]["from"] == "2026-03-01T00:00:00+00:00"   # earliest detection


def test_a_previous_report_ending_in_the_future_stops_the_build():
    prev = {"reportPeriod": {"from": "2026-11-01T00:00:00+00:00", "to": "2027-01-01T00:00:00+00:00"}}
    with pytest.raises(SystemExit, match="starts after it ends"):
        _build(prev_vdt=prev)


def test_history_keeps_a_finding_that_left_the_vdr_then_drops_it_after_a_year():
    _, _, mrh = _build()
    vdr = json.loads(json.dumps(VDR))
    vdr["findings"] = [f for f in vdr["findings"] if f["tracking_id"] != "grype-CVE-2099-0001-thumbnailer"]
    _, _, later = _build(vdr=vdr, prev_mrh=mrh, now=NOW + timedelta(days=1))
    gone = next(r for r in later["activeVulnerabilities"]
                if r["providerTrackingId"] == "grype-CVE-2099-0001-thumbnailer")
    assert gone["finalDisposition"] == "Remediated"
    assert gone["providerExtensions"]["noLongerReportedAt"] == (NOW + timedelta(days=1)).isoformat()
    assert "projectedNextReduction" not in gone and gone["overdueStatus"] == {"isOverdue": False}
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
    vdr = next(s for s in steps if "scripts/run-gates.sh vdr" in s.get("run", ""))
    assert steps.index(vdr) < steps.index(build)


def test_the_deploy_publishes_and_round_trips_the_reports():
    # The deploy uploads and round-trips what the config lists for it
    # (scripts/published-set.py; tests/test_published_set.py runs both steps).
    import _freshness
    arts = {a["path"]: a for a in _freshness.load_freshness_config()["artifacts"]}
    for name in (mod.VDT_OUT, mod.AVI_OUT, mod.MRH_OUT):
        a = arts[f".well-known/{name}"]
        assert "deploy" in a["published_by"] and a["signature"] == f".well-known/{name.removesuffix('.json')}.bundle"


def test_the_nightly_publishes_them_under_its_vdr_prefix():
    steps = _steps("evidence-nightly.yml")
    publish = next(s for s in steps if s.get("name") == "Publish VDR + trend to /.well-known/")["run"]
    assert "for a in vdr-detail-report vdr-accepted-vulnerabilities vdr-history; do" in publish
    for name in (mod.VDT_OUT, mod.AVI_OUT, mod.MRH_OUT):
        assert name.startswith("vdr-"), "the nightly may write only .well-known/vdr-*"


def test_external_verification_checks_signature_and_schema():
    text = (REPO / "scripts" / "verify-published.sh").read_text()
    assert 'published-set.py" signed' in text  # signatures: tests/test_verify_published.py
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
