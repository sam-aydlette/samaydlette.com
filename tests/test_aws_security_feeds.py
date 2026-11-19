"""Amazon Inspector and IAM Access Analyzer findings as VDR evidence.

Each finding becomes a VDR finding the vulnerability gate governs: without a
decision record naming it, the gate fails. The published fields carry no
account ID, and the resource resolves to the inventoried component it names.
"""
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "detection"


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vdr = _load("vdr_aws", "build-vdr-report.py")
gate = _load("vuln_gate_aws", "vuln-gate.py")


def test_an_inspector_finding_is_one_cve_in_one_package_of_one_function():
    (f,) = vdr.ingest_inspector(FIX / "inspector.json")
    assert f["source"] == "inspector" and f["cve"] == "CVE-2026-0001"
    assert f["tracking_id"] == "inspector-CVE-2026-0001-samaydlette-com-silk-reeling-examplepkg"
    assert f["resource"] == "arn:aws:lambda:us-east-2:ACCOUNT:function:samaydlette-com-silk-reeling"
    assert f["cvss_vector"].startswith("CVSS:3.1/") and f["fix_state"] == "fixed" and f["fix_versions"] == ["1.0.1"]


def test_an_access_analyzer_finding_names_the_principal_and_access_without_the_account():
    (f,) = vdr.ingest_access_analyzer(FIX / "access-analyzer.json")
    assert f["source"] == "access-analyzer" and f["severity"] == "MEDIUM"
    assert f["tracking_id"] == "access-analyzer-11111111-2222-3333-4444-555555555555"
    assert "token.actions.githubusercontent.com" in f["description"] and "sts:AssumeRoleWithWebIdentity" in f["description"]
    assert "000000000000" not in json.dumps(f)


def test_public_access_is_high_and_resolved_findings_are_not_carried(tmp_path):
    doc = json.loads((FIX / "access-analyzer.json").read_text())
    resolved = dict(doc["findings"][0], id="resolved", status="RESOLVED")
    doc["findings"] = [dict(doc["findings"][0], isPublic=True), resolved]
    p = tmp_path / "a.json"
    p.write_text(json.dumps(doc))
    assert [(f["severity"], f["title"].split()[0]) for f in vdr.ingest_access_analyzer(p)] == [("HIGH", "Public")]


def test_suppressed_and_archived_findings_are_still_carried(tmp_path):
    for name, ingest, status in (("inspector.json", vdr.ingest_inspector, "SUPPRESSED"),
                                 ("access-analyzer.json", vdr.ingest_access_analyzer, "ARCHIVED")):
        doc = json.loads((FIX / name).read_text())
        doc["findings"][0]["status"] = status
        p = tmp_path / name
        p.write_text(json.dumps(doc))
        assert len(ingest(p)) == 1


def test_the_findings_resolve_to_their_inventoried_components():
    index = {"arn:aws:lambda:us-east-2:ACCOUNT:function:samaydlette-com-silk-reeling": "aws::function::silk_reeling",
             "arn:aws:iam::ACCOUNT:role/github-actions-deploy-oidc": "aws::iam_role::deploy"}
    found = vdr.ingest_inspector(FIX / "inspector.json") + vdr.ingest_access_analyzer(FIX / "access-analyzer.json")
    assert [vdr.resolve_component(f, index) for f in found] == ["aws::function::silk_reeling", "aws::iam_role::deploy"]


def test_an_undecided_finding_from_either_feed_fails_the_vulnerability_gate():
    found = vdr.ingest_inspector(FIX / "inspector.json") + vdr.ingest_access_analyzer(FIX / "access-analyzer.json")
    vulns = gate.vulns_from_vdr({"findings": found})
    ids = {v["id"] for v in vulns}
    assert ids == {"CVE-2026-0001", "access-analyzer-11111111-2222-3333-4444-555555555555"}
    assert {v["id"] for v in gate.find_unhandled(vulns, {})} == ids


def test_the_two_source_lists_agree():
    assert vdr.VULN_SOURCES == gate.VULN_SOURCES
