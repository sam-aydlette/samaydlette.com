"""CodeQL alerts and the authenticated ZAP API scan reach the VDR (VDR-CSO-DET, DAC).

CodeQL alerts (SAST of first-party code) become findings with a stable tracking
id per alert, the rule as tool_id and the file as resource, and are decided
through the decision register like every other vulnerability. The API scan's
ZAP report is read by the same ZAP ingester as the site baseline, with its own
tracking ids so the two scans' findings never merge. A given input that is
missing or malformed stops the build: no scan never reads as zero findings.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DET = REPO / "tests" / "fixtures" / "detection"
ZAP = REPO / "tests" / "fixtures" / "zap"
sys.path.insert(0, str(REPO / "scripts"))
import _codeql  # noqa: E402
import _zap_api  # noqa: E402


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vdr = _load("vdr", "build-vdr-report.py")
vg = _load("vuln_gate", "vuln-gate.py")


def test_codeql_alert_becomes_a_finding():
    [f] = _codeql.ingest_codeql(str(DET / "codeql.json"))
    assert f == {
        "source": "codeql", "tool_id": "py/path-injection", "tracking_id": "codeql-py/path-injection-7",
        "title": "Uncontrolled data used in path expression",
        "description": "This path depends on a user-provided value.", "severity": "HIGH",
        "resource": "backend/main.py", "detected_at": "2026-11-03T05:41:00Z"}


def _alert(number, rule="js/xss", state="open", **rule_extra):
    return {"number": number, "state": state, "created_at": "2026-11-01T00:00:00Z",
            "rule": {"id": rule, "description": "d", **rule_extra},
            "most_recent_instance": {"location": {"path": "website/assets/js/trust.js"}, "message": {"text": "m"}}}


def _write(tmp_path, alerts):
    p = tmp_path / "codeql.json"
    p.write_text(json.dumps({"analyses": [], "alerts": alerts}))
    return str(p)


def test_tracking_ids_are_per_alert_and_stable(tmp_path):
    a = _codeql.ingest_codeql(_write(tmp_path, [_alert(3), _alert(4)]))
    b = _codeql.ingest_codeql(_write(tmp_path, [_alert(4), _alert(3)]))
    assert [f["tracking_id"] for f in a] == ["codeql-js/xss-3", "codeql-js/xss-4"]
    assert {f["tracking_id"] for f in a} == {f["tracking_id"] for f in b}


def test_only_open_alerts_are_findings(tmp_path):
    fs = _codeql.ingest_codeql(_write(tmp_path, [_alert(1), _alert(2, state="dismissed"), _alert(3, state="fixed")]))
    assert [f["tracking_id"] for f in fs] == ["codeql-js/xss-1"]


@pytest.mark.parametrize("rule,want", [
    ({"security_severity_level": "critical", "severity": "note"}, "CRITICAL"),
    ({"security_severity_level": "low", "severity": "error"}, "LOW"),
    ({"severity": "error"}, "HIGH"),
    ({"severity": "warning"}, "MEDIUM"),
    ({"severity": "note"}, "LOW"),
    ({}, "MEDIUM"),
])
def test_severity_prefers_codeql_security_severity(rule, want):
    assert _codeql.severity(rule) == want


@pytest.mark.parametrize("content,match", [
    (None, "not found"),
    ("{not json", "not valid JSON"),
    (json.dumps({"alerts": []}), "no alerts"),
    (json.dumps({"analyses": [], "alerts": [{"state": "open", "rule": {"id": "py/x"}}]}), "no number"),
])
def test_codeql_input_given_but_unusable_fails_closed(tmp_path, content, match):
    p = tmp_path / "codeql.json"
    if content is not None:
        p.write_text(content)
    with pytest.raises(SystemExit, match=match):
        _codeql.ingest_codeql(str(p))


def test_no_codeql_input_means_no_findings():
    assert _codeql.ingest_codeql(None) == []


def test_codeql_findings_are_vulnerabilities_the_register_decides():
    """A CodeQL finding is gated like a ZAP alert: unhandled without a decision."""
    assert "codeql" in vdr.VULN_SOURCES and vdr.VULN_SOURCES == vg.VULN_SOURCES
    [f] = _codeql.ingest_codeql(str(DET / "codeql.json"))
    vulns = vg.vulns_from_vdr({"findings": [f]})
    assert [v["id"] for v in vulns] == ["codeql-py/path-injection-7"]
    assert vg.find_unhandled(vulns, {}) == vulns


def test_codeql_finding_is_published_in_the_report():
    report, _ = vdr.build_report(_codeql.ingest_codeql(str(DET / "codeql.json")), [], set(), {})
    [pub] = [f for f in report["findings"] if f["source"] == "codeql"]
    assert pub["tracking_id"] == "codeql-py/path-injection-7"
    assert pub["tool_id"] == "py/path-injection" and pub["resource"] == "backend/main.py"


def test_api_scan_findings_have_their_own_tracking_ids():
    al = {"entries": []}
    site = vdr.ingest_zap(str(ZAP / "report.json"), al)
    api = _zap_api.ingest_zap_api(str(ZAP / "report.json"), vdr.ingest_zap, al)
    assert {f["tracking_id"] for f in api} == {"zap-api-10038", "zap-api-10021", "zap-api-90004"}
    assert not {f["tracking_id"] for f in api} & {f["tracking_id"] for f in site}
    assert all(f["source"] == "zap" for f in api)
    # Same alert type in both scans: two findings, decided separately.
    assert len(vdr.dedupe_findings(site + api)) == len(site) + len(api)


@pytest.mark.parametrize("content,match", [
    (None, "not found"),
    ("[]", "no site"),
    ("{not json", "not valid JSON"),
])
def test_api_report_given_but_unusable_fails_closed(tmp_path, content, match):
    p = tmp_path / "zap-api-report.json"
    if content is not None:
        p.write_text(content)
    with pytest.raises(SystemExit, match=match):
        _zap_api.ingest_zap_api(str(p), vdr.ingest_zap, {"entries": []})


def test_builder_takes_both_inputs():
    out = subprocess.run([sys.executable, str(REPO / "scripts" / "build-vdr-report.py"), "--help"],
                         capture_output=True, text=True, check=True).stdout
    assert "--codeql" in out and "--zap-api" in out
