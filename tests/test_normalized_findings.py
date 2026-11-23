"""The normalized findings input (--findings): the platform-neutral plug.

A platform adapter writes a findings/v1 document (infrastructure/schemas/
findings.schema.json); the VDR build reads it without knowing the platform. The
build checks the rules itself, so a bad document fails the build rather than
publishing a report that checked less.
"""
import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((REPO / "infrastructure" / "schemas" / "findings.schema.json").read_text())

spec = importlib.util.spec_from_file_location("vdr_norm", REPO / "scripts" / "build-vdr-report.py")
vdr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vdr)
spec = importlib.util.spec_from_file_location("gate_norm", REPO / "scripts" / "vuln-gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

# A finding from a platform this repository does not run on: the build takes it
# exactly as it takes the AWS adapter's.
OTHER_PLATFORM = {
    "schema_version": "findings/v1", "platform": "example-cloud", "adapter": "their-adapter.py",
    "findings": [{"source": "example-scanner", "tool_id": "EX-1", "tracking_id": "example-scanner-EX-1-bucket-a",
                  "title": "Bucket a allows public listing", "severity": "HIGH", "resource": "bucket-a"}],
}


def _write(tmp_path, doc):
    p = tmp_path / "f.json"
    p.write_text(json.dumps(doc))
    return p


def test_a_document_from_another_platform_is_read_as_is(tmp_path):
    assert vdr.ingest_findings(_write(tmp_path, OTHER_PLATFORM)) == OTHER_PLATFORM["findings"]


def test_a_source_outside_the_vulnerability_sources_is_a_configuration_finding(tmp_path):
    (f,) = vdr.ingest_findings(_write(tmp_path, OTHER_PLATFORM))
    assert vdr.classify_finding(f["tool_id"]) == (None, None)  # open until a decision names EX-1
    assert gate.vulns_from_vdr({"findings": [f]}) == []


@pytest.mark.parametrize("breakage, message", [
    (lambda d: d.update(schema_version="findings/v0"), "schema_version"),
    (lambda d: d.pop("platform"), "needs exactly"),
    (lambda d: d.update(extra=1), "needs exactly"),
    (lambda d: d.update(findings={}), "not a list"),
    (lambda d: d["findings"][0].pop("tracking_id"), "missing tracking_id"),
    (lambda d: d["findings"][0].update(severity="SEVERE"), "severity"),
    (lambda d: d["findings"][0].update(fix_state="maybe"), "fix_state"),
    # What the build computes is never taken from an adapter.
    (lambda d: d["findings"][0].update(first_detected="2020-01-01T00:00:00Z"), "first_detected"),
    (lambda d: d["findings"][0].update(decision_id="DEC-001"), "decision_id"),
])
def test_a_document_that_breaks_a_rule_fails_the_build(tmp_path, breakage, message):
    doc = json.loads(json.dumps(OTHER_PLATFORM))
    breakage(doc)
    with pytest.raises(SystemExit, match=message):
        vdr.ingest_findings(_write(tmp_path, doc))


def test_an_absent_or_unreadable_document_fails_the_build(tmp_path):
    with pytest.raises(SystemExit, match="not found"):
        vdr.ingest_findings(tmp_path / "absent.json")
    (tmp_path / "bad.json").write_text("{")
    with pytest.raises(SystemExit, match="not JSON"):
        vdr.ingest_findings(tmp_path / "bad.json")


def test_the_schema_states_the_rules_the_build_checks():
    props = SCHEMA["properties"]["findings"]["items"]
    assert tuple(props["required"]) == vdr._FINDING_REQUIRED
    assert set(props["properties"]) - set(props["required"]) == vdr._FINDING_OPTIONAL
    assert set(props["properties"]["severity"]["enum"]) == vdr._FINDING_SEVERITIES
    assert set(props["properties"]["fix_state"]["enum"]) == vdr._FINDING_FIX_STATES
    assert SCHEMA["properties"]["schema_version"]["const"] == vdr.FINDINGS_SCHEMA_VERSION


def test_the_schema_accepts_the_good_document_and_refuses_a_computed_field():
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(OTHER_PLATFORM, SCHEMA)
    doc = json.loads(json.dumps(OTHER_PLATFORM))
    doc["findings"][0]["pain"] = "N4"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, SCHEMA)
