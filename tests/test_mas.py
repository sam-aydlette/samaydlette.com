"""The Minimum Assessment Scope is generated, complete, and fails closed on a gap
(MAS-CSO-IIR, MAS-CSO-FLO, MAS-CSO-MDI, MAS-CSO-TPR, FRC-CSX-MAS).

Each invariant scripts/build-mas.py enforces has a committed known-bad fixture
under tests/fixtures/mas/ (and tests/fixtures/third-party/) that fails for that
reason, and a test that the repository's own inputs pass it.
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

import jsonschema
import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "mas"
sys.path.insert(0, str(REPO / "scripts"))
import _redact  # noqa: E402
import _tpr  # noqa: E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mas = _load("build_mas", REPO / "scripts" / "build-mas.py")
bks = _load("bks_mas", REPO / "scripts" / "build-ksi-signal.py")

INPUTS = json.loads(mas.INPUTS.read_text())
CLASSIFICATION = json.loads(mas.CLASSIFICATION.read_text())
TPR = json.loads(mas.THIRD_PARTY.read_text())
SIGNAL = json.loads((FIX / "signal.json").read_text())
CF_TF = mas.CLOUDFRONT_TF.read_text()
BOOT = "\n".join(p.read_text() for p in sorted(mas.BOOTSTRAP_DIR.glob("*.tf")))
DST = set(INPUTS["data_store_types"])


def _build(signal=SIGNAL, classification=CLASSIFICATION, tf=CF_TF):
    return mas.build(signal, INPUTS, classification, TPR, tf, BOOT, "0" * 40, "2026-11-05T00:00:00+00:00")


# --- the repository's own scope passes, and publishes nothing it must not ---------------

def test_the_repository_scope_builds_with_no_gap():
    doc, problems = _build()
    assert problems == []
    assert all(doc["checks"].values())


def test_fixture_signal_carries_every_declared_external_service():
    # The fixture must track the inventory builder, or the other tests prove nothing.
    ext = {c["component_id"] for c in bks.build_external_components()}
    assert ext <= {c["component_id"] for c in SIGNAL["components"]}


def test_the_published_scope_carries_no_account_id_or_arn():
    doc, _ = _build()
    text = json.dumps(doc)
    assert not _redact.find(text)
    assert "arn:aws" not in text
    assert "@" not in text.replace("@mediapipe", "")


def test_markdown_twin_states_every_section_and_the_derivation():
    doc, _ = _build()
    md = mas.render_markdown(doc)
    for heading in ("How this is derived", "MAS-CSO-IIR", "MAS-CSO-FLO", "MAS-CSO-MDI", "MAS-CSO-TPR", "FRC-CSX-MAS"):
        assert heading in md
    for t in doc["third_party_information_resources"]:
        assert t["compensating_controls"] in md


# --- MAS-CSO-IIR: every off-origin host in the CSPs is placed ---------------------------

def test_csp_hosts_include_the_app_origins():
    hosts = mas.csp_hosts(CF_TF, BOOT)
    assert {"cdn.jsdelivr.net", "storage.googleapis.com"} <= set(hosts)
    assert any(h.endswith(".amazoncognito.com") for h in hosts)


def test_the_app_origins_are_inventoried_external_services():
    ids = {c["component_id"] for c in bks.build_external_components()}
    assert {"ext::jsdelivr", "ext::google-cloud-storage", "ext::first-epss", "ext::anchore-grype-db"} <= ids


def test_unplaced_csp_host_fails():
    _, problems = _build(tf=(FIX / "csp-unplaced.tf.fixture").read_text())
    # Compare the named host exactly, not as a substring of the message.
    named = {m.group(1) for p in problems for m in [re.match(r"the CSP allows (\S+), ", p)] if m}
    assert "unvetted-cdn.example.com" in named


def test_unresolvable_csp_source_fails_closed():
    with pytest.raises(SystemExit):
        mas.csp_hosts((FIX / "csp-unresolved.tf.fixture").read_text(), "")


def test_out_of_scope_host_needs_a_reason():
    _, problems = mas.place_hosts(["ochelli.com"], {"ochelli.com": {"out_of_scope": " "}}, set())
    assert problems


# --- MAS-CSO-FLO: every external service and data store is in a flow --------------------

def test_flow_gaps_fail():
    _, problems = mas.flows(json.loads((FIX / "classification-gaps.json").read_text()),
                            json.loads((FIX / "signal-gaps.json").read_text())["components"], DST)
    assert any("aws::function::ghost" in p for p in problems)
    assert any("aws::log_group::brand_new" in p and "no information flow" in p for p in problems)


def test_flow_category_is_the_high_water_mark_of_its_endpoints():
    comps = [{"component_id": "a", "type": "x", "security_category": {"confidentiality": "low", "integrity": "high", "availability": "low"}},
             {"component_id": "b", "type": "x", "security_category": {"confidentiality": "moderate", "integrity": "low", "availability": "low"}}]
    cls = {"declared": [], "flows": [{"id": "F", "label": "a to b", "path": [{"component": "a"}, {"component": "b"}]}]}
    out, problems = mas.flows(cls, comps, set())
    assert problems == []
    assert out[0]["security_category"] == {"confidentiality": "moderate", "integrity": "high", "availability": "low"}


def test_every_external_service_and_data_store_in_the_inventory_is_in_a_flow():
    _, problems = mas.flows(CLASSIFICATION, SIGNAL["components"], DST)
    assert problems == []


# --- MAS-CSO-MDI: every data store and log has a metadata entry -------------------------

def test_data_store_without_metadata_fails():
    _, problems = mas.metadata_inventory(json.loads((FIX / "signal-gaps.json").read_text())["components"],
                                         INPUTS["metadata"], DST)
    assert any("aws::log_group::brand_new" in p for p in problems)


def _tf_block(text, rtype, name):
    m = re.search(r'resource\s+"%s"\s+"%s"\s*\{(.*?)\n\}' % (re.escape(rtype), re.escape(name)), text, re.S)
    assert m, (rtype, name)
    return m.group(1)


def _num(block, key):
    m = re.search(r"\b%s\s*=\s*(\d+)" % key, block)
    assert m, key
    return int(m.group(1))


def test_metadata_retention_matches_the_terraform():
    infra = REPO / "infrastructure"
    every = "\n".join(p.read_text() for p in sorted(infra.glob("*.tf")) + sorted((infra / "bootstrap").glob("*.tf")))
    lg = {"opa_compliance": "opa_compliance", "evidence_watchdog": "evidence_watchdog",
          "silk_reeling": "silk_reeling", "silk_apigw": "silk_apigw", "route53_query_log": "route53_query_log"}
    md = INPUTS["metadata"]
    for comp, res in lg.items():
        assert md[f"aws::log_group::{comp}"]["retention_days"] == _num(
            _tf_block(every, "aws_cloudwatch_log_group", res), "retention_in_days"), comp
    assert md["aws::object_store::logs"]["retention_days"] == _num(
        _tf_block(every, "aws_s3_bucket_lifecycle_configuration", "logs"), "days")
    assert md["aws::object_store::cloudtrail"]["retention_days"] == int(
        re.search(r"expiration\s*\{\s*days\s*=\s*(\d+)", _tf_block(every, "aws_s3_bucket_lifecycle_configuration", "cloudtrail")).group(1))
    assert md["aws::object_store::website"]["retention_days"] == _num(
        _tf_block(every, "aws_s3_bucket_lifecycle_configuration", "website"), "noncurrent_days")
    assert md["aws::object_store::tfstate"]["retention_days"] == _num(
        _tf_block(every, "aws_s3_bucket_lifecycle_configuration", "tfstate"), "noncurrent_days")
    assert md["aws::message_queue::compliance_dlq"]["retention_days"] * 86400 == _num(
        _tf_block(every, "aws_sqs_queue", "compliance_dlq"), "message_retention_seconds")


# --- MAS-CSO-TPR ------------------------------------------------------------------------

def test_decided_third_party_record_without_the_four_fields_fails_the_inventory():
    with pytest.raises(SystemExit):
        bks.build_external_components(REPO / "tests" / "fixtures" / "third-party" / "decided-without-tpr-fields.json")


def test_every_third_party_resource_is_decided_with_the_four_fields():
    _, problems = mas.third_party(SIGNAL["components"], TPR)
    assert problems == []


def test_undecided_third_party_record_fails_the_scope():
    undecided = json.loads(json.dumps(TPR))
    undecided["components"]["ext::jsdelivr"]["decided_by"] = None
    _, problems = mas.third_party(SIGNAL["components"], undecided)
    assert any("ext::jsdelivr" in p for p in problems)


def test_published_inventory_carries_the_four_fields():
    for c in bks.build_external_components():
        for f in bks.MAS_TPR_FIELDS:
            assert c["attributes"][f] not in (None, "", "not recorded"), (c["component_id"], f)


def test_cpo_helper_matches_the_cpo_schema():
    schema = json.loads((REPO / "infrastructure" / "schemas" / "fedramp-2026-06-24" /
                         "fedramp-certification-package-overview-schema-2026-06-24.json").read_text())
    out = _tpr.cpo_third_party_information_resources()
    jsonschema.validate(out, schema["properties"]["thirdPartyInformationResources"])
    assert len(out["nonCertified"]) == len(TPR["components"])


# --- FRC-CSX-MAS: every KSI applies to the scope, every component type is covered -------

def test_component_type_in_no_ksi_domain_fails():
    _, _, problems = mas.ksi_application(json.loads((FIX / "signal-gaps.json").read_text()), {})
    assert any("mystery" in p for p in problems)


def test_every_ksi_applies_and_every_component_type_is_covered():
    ka, per_type, problems = mas.ksi_application(SIGNAL, INPUTS["whole_set_types"])
    assert problems == []
    assert {k["ksi"] for k in ka} == {k["id"] for k in SIGNAL["ksis"]}
    assert all(k["components"] > 0 or k["applies_to"] == "whole set" for k in ka)
    assert set(per_type) == {c["type"] for c in SIGNAL["components"]}


def test_audit_trail_is_in_the_logging_ksi_domain():
    assert "audit_log_trail" in bks.KSI_FAMILY_EVIDENCE_TYPES["MLA"]


# --- the deploy builds it before the SDR and publishes it signed ------------------------

WF = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()


def test_deploy_builds_the_scope_before_the_sdr_and_publishes_it():
    build = WF.index("- name: Build the Minimum Assessment Scope")
    sdr = WF.index("- name: Build Security Decision Record (SDR")
    assert build < sdr
    gate = WF[WF.index("- name: Publication redaction gate (no AWS account ID)"):WF.index("- name: Publish all signed artifacts")]
    publish = WF[WF.index("- name: Publish all signed artifacts"):WF.index("- name: Attest artifact provenance")]
    assert "minimum-assessment-scope" in gate and "minimum-assessment-scope" in publish
    assert "--bundle minimum-assessment-scope.bundle minimum-assessment-scope.json" in WF
