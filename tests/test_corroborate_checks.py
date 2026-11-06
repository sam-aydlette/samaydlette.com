"""The corroboration sections beyond the boundary map (rampart-corroboration/2).

Each section is a pure judge over facts read from TAP or an upstream source.
Every section has a committed known-bad fixture under tests/fixtures/corroboration/
that must come out `differs`, and a check that a section which compared nothing
is `not_checked`, never `agrees`.
"""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIX = REPO / "tests" / "fixtures" / "corroboration"
sys.path.insert(0, str(REPO / "tools" / "boundary-map"))
import corroborate_checks as ck  # noqa: E402

spec = importlib.util.spec_from_file_location("corr_v2", REPO / "tools" / "boundary-map" / "corroborate.py")
corr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corr)


def fx(name):
    return json.loads((FIX / name).read_text())


# --- signatures ------------------------------------------------------------------

def test_signed_artifacts_come_from_the_governed_config_without_the_report_itself():
    arts = ck.signed_artifacts(json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json").read_text()))
    paths = {a["artifact"] for a in arts}
    assert ".well-known/boundary-corroboration.json" not in paths   # would verify itself
    assert ".well-known/ksi-signal-runtime.json" not in paths       # KMS-signed; its own section
    assert ".well-known/vdr-status.json" not in paths               # unsigned
    assert {a["cadence"] for a in arts} == {"deploy", "nightly"}
    # The POA&M attestation is retired; the SDR's replaced the retired SSP's.
    assert sum(a["kind"] == "dsse" for a in arts) == 4
    assert all(a.get("bundle") for a in arts if a["kind"] == "bundle")


def test_expected_identities_are_the_files_writers_not_its_cadence():
    """From scripts/_signers.py, which tests/test_publishers.py holds to the
    workflows' publish steps."""
    import _signers
    wf = "https://github.com/sam-aydlette/samaydlette.com/.github/workflows/"
    assert ck.expected_identities(".well-known/ksi-signal.json") == [wf + "deploy-with-opa.yml@refs/heads/main"]
    assert ck.expected_identities(".well-known/ocr-issues.json") == [wf + "package-maintenance.yml@refs/heads/main"]
    assert ck.expected_identities(".well-known/vdr-report.json") == [wf + "deploy-with-opa.yml@refs/heads/main",
                                                                    wf + "evidence-nightly.yml@refs/heads/main"]
    arts = ck.signed_artifacts(json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json").read_text()))
    for a in arts:
        assert a["identities"] == [_signers.IDENTITIES[k] for k in _signers.signers(a["artifact"])], a["artifact"]


def test_known_bad_a_file_signed_by_a_workflow_that_does_not_write_it_differs():
    f = fx("signatures-by-writer.json")
    s = ck.judge_signatures(f["facts"], f["artifacts"])
    assert s["compared"] == 6
    assert sorted((x["artifact"], x["problem"]) for x in s["findings"]) == [
        ("ocr-issues.json", "signed by an unexpected identity"),
        ("vdr-report.json", "signed by an unexpected identity")]


def test_known_bad_signatures_differ_on_each_artifact():
    f = fx("signatures-bad.json")
    s = ck.judge_signatures(f["facts"], f["artifacts"])
    assert s["status"] == "differs" and s["compared"] == 5
    by = {}
    for x in s["findings"]:
        by.setdefault(x["artifact"], []).append(x["problem"])
    assert by == {"a.json": ["signature does not verify"],
                  "b.json": ["signed by an unexpected identity"],
                  "c.json.intoto.jsonl": ["attestation subject is not the published artifact"],
                  "d.json": ["signed from a ref other than main"]}


def test_good_signatures_agree_and_an_unfetched_one_is_not_checked():
    f = fx("signatures-bad.json")
    arts = [a for a in f["artifacts"] if a["artifact"].endswith("e.json")]
    good = [x for x in f["facts"] if x["artifact"].endswith("e.json")]
    assert ck.judge_signatures(good, arts)["status"] == "agrees"
    s = ck.judge_signatures([], arts)
    assert s["status"] == "not_checked" and s["not_checked"][0]["artifact"] == "e.json"


# --- provenance --------------------------------------------------------------------

def test_known_bad_provenance_differs_and_names_commits_not_run_ids():
    f = fx("provenance-bad.json")
    s = ck.judge_provenance(f["facts"], f["runs"], f["workflows"], 10)
    assert s["status"] == "differs" and s["compared"] == 2
    probs = sorted(p for x in s["findings"] for p in x["problems"])
    assert probs == ["GitHub records the run at a different commit",
                     "GitHub records the run under a different workflow",
                     "the run concluded failure"]
    assert len(s["not_checked"]) == 1   # run 333 is outside TAP's window; 444 never verified
    text = json.dumps(s)
    for run_id in ("111", "222", "333", "444"):
        assert f"/runs/{run_id}" not in text and f'"{run_id}"' not in text


def test_provenance_with_no_run_in_window_is_not_checked():
    f = fx("provenance-bad.json")
    assert ck.judge_provenance(f["facts"], [], f["workflows"], 10)["status"] == "not_checked"


# --- live_configuration --------------------------------------------------------------

def test_known_bad_live_configuration_differs_on_every_claimed_property():
    f = fx("live-configuration-bad.json")
    claims = ck.live_claims(f["signal"], f["tag_config"])
    s = ck.judge_live(claims, f["live"], f["group_members"])
    assert s["status"] == "differs"
    got = sorted((x["component"], x["property"]) for x in s["findings"])
    assert got == [
        ("aws::audit_log_trail::management", "is_logging"),
        ("aws::iam_group::ops", "members_have_mfa"),
        ("aws::iam_role::ci", "trusted_services"),
        ("aws::iam_role::ci", "trusts_wildcard_principal"),
        ("aws::iam_role::deploy", "trusted_services"),
        ("aws::identity_provider::users", "mfa_configuration"),
        ("aws::log_group::app", "retention_in_days"),
        ("aws::object_store::data", "classification_tags_present"),
        ("aws::object_store::data", "public_access_blocked"),
        ("aws::object_store::data", "tags_present"),
        ("aws::object_store::data", "versioning"),
        ("aws::object_store::site", "served_through_oac"),
    ]
    # The collector left encryption empty: not checked, never a pass or a failure.
    assert [(x["component"], x["property"]) for x in s["not_checked"]] == [("aws::object_store::data", "encryption")]
    assert s["not_covered"]


def test_live_claims_are_only_what_is_published():
    f = fx("live-configuration-bad.json")
    sig = copy.deepcopy(f["signal"])
    for c in sig["components"]:
        c["attributes"]["baseline_configuration"] = "AWS default"
    sig["validations"] = []
    assert ck.live_claims(sig, f["tag_config"]) == []


def test_live_claims_cite_their_source():
    f = fx("live-configuration-bad.json")
    for cl in ck.live_claims(f["signal"], f["tag_config"]):
        assert "ksi-signal.json" in cl["claim"]
        if cl["property"] in ("tags_present", "classification_tags_present", "encryption"):
            assert "infrastructure/policy/" in cl["claim"]


def test_group_members_are_counted_never_named():
    f = fx("live-configuration-bad.json")
    claims = [c for c in ck.live_claims(f["signal"], f["tag_config"]) if c["property"] == "members_have_mfa"]
    members = {"aws::iam_group::ops": [{"console": True, "mfa_enabled": False, "UserName": "someone@example.com"}]}
    s = ck.judge_live(claims, {}, members)
    assert s["findings"][0]["observed"] == "1 of 1 console member(s) have no MFA device"
    assert "example.com" not in json.dumps(s)
    assert ck.judge_live(claims, {}, {"aws::iam_group::ops": None})["status"] == "not_checked"


def test_machine_members_without_a_console_password_need_no_mfa():
    f = fx("live-configuration-bad.json")
    claims = [c for c in ck.live_claims(f["signal"], f["tag_config"]) if c["property"] == "members_have_mfa"]
    machine = {"aws::iam_group::ops": [{"console": False, "mfa_enabled": False}, {"console": True, "mfa_enabled": True}]}
    assert ck.judge_live(claims, {}, machine)["status"] == "agrees"
    unknown = {"aws::iam_group::ops": [{"mfa_enabled": False}]}  # console sign-in not read: never assumed machine
    assert ck.judge_live(claims, {}, unknown)["status"] == "not_checked"


def test_a_github_oidc_role_claim_agrees_only_with_no_service_and_no_wildcard():
    f = fx("live-configuration-bad.json")
    claims = [c for c in ck.live_claims(f["signal"], f["tag_config"]) if c["component"] == "aws::iam_role::ci"]
    assert {c["property"] for c in claims} == {"trusted_services", "trusts_wildcard_principal"}
    good = {"aws::iam_role::ci": {"trusted_services": [], "trusts_wildcard_principal": False}}
    assert ck.judge_live(claims, good, {})["status"] == "agrees"


def test_oac_is_derived_from_the_distribution_origins():
    tap = {"entities": [
        {"id": "b", "type": "s3_bucket", "fields": {"name": "site.example"}},
        {"id": "d", "type": "cloudfront_distribution", "fields": {"origin_access": {"S3-site.example": "oai", "api": "none"}}}]}
    sig = {"components": [{"component_id": "aws::object_store::site", "type": "object_store"}]}
    assert ck.live_values(tap, {"b": "aws::object_store::site"}, sig)["aws::object_store::site"]["served_through_oac"] is False
    tap["entities"][1]["fields"]["origin_access"]["S3-site.example"] = "oac"
    assert ck.live_values(tap, {"b": "aws::object_store::site"}, sig)["aws::object_store::site"]["served_through_oac"] is True


# --- runtime_signing_key -----------------------------------------------------------

def test_known_bad_signing_key_differs():
    f = fx("signing-key-mismatch.json")
    kms = ck.der_sha256_of_pem(f["key_a"])
    s = ck.judge_signing_key(kms, f["key_a"], {"public_key_pem": f["key_b"]}, {"verified": True, "fresh": True})
    assert s["status"] == "differs"
    assert [x["problem"] for x in s["findings"]] == [
        "the key pinned in infrastructure/keys/runtime-signing-key.json is not the key KMS holds"]
    s = ck.judge_signing_key(kms, f["key_b"], {"public_key_pem": f["key_a"]}, {"verified": True, "fresh": True})
    assert [x["problem"] for x in s["findings"]] == ["the published runtime-signing-pubkey.pem is not the key KMS holds"]


def test_signing_key_not_read_is_not_checked():
    assert ck.judge_signing_key(None, "x", {}, None)["status"] == "not_checked"


def test_committed_pin_matches_the_published_key_shape():
    pinned = json.loads((REPO / "infrastructure" / "keys" / "runtime-signing-key.json").read_text())
    assert len(ck.der_sha256_of_pem(pinned["public_key_pem"])) == 64


def _signed_runtime(tmp_path, tamper=False):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from datetime import datetime, timezone
    key = ec.generate_private_key(ec.SECP256R1())
    body = {"emitted_at": datetime.now(timezone.utc).isoformat(), "provenance": {"emitter": "test"}, "validations": []}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    sig = key.sign(canon, ec.ECDSA(hashes.SHA256()))
    doc = copy.deepcopy(body)
    doc["provenance"]["attestation"] = {"signature": base64.b64encode(sig).decode()}
    if tamper:
        doc["validations"] = [{"x": 1}]
    p = tmp_path / "rt.json"
    p.write_text(json.dumps(doc))
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return p, pem


def test_runtime_signal_is_verified_with_the_builders_code_against_the_kms_key(tmp_path):
    p, pem = _signed_runtime(tmp_path)
    r = corr.verify_runtime_with(pem, p, tmp_path)
    assert r["verified"] is True and r["fresh"] is True
    kms = ck.der_sha256_of_pem(pem)
    assert ck.judge_signing_key(kms, pem, {"public_key_pem": pem}, r)["status"] == "agrees"


def test_a_tampered_runtime_signal_differs(tmp_path):
    p, pem = _signed_runtime(tmp_path, tamper=True)
    r = corr.verify_runtime_with(pem, p, tmp_path)
    assert r["verified"] is False
    s = ck.judge_signing_key(ck.der_sha256_of_pem(pem), pem, {"public_key_pem": pem}, r)
    assert s["status"] == "differs"


# --- vulnerabilities -------------------------------------------------------------------

def test_known_bad_vulnerabilities_differ():
    f = fx("vulnerabilities-bad.json")
    s = ck.judge_vulnerabilities("observed", f["alerts"], f["vdr"])
    assert s["status"] == "differs" and s["compared"] == 2
    assert [x["advisory"] for x in s["findings"]] == ["CVE-2026-0001"]


def test_unreadable_dependabot_is_not_checked_and_an_empty_readable_one_agrees():
    f = fx("vulnerabilities-bad.json")
    assert ck.judge_vulnerabilities("unobservable", [], f["vdr"])["status"] == "not_checked"
    assert ck.judge_vulnerabilities("", None, f["vdr"])["status"] == "not_checked"
    assert ck.judge_vulnerabilities("observed", [], f["vdr"])["status"] == "agrees"


# --- ksi_catalog ------------------------------------------------------------------------

def test_known_bad_ksi_catalog_differs():
    f = fx("ksi-catalog-bad.json")
    s = ck.judge_ksi_catalog(f["signal"], f["upstream"], "h" * 40, "p" * 40)
    assert s["status"] == "differs"
    assert [x["ksi"] for x in s["findings"]] == ["KSI-ZZZ-FAK"]
    assert s["upstream_not_claimed"] == ["KSI-CMT-RMV"]


def test_ksi_ids_are_read_from_the_vendored_rules():
    rules = json.loads((REPO / "infrastructure" / "schemas" / "fedramp-rules" / "fedramp-consolidated-rules.json").read_text())
    assert len(ck.ksi_ids(rules)) >= 40


def test_unreadable_or_reshaped_upstream_is_not_checked():
    f = fx("ksi-catalog-bad.json")
    assert ck.judge_ksi_catalog(f["signal"], None, None, "p")["status"] == "not_checked"
    assert ck.judge_ksi_catalog(f["signal"], {"KSI": {}}, "h", "p")["status"] == "not_checked"


# --- the whole report ---------------------------------------------------------------------

def test_overall_result_needs_every_section():
    agree = {"status": "agrees"}
    full = {k: agree for k in ck.SECTION_ORDER}
    assert ck.overall(full) == "agrees"
    assert ck.overall({**full, "vulnerabilities": {"status": "not_checked"}}) == "incomplete"
    assert ck.overall({**full, "signatures": {"status": "differs"}, "vulnerabilities": {"status": "not_checked"}}) == "differs"
    assert ck.overall({k: agree for k in ck.SECTION_ORDER[:-1]}) == "incomplete"


def test_a_section_that_compared_nothing_never_agrees():
    assert ck.section([], 0, source="s")["status"] == "not_checked"
    assert ck.section([], 3, [{"why": "x"}], source="s")["status"] == "not_checked"
    assert ck.section([{"x": 1}], 3, [{"why": "x"}], source="s")["status"] == "differs"


def test_assemble_keeps_the_boundary_keys_and_adds_sections():
    rep = {"result": "agrees", "summary": {"in_scope": 2, "relationships_compared": 1}, "tap_only": [], "map_only": [],
           "tag_differences": [], "relationships_tap_only": []}
    out = corr.assemble(rep, {k: {"status": "agrees"} for k in ck.SECTION_ORDER if k != "boundary"})
    assert out["boundary_result"] == "agrees" and out["result"] == "agrees"
    assert list(out["checks"]) == list(ck.SECTION_ORDER)
    assert out["checks"]["boundary"]["compared"] == 3
    out = corr.assemble({**rep, "result": "agrees"}, {"signatures": {"status": "agrees"}})
    assert out["result"] == "incomplete"


def test_the_container_reader_returns_booleans_per_member_only():
    # Member names never leave the container: each member is {"console": bool, "mfa_enabled": bool}.
    assert 'members.append({"console": console,' in corr.READ_FACTS
    assert '"mfa_enabled": bool(iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"])})' in corr.READ_FACTS


def test_the_committed_v2_report_is_safe_and_complete():
    path = REPO / "docs" / "boundary" / "corroboration.json"
    doc = json.loads(path.read_text())
    corr.check_redaction(path.read_text())
    assert doc["schema"] == "rampart-corroboration/2"
    assert list(doc["checks"]) == list(ck.SECTION_ORDER)
    assert doc["result"] == ck.overall(doc["checks"])
    for s in doc["checks"].values():
        assert s["status"] in ("agrees", "differs", "not_checked") and s["source"]

