"""The simulated assessor ("Totally Real Assessment Services, LLC (simulated)")
and the keyless assessor port (IVV-CSO-FIA, IVV-CSO-ICP, IVV-CSX-AIA,
CPO-CSO-OSA, SDR-CSO-FRR).

The assessor re-runs every cited check from the provider's assessor guide and
writes one signed set; the provider accepts the set only when its Sigstore
bundle verifies against the pinned assessor identity and every record is bound
to it, and the SDR carries every record verbatim. It is plainly labelled as a
simulation and claims no FedRAMP recognition.
"""
import copy
import importlib.util
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "assessor"
WF = REPO / ".github" / "workflows"
IDENTITY = REPO / "infrastructure" / "keys" / "assessor-identity.json"
sys.path.insert(0, str(REPO / "scripts"))
import _assessor  # noqa: E402

spec = importlib.util.spec_from_file_location("assess", REPO / "tools" / "simulated-assessor" / "assess.py")
assess = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assess)

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)
SITE = "https://samaydlette.com"
SIG = "00000000-0000-4000-8000-000000000001"
BIND = {"expect_commit": "0" * 40, "expect_signal_id": SIG}  # what the fixture set covers


def ok(*_a):
    return True


def _set(tmp_path, fixture="simulated-set.json"):
    s = tmp_path / "simulated-assessment.json"
    s.write_text((FIX / fixture).read_text())
    b = tmp_path / "simulated-assessment.bundle"
    b.write_text("{}")
    return s, b


# --- the provider accepts only the pinned assessor's signed set ------------------------

def test_genuine_set_loads_and_carries_an_overall_summary(tmp_path):
    recs = _assessor.load_assessment(*_set(tmp_path), IDENTITY, verifier=ok, **BIND)
    assert len(recs) == 4
    summary = _assessor.overall_summary(recs)
    assert summary["kind"] == "summary" and "IVV-IAS-OSA" in summary["text"]


def test_known_bad_tampered_record_fails(tmp_path):
    with pytest.raises(SystemExit, match="differs from the record the assessor signed"):
        _assessor.load_assessment(*_set(tmp_path, "simulated-set-tampered.json"), IDENTITY, verifier=ok, **BIND)


def test_set_whose_signature_does_not_verify_fails(tmp_path):
    with pytest.raises(SystemExit, match="does not verify"):
        _assessor.load_assessment(*_set(tmp_path), IDENTITY, verifier=lambda *_a: False, **BIND)


@pytest.mark.parametrize("missing", ["set", "bundle"])
def test_missing_assessment_fails_the_build(tmp_path, missing):
    s, b = _set(tmp_path)
    (s if missing == "set" else b).unlink()
    with pytest.raises(SystemExit, match="missing"):
        _assessor.load_assessment(s, b, IDENTITY, verifier=ok, **BIND)


def test_set_from_another_assessor_fails(tmp_path):
    s, b = _set(tmp_path)
    doc = json.loads(s.read_text())
    doc["assessor"]["organization"] = "Some Other Auditor"
    s.write_text(json.dumps(doc))
    with pytest.raises(SystemExit, match="not the pinned assessor"):
        _assessor.load_assessment(s, b, IDENTITY, verifier=ok, **BIND)


def test_set_without_an_overall_summary_fails(tmp_path):
    s, b = _set(tmp_path)
    doc = json.loads(s.read_text())
    doc["records"] = [r for r in doc["records"] if r["kind"] != "summary"]
    s.write_text(json.dumps(doc))
    with pytest.raises(SystemExit, match="overall summary"):
        _assessor.load_assessment(s, b, IDENTITY, verifier=ok, **BIND)


def test_cosign_is_asked_for_exactly_the_pinned_identity(tmp_path, monkeypatch):
    seen = {}

    def fake_run(argv, **_kw):
        seen["argv"] = argv

        class R:
            returncode = 0
        return R()
    monkeypatch.setattr(_assessor.subprocess, "run", fake_run)
    ident = _assessor.load_keyless_identity(IDENTITY)
    assert _assessor.cosign_verify("s.json", "s.bundle", ident)
    argv = seen["argv"]
    assert argv[argv.index("--certificate-identity") + 1] == ident["certificate_identity"]
    assert "--certificate-identity-regexp" not in argv


def test_keyless_identity_refuses_loose_record_files(tmp_path):
    d = tmp_path / "records"
    d.mkdir()
    (d / "genuine.json").write_text((FIX / "genuine.json").read_text())
    with pytest.raises(SystemExit, match="keyless"):
        _assessor.load_records(d, IDENTITY)


def test_set_records_match_the_published_record_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((REPO / "infrastructure" / "schemas" / "assessor-record.schema.json").read_text())
    for rec in json.loads((FIX / "simulated-set.json").read_text())["records"]:
        jsonschema.validate(rec, schema)


# --- the SDR carries every rule's and KSI's independent result verbatim ----------------

def test_every_rule_and_ksi_gets_its_independent_result_and_t74_holds(tmp_path):
    recs = _assessor.load_assessment(*_set(tmp_path), IDENTITY, verifier=ok, **BIND)
    pseudo = [{"rule_id": i, "assessor_comment_responses": []} for i in ("SDR-CSO-FRR", "CDS-CSO-RPS", "KSI-CED-RAT")]
    block = _assessor.attach(pseudo, recs)
    assert all(len(p["assessor_comment_responses"]) == 1 for p in pseudo)
    assert [r["kind"] for r in block["records"]] == ["summary"]
    by_rule = {p["rule_id"]: p["assessor_comment_responses"] for p in pseudo}
    sdr = {"providerExtensions": {"assessorRecords": block, "assessorCommentResponses": by_rule}}
    _assessor.verify_output(sdr, recs)
    text = by_rule["SDR-CSO-FRR"][0]["text"]
    assert "Independent verification:" in text and "Independent validation:" in text
    bad = copy.deepcopy(sdr)
    bad["providerExtensions"]["assessorCommentResponses"]["SDR-CSO-FRR"][0]["text"] = "Softened."
    with pytest.raises(SystemExit):
        _assessor.verify_output(bad, recs)


# --- the assessor's own checks ---------------------------------------------------------

def _guide(**art):
    chk = {"url": f"{SITE}/.well-known/security-decision-record.json",
           "bundle_url": f"{SITE}/.well-known/security-decision-record.bundle", "identities": ["deploy"],
           "timestamp": {"source": "json", "field": "emitted_at"}, "max_age_hours": 720, **art}
    return {"site": SITE, "fedRampId": "Example Provider (EXD)",
            "identities": {"deploy": "D", "nightly": "N", "assessor": "A", "oidc_issuer": "I"},
            "rules": [{"rule_id": "SDR-CSO-FRR", "force": "MUST", "status": "Implemented", "evidence": [
                {"kind": "test", "ref": "tests/t.py::test_a", "check": {"pytest": "tests/t.py::test_a"}},
                {"kind": "artifact", "ref": ".well-known/security-decision-record.json", "check": {"artifact": chk}}]},
                {"rule_id": "CDS-CSO-RPS", "force": "MAY", "status": "Not Applicable",
                 "not_applicable": "not exercised", "evidence": []}],
            "ksis": [{"ksi_id": "KSI-CED-RAT"}]}


def _get(age_hours=3, status=200, signal_has_ksi=True, ksi_status="pass"):
    emitted = (NOW - timedelta(hours=age_hours)).isoformat()

    def get(url):
        if url.endswith("ksi-signal.json"):
            ks = [{"id": "KSI-CED-RAT", "status": ksi_status, "method": "documentation"}] if signal_has_ksi else []
            return 200, json.dumps({"signal_id": "sig-1", "ksis": ks}).encode(), {}
        if url.endswith(".bundle"):
            return 200, b"{}", {}
        return status, json.dumps({"emitted_at": emitted}).encode(), {}
    return get


def _run(guide, tests_result="passed", verify=ok, **get_kw):
    a = assess.Assessor(guide, str(REPO), NOW, get=_get(**get_kw), verify=verify,
                        tests=lambda refs, _repo: {r: tests_result for r in refs})
    return a.assess()


def test_a_sound_package_passes_every_rule_and_ksi():
    rules, ksis = _run(_guide())
    assert [(r[0], r[1]) for r in rules] == [("SDR-CSO-FRR", "pass"), ("CDS-CSO-RPS", "pass")]
    assert ksis[0][1] == "pass"


def test_a_cited_test_failing_on_the_assessor_rerun_is_a_failure():
    rules, _ = _run(_guide(), tests_result="failed")
    assert rules[0][1] == "fail"


def test_a_published_artifact_whose_signature_fails_is_a_failure():
    rules, _ = _run(_guide(), verify=lambda *_a: False)
    assert rules[0][1] == "fail"
    _, ksis = _run(_guide(), verify=lambda *_a: False)
    assert ksis[0][1] == "fail"


def test_a_ksi_the_signal_does_not_report_passing_is_a_failure():
    _, ksis = _run(_guide(), ksi_status="fail")
    assert ksis[0][1] == "fail" and "'fail'" in ksis[0][2][0]


def test_dotted_timestamp_fields_are_read():
    body = json.dumps({"metadata": {"lastUpdated": (NOW - timedelta(hours=2)).isoformat()}}).encode()
    age = assess._age_hours(body, {}, {"source": "json", "field": "metadata.lastUpdated"}, NOW)
    assert round(age) == 2


@pytest.mark.parametrize("kw,needle", [({"status": 404}, "not yet published"), ({"age_hours": 900}, "past its")])
def test_unpublished_or_stale_artifacts_are_observations_not_failures(kw, needle):
    rules, _ = _run(_guide(), **kw)
    assert rules[0][1] == "observation" and needle in rules[0][3][0]


def test_status_short_of_complete_fails():
    g = _guide()
    g["rules"][0]["status"] = "Partially Implemented"
    rules, _ = _run(g)
    assert rules[0][1] == "fail"


def test_main_exits_non_zero_on_any_failure(tmp_path, monkeypatch):
    g = tmp_path / "guide.json"
    g.write_text(json.dumps(_guide()))
    monkeypatch.setattr(assess, "http_get", _get())
    monkeypatch.setattr(assess, "cosign_verify", ok)
    monkeypatch.setattr(assess, "run_tests", lambda refs, _r: {r: "failed" for r in refs})
    out = tmp_path / "set.json"
    assert assess.main(["--guide", str(g), "--output", str(out)]) == 1
    doc = json.loads(out.read_text())
    assert doc["results"]["rules"]["fail"] == 1


def test_the_set_round_trips_through_the_provider_port(tmp_path):
    rules, ksis = _run(_guide())
    doc = assess.build_set(_guide(), rules, ksis, NOW, "0" * 40, "f" * 64, {"signal_id": SIG, "commit": "f" * 40})
    s = tmp_path / "simulated-assessment.json"
    s.write_text(json.dumps(doc))
    b = tmp_path / "simulated-assessment.bundle"
    b.write_text("{}")
    recs = _assessor.load_assessment(s, b, IDENTITY, verifier=ok, **BIND)
    assert {r.get("rule_id") for r in recs} == {"SDR-CSO-FRR", "CDS-CSO-RPS", "KSI-CED-RAT", None}


def test_the_assessor_runs_cited_tests_itself():
    res = assess.run_tests({"tests/test_frr_evidence.py::test_all_cited_tests_passing_is_a_pass",
                            "tests/test_frr_evidence.py::test_no_such_test"}, str(REPO))
    assert res == {"tests/test_frr_evidence.py::test_all_cited_tests_passing_is_a_pass": "passed",
                   "tests/test_frr_evidence.py::test_no_such_test": "not run"}


# --- it is obviously a simulation and claims nothing ------------------------------------

def test_the_simulation_is_labelled_and_claims_no_fedramp_recognition():
    ident = json.loads(IDENTITY.read_text())
    doc = json.loads((FIX / "simulated-set.json").read_text())
    assert ident["simulated"] is True and "(simulated)" in ident["assessor"]
    assert doc["simulated"] is True and doc["fedramp_recognized"] is False
    assert doc["assessor_id"] == "NOT-A-REAL-ASSESSOR-ID"
    assert not re.fullmatch(r"\d{6}", doc["assessor_id"])  # never shaped like a FedRAMP assessor ID
    for rec in doc["records"]:
        assert "SIMULATED" in rec["text"]
        assert "not a FedRAMP Recognized" in rec["text"] or "not a FedRAMP Recognized" in assess.DISCLAIMER


def test_the_pinned_identity_is_the_assessor_workflow_not_the_deploy():
    ident = _assessor.load_keyless_identity(IDENTITY)
    assert ident["certificate_identity"] == (
        "https://github.com/sam-aydlette/samaydlette.com/.github/workflows/simulated-assessor.yml@refs/heads/main")
    assert ident["certificate_oidc_issuer"] == "https://token.actions.githubusercontent.com"


# --- wiring: runs on every deploy, before the SDR, and the deploy needs it --------------

def _deploy():
    return (WF / "deploy-with-opa.yml").read_text()


def test_the_deploy_needs_the_assessor_and_builds_the_sdr_from_its_set():
    wf = _deploy()
    job = wf.split("\n  simulated-assessor:\n", 1)[1].split("\n  # ====", 1)[0]
    assert "uses: ./.github/workflows/simulated-assessor.yml" in job
    deploy_job = wf.split("\n  deploy:\n", 1)[1]
    assert re.search(r"needs: \[[^\]]*simulated-assessor[^\]]*\]", deploy_job)
    sdr_step = deploy_job.split("- name: Build Security Decision Record", 1)[1].split("\n    - name:", 1)[0]
    assert sdr_step.count("--assessment simulated-assessment.json") == 2  # build and T74 re-check
    assert deploy_job.index("- name: Download the simulated assessment") < deploy_job.index(
        "- name: Build Security Decision Record")


def test_the_assessor_workflow_holds_no_cloud_credentials_and_signs_as_itself():
    wf = (WF / "simulated-assessor.yml").read_text()
    assert "workflow_call" in wf
    assert "configure-aws-credentials" not in wf and "secrets." not in wf
    assert "id-token: write" in wf
    assert "cosign sign-blob" in wf and "cosign verify-blob" in wf


def test_only_the_job_that_installs_nothing_but_cosign_can_sign():
    wf = (WF / "simulated-assessor.yml").read_text()
    assess_job, sign_job = wf.split("\n  assess:\n", 1)[1].split("\n  sign:\n", 1)
    assert "id-token: write" not in assess_job
    assert "pip install" not in sign_job and "id-token: write" in sign_job
    assert "cosign sign-blob" in sign_job and "cosign sign-blob" not in assess_job
    assert "needs: [assess]" in sign_job


def test_the_assessor_workflow_pins_the_same_opa_as_the_deploy():
    def pins(text):
        return {k: re.search(rf"^\s*{k}: (\S+)", text, re.M).group(1) for k in ("OPA_VERSION", "OPA_SHA256")}
    assert pins((WF / "simulated-assessor.yml").read_text()) == pins(_deploy())


@pytest.mark.parametrize("url", ["file:///etc/passwd", "http://samaydlette.com/.well-known/x.json",
                                 "https://example.org/.well-known/x.json"])
def test_the_assessor_fetches_only_https_from_the_providers_site(url):
    with pytest.raises(SystemExit, match="refusing to fetch"):
        assess.http_get(url)


def test_the_set_names_the_offering_and_a_guide_without_an_id_fails(tmp_path):
    g = _guide()
    doc = assess.build_set(g, *_run(g), NOW, "0" * 40, "f" * 64)
    assert doc["fedRampId"] == "Example Provider (EXD)"
    del g["fedRampId"]
    with pytest.raises(SystemExit, match="CDS-CSO-FID"):
        assess.build_set(g, *_run(g), NOW, "0" * 40, "f" * 64)


# --- binding: an assessment is evidence only for the state it covered ---------------------

@pytest.mark.parametrize("fixture,needle", [("simulated-set-other-commit.json", "not the stated commit"),
                                            ("simulated-set-other-signal.json", "not the stated signal")])
def test_known_bad_a_set_covering_another_commit_or_signal_is_refused(tmp_path, fixture, needle):
    with pytest.raises(SystemExit, match=needle):
        _assessor.load_assessment(*_set(tmp_path, fixture), IDENTITY, verifier=ok, **BIND)


@pytest.mark.parametrize("missing", ["expect_commit", "expect_signal_id"])
def test_an_unbound_assessment_is_refused(tmp_path, missing):
    with pytest.raises(SystemExit, match="unbound assessment is refused"):
        _assessor.load_assessment(*_set(tmp_path), IDENTITY, verifier=ok, **dict(BIND, **{missing: None}))


def test_the_cli_refuses_a_set_for_another_commit(tmp_path, monkeypatch):
    monkeypatch.setattr(_assessor, "cosign_verify", ok)
    s, b = _set(tmp_path, "simulated-set-other-commit.json")
    argv = ["--assessment", str(s), "--assessment-bundle", str(b), "--identity", str(IDENTITY),
            "--assessment-commit", "0" * 40, "--assessment-signal-id", SIG]
    with pytest.raises(SystemExit, match="not the stated commit"):
        _assessor.main(argv)


def test_the_set_records_the_commit_signal_and_phase_it_covered():
    signal = {"signal_id": SIG, "commit": "f" * 40}
    g = _guide()
    a = assess.Assessor(g, str(REPO), NOW, get=_get(), verify=ok, tests=lambda refs, _r: {r: "passed" for r in refs})
    rules, ksis = a.assess()
    assert a.signal == {"signal_id": "sig-1", "commit": None}
    doc = assess.build_set(g, rules, ksis, NOW, "0" * 40, "f" * 64, signal, "post-deploy")
    assert doc["subject"]["commit"] == "0" * 40 and doc["subject"]["signal_id"] == SIG
    assert doc["subject"]["phase"] == "post-deploy" and doc["subject"]["signal_commit"] == "f" * 40
    summary = next(r for r in doc["records"] if r["kind"] == "summary")["text"]
    assert "post-deploy assessment" in summary and SIG in summary


def _post(get):
    return assess.Assessor(_guide(), str(REPO), NOW, get=get, verify=ok, phase="post-deploy", commit="a" * 40,
                           tests=lambda refs, _r: {r: "passed" for r in refs}).assess()


def test_after_the_deploy_the_live_signal_must_carry_the_deployed_commit():
    base = _get()

    def get(url, commit):
        status, body, h = base(url)
        if url.endswith("ksi-signal.json"):
            doc = json.loads(body)
            doc["provenance"] = {"source": {"commit": commit}}
            body = json.dumps(doc).encode()
        return status, body, h
    _, ksis = _post(lambda u: get(u, "b" * 40))
    assert ksis[0][1] == "fail" and "not the deployed commit" in ksis[0][2][0]
    _, ksis = _post(lambda u: get(u, "a" * 40))
    assert ksis[0][1] == "pass"


def test_after_the_deploy_an_unpublished_artifact_is_recorded_and_a_bad_signature_fails():
    rules, _ = _post(_get(status=404))
    assert rules[0][1] == "observation" and "not published after the deploy" in rules[0][3][0]
    rules, _ = assess.Assessor(_guide(), str(REPO), NOW, get=_get(), verify=lambda *_a: False, phase="post-deploy",
                               commit="a" * 40, tests=lambda refs, _r: {r: "passed" for r in refs}).assess()
    assert rules[0][1] == "fail"


def test_the_sdr_states_which_commit_and_signal_its_assessment_covered(tmp_path):
    spec2 = importlib.util.spec_from_file_location("build_sdr_cov", REPO / "scripts" / "build-sdr.py")
    sdr = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(sdr)
    _, subject = _assessor.load_assessment_with_subject(*_set(tmp_path), IDENTITY, verifier=ok, **BIND)
    cov = sdr.assessment_coverage(subject)
    assert cov["commit"] == "0" * 40 and cov["signalId"] == SIG and cov["phase"] == "pre-deploy"
    assert "0" * 40 in cov["statement"] and SIG in cov["statement"] and "after publishing" in cov["statement"].lower()


def _jobs():
    import yaml
    return yaml.safe_load(_deploy())["jobs"]


def test_the_deploy_binds_the_pre_deploy_set_to_this_commit_and_the_live_signal():
    deploy_job = _deploy().split("\n  deploy:\n", 1)[1]
    for name in ("- name: Build Security Decision Record", "- name: Build Certification Package Overview (CPO)"):
        step = deploy_job.split(name, 1)[1].split("\n    - name:", 1)[0]
        assert step.count('--assessment-signal-id "$ASSESSED_SIGNAL_ID"') == step.count("--assessment simulated")
        assert step.count("--assessment-commit") == step.count("--assessment simulated")
    bind = deploy_job.index("- name: Bind the pre-deploy assessment to the state it covered")
    assert bind < deploy_job.index("- name: Build Security Decision Record")
    assert bind < deploy_job.index("- name: Publish")  # read before anything under /.well-known/ is replaced


def test_a_post_deploy_assessment_runs_after_publish_and_its_failure_alerts():
    jobs = _jobs()
    post, binding = jobs["post-deploy-assessor"], jobs["post-deploy-binding"]
    assert post["uses"] == "./.github/workflows/simulated-assessor.yml" and post["with"]["phase"] == "post-deploy"
    assert {"deploy", "package-maintainer", "incident-publisher"} <= set(post["needs"])
    assert jobs["deploy"]["outputs"]["signal_id"] == "${{ steps.ksi.outputs.signal_id }}"
    run = "\n".join(s.get("run", "") for s in binding["steps"])
    assert '--assessment-commit "$GITHUB_SHA"' in run and '--assessment-signal-id "$PUBLISHED_SIGNAL_ID"' in run
    assert any(s.get("with", {}).get("name") == "simulated-assessment-post-deploy" for s in binding["steps"])
    for need in ("post-deploy-assessor", "post-deploy-binding"):
        assert need in jobs["notify"]["needs"] and f"needs.{need}.result == 'failure'" in jobs["notify"]["if"]


def test_the_two_phases_upload_distinct_artifacts():
    wf = (WF / "simulated-assessor.yml").read_text()
    assert "name: simulated-assessment-${{ inputs.phase }}\n" in wf
    assert '--phase "$PHASE"' in wf
