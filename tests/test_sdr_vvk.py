"""FRC-CSX-VVK: the automated methods the SDR counts per KSI, strictly (a
method counts only when it tests that KSI's measures), and the claim check
that replaces the old two-method gate: the deploy fails only when the
FRC-CSX-VVK record claims more than the computed counts support.

Methods: an annotated OPA rule at plan and at runtime (two methods, see
test_sdr.py), and the mechanisms of infrastructure/schemas/ksi-methods.json,
each counted only when its verifier passes (scripts/_ksi_methods.py)."""
import copy
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _controls  # noqa: E402
import _decisions  # noqa: E402
import _frr  # noqa: E402
import _ksi_methods  # noqa: E402
import _rules  # noqa: E402
import _signers  # noqa: E402

spec = importlib.util.spec_from_file_location("build_sdr_vvk", REPO / "scripts" / "build-sdr.py")
sdr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdr)

FIX = REPO / "tests" / "fixtures" / "vvk"
CATALOG = json.loads((REPO / "infrastructure" / "schemas" / "ksi-catalog.json").read_text())
NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
SIGNED = (True, None)
METHODS = _ksi_methods.load()
ALL_KSIS = sorted(i["id"] for f in CATALOG["KSI"].values() for i in f["indicators"])


def _vdr(name="vdr-good.json"):
    return json.loads((FIX / name).read_text())


def _signal():
    comps = [{"component_id": "aws::function::app", "type": "function"}]
    ksis = [{"id": k, "status": "pass", "method": "policy-validation",
             "evidence": {"validation_ids": ["v-1"], "failed_validation_ids": [],
                          "component_refs": ["aws::function::app"]}} for k in ALL_KSIS]
    return {"signal_id": "sig-1", "components": comps, "ksis": ksis}


def _build(results=None, methods_doc=None, records=None, accepted=None, not_applicable=None):
    sig = _signal()
    return sdr.build(CATALOG, sig, records or _frr.load(), _rules.applicable_provider_rules(),
                     _controls.project(sig, CATALOG), sdr.moderate_ids(), {}, [], "none supplied", [],
                     {"fedramp_class": "C", "impact_level": "Moderate"}, {}, {}, NOW,
                     {"ac": "https://example.invalid/ac.md"}, methods_doc=methods_doc or METHODS,
                     results=results, accepted=accepted, not_applicable=not_applicable)


def _ext(doc):
    return {k["ksiId"]: k["providerExtensions"] for k in doc["keySecurityIndicators"]}


def _all_pass(methods_doc=METHODS):
    return {m["key"]: SIGNED for m in methods_doc["methods"]}


def _table(*methods):
    return {"schema": "ksi-methods/1", "version": "t", "description": "t", "rationale": "t",
            "methods": [{"key": k, "mechanism": k, "measure": "m", "ksis": ks, "input": inp,
                         "verifier": {"kind": "plan-gate"}} for k, ks, inp in methods]}


# --- the VDR behind a detection-feed method -------------------------------------------------

def test_a_bound_signed_fresh_vdr_is_usable():
    assert sdr.vdr_usable(_vdr(), _signal(), NOW, SIGNED, 24) == (True, None)


@pytest.mark.parametrize("fixture,signature,reason", [
    ("vdr-unbound.json", SIGNED, "not bound to this inventory"),
    ("vdr-stale.json", SIGNED, "not within its 24-hour window"),
    ("vdr-good.json", (False, "the VDR signature does not verify against the allowed identities"), "does not verify"),
])
def test_known_bad_vdrs_are_not_usable_each_for_its_reason(fixture, signature, reason):
    ok, why = sdr.vdr_usable(_vdr(fixture), _signal(), NOW, signature, 24)
    assert not ok and reason in why


@pytest.mark.parametrize("fixture,reason", [
    ("vdr-grype-failed.json", "the grype feed failed the detection gate"),
    ("vdr-no-grype.json", "lists no grype feed"),
])
def test_known_bad_detection_feeds_do_not_count(fixture, reason):
    ok, why = _ksi_methods.verify_vdr_feeds(_ksi_methods.by_key(METHODS)["grype"], SIGNED, _vdr(fixture))
    assert not ok and reason in why


def test_the_vdr_signature_is_checked_against_the_allowed_identities(tmp_path):
    (tmp_path / "v.json").write_text("{}")
    (tmp_path / "v.bundle").write_text("{}")
    seen = []

    def verifier(path, bundle, ids):
        seen.append(list(ids))
        return False
    assert sdr.vdr_signature(tmp_path / "v.json", tmp_path / "v.bundle", ["id-a", "id-b"], verifier)[0] is False
    assert seen == [["id-a", "id-b"]]
    assert sdr.vdr_signature(tmp_path / "v.json", tmp_path / "v.bundle", ["id-a"], lambda *_a: True) == SIGNED
    assert sdr.vdr_signature(tmp_path / "v.json", None, ["id-a"])[0] is False


def test_the_plan_gate_run_counts_only_from_a_signed_signal_whose_validations_pass():
    sig = {"validations": [{"validation_id": "v", "result": "pass"}]}
    assert sdr.plan_gate_run(sig, SIGNED) == (True, None)
    assert sdr.plan_gate_run(sig, (False, "unsigned"))[1] == "unsigned"
    assert sdr.plan_gate_run({"validations": []}, SIGNED)[1] == "the KSI signal carries no plan validations"
    assert sdr.plan_gate_run({"validations": [{"result": "fail"}]}, SIGNED)[1] == "a plan validation failed"


# --- counting ---------------------------------------------------------------------------------

def test_each_counted_method_adds_one_for_exactly_its_ksis():
    """With no rule annotated, a KSI's count is the number of table methods
    naming it whose verifier passed; nothing else counts."""
    m = {k: v["automatedMethods"] for k, v in _ext(_build(_all_pass())).items() if v["status"] != "Not Applicable"}
    want = {k: 0 for k in m}
    for meth in METHODS["methods"]:
        for k in meth["ksis"]:
            if k in want:
                want[k] += 1
    assert m == want
    assert m["KSI-SCR-MON"] == 2 and m["KSI-SVC-EIS"] == 3 and m["KSI-CNA-IBP"] == 2


def test_known_bad_a_method_that_did_not_verify_counts_nothing_and_says_why():
    res = {**_all_pass(), "reconcile": (False, "invariant (a) was not checked against live state")}
    x = _ext(_build(res))["KSI-SVC-ACM"]
    assert x["automatedMethods"] == 1
    assert {m["key"]: m["reason"] for m in x["methods"]}["reconcile"] == \
        "invariant (a) was not checked against live state"
    assert _ext(_build({}))["KSI-SVC-ACM"]["automatedMethods"] == 0  # not evaluated: not counted


def test_a_mechanism_counts_once_per_ksi():
    """Recovery-rebuild publishes many exercises; it is one method."""
    assert sum(1 for m in METHODS["methods"] if "KSI-RPL-TRC" in m["ksis"]) == 1
    assert _ext(_build(_all_pass()))["KSI-RPL-TRC"]["automatedMethods"] == 1


def test_a_ksi_reaching_two_only_with_a_stand_in_is_simulated():
    t = _table(("a", ["KSI-INR-RIR"], "stand-in"), ("b", ["KSI-INR-RIR"], "real"),
               ("c", ["KSI-INR-AAR"], "real"), ("d", ["KSI-INR-AAR"], "real"))
    x = _ext(_build({"a": SIGNED, "b": SIGNED, "c": SIGNED, "d": SIGNED}, methods_doc=t))
    assert (x["KSI-INR-RIR"]["status"], x["KSI-INR-RIR"]["realInputMethods"]) == ("Simulated", 1)
    assert x["KSI-INR-AAR"]["status"] == "Implemented"
    assert x["KSI-INR-RPI"]["status"] == "Not Demonstrated"


def test_the_committed_training_is_one_stand_in_method():
    t = sdr.training_result(_training())
    assert t == (True, None)
    x = _ext(_build({**_all_pass(), "training": t, "phishing-drill": (False, "not published")}))["KSI-CED-RAT"]
    assert x["automatedMethods"] == 1 and x["realInputMethods"] == 0 and x["status"] == "Not Demonstrated"
    # With the phishing drill (also a stand-in) it reaches two, and is Simulated, never Implemented.
    x = _ext(_build({**_all_pass(), "training": t}))["KSI-CED-RAT"]
    assert x["automatedMethods"] == 2 and x["realInputMethods"] == 0 and x["status"] == "Simulated"
    assert sdr.training_result(sdr.NO_TRAINING) == (False, "training currency: not evaluated in this build")


# --- published records: signed by their publisher --------------------------------------------

def test_published_records_are_checked_against_their_own_publisher(tmp_path):
    seen = {}

    def verifier(path, bundle, ids):
        seen[Path(path).name] = ids
        return False
    recs = {}
    for key, name in _ksi_methods.published_keys(METHODS).items():
        p = tmp_path / key / name
        p.parent.mkdir()
        p.write_text("{}")
        (p.parent / (name[:-5] + ".bundle")).write_text("{}")
        recs[key] = (p, p.parent / (name[:-5] + ".bundle"))
    res = sdr.published_methods(METHODS, recs, NOW, sdr._freshness.load_freshness_config(), verifier)
    assert all(not ok and "does not verify against its publisher" in why for ok, why in res.values())
    assert seen["vdr-audit-log-review.json"] == [_signers.IDENTITIES["nightly"]]
    assert seen["security-settings.json"] == [_signers.IDENTITIES["deploy"]]
    assert sdr.published_methods(METHODS, {}, NOW, sdr._freshness.load_freshness_config()) == {
        k: sdr.NOT_EVALUATED for k in _ksi_methods.published_keys(METHODS)}


def test_the_method_record_argument_is_validated():
    assert sdr._method_record_args(["reconcile=d/reconcile-report.json"], METHODS) == {
        "reconcile": ("d/reconcile-report.json", "d/reconcile-report.bundle")}
    for bad in ("nonsense=x.json", "reconcile=x.txt", "plan-gate=x.json"):
        with pytest.raises(SystemExit):
            sdr._method_record_args([bad], METHODS)


INCIDENTS = json.loads((REPO / "data" / "incidents.json").read_text())


def _training(reg=None, prev=None, now=NOW):
    reg = reg or _decisions.load()
    return sdr.training_methods(prev or {}, reg, INCIDENTS, len(_frr.load()["records"]),
                                sdr._ksi_count(CATALOG), now)


def test_the_committed_data_gives_ksi_ced_rat_two_training_methods():
    t = _training()
    assert t["currency"] == (True, None) and t["completion"] == (True, None)
    assert t["summary"]["simulated"] is True and "(simulated)" in t["summary"]["trainee"]


# --- the FRC-CSX-VVK claim -------------------------------------------------------------------

def _records_with_vvk(status, **fields):
    recs = copy.deepcopy(_frr.load())
    for r in recs["records"]:
        if r["frr_id"] == sdr.VVK:
            r.clear()
            r.update({"frr_id": sdr.VVK, "status": status, "implementation": "x", **fields})
    return recs


IMPLEMENTED_VVK = {"evidence": [{"kind": "test", "ref": "tests/test_sdr_vvk.py::test_each_counted_method_adds_one_for_exactly_its_ksis"}]}


def test_the_committed_vvk_record_states_not_demonstrated_and_passes_the_claim_check():
    recs = _frr.load()
    rec = next(r for r in recs["records"] if r["frr_id"] == sdr.VVK)
    assert rec["status"] == "Not Demonstrated" and not rec.get("evidence") and not rec.get("approval")
    doc = _build(_all_pass())
    assert sdr.vvk_shortfalls(doc)
    assert sdr.vvk_claim(doc, recs) == []


def test_known_bad_vvk_implemented_while_a_ksi_is_short_fails():
    doc = _build(_all_pass())
    why = sdr.vvk_claim(doc, _records_with_vvk("Implemented", **IMPLEMENTED_VVK))
    assert len(why) == 1 and "is recorded Implemented but" in why[0] and "KSI-IAM-SUS" in why[0]


def test_vvk_implemented_is_supported_when_every_ksi_has_two():
    t = _table(("a", ALL_KSIS, "real"), ("b", ALL_KSIS, "real"))
    doc = _build({"a": SIGNED, "b": SIGNED}, methods_doc=t)
    assert sdr.vvk_shortfalls(doc) == []
    assert sdr.vvk_claim(doc, _records_with_vvk("Implemented", **IMPLEMENTED_VVK)) == []


def test_known_bad_vvk_simulated_or_not_applicable_fails():
    doc = _build(_all_pass())
    sim = _records_with_vvk("Simulated", evidence=[{"kind": "step", "ref": "deploy-with-opa.yml#Run OPA Compliance Check"}],
                            simulated={"counterparty": "assessor", "how": "x"})
    assert "its status follows the counts" in sdr.vvk_claim(doc, sim)[0]
    na = _records_with_vvk("Not Applicable", not_applicable="x")
    assert "its status follows the counts" in sdr.vvk_claim(doc, na)[0]


def test_an_accepted_ksi_decision_exempts_a_short_ksi():
    doc = _build(_all_pass(), accepted={k: "DEC-001" for k in ALL_KSIS})
    assert sdr.vvk_shortfalls(doc) == []
    assert sdr.vvk_acceptances(_decisions.load(), NOW) == {}


def test_a_not_applicable_ksi_is_not_short():
    na = {"KSI-SVC-RUD": {"ksi_id": "KSI-SVC-RUD", "status": "Not Applicable", "not_applicable": "x",
                          "proposal": {"by": "x", "on": "2026-11-06"}}}
    sig_short = [s.split(":")[0] for s in sdr.vvk_shortfalls(_build(_all_pass(), not_applicable=na))]
    assert "KSI-SVC-RUD" not in sig_short


def test_the_sdr_publishes_the_computed_count_on_the_vvk_entry():
    doc = _build(_all_pass())
    req = next(r for r in doc["fedRampRequirements"] if r["frrID"] == sdr.VVK)
    line, ext = sdr.vvk_computed(doc)
    assert line in req["frrValidation"]
    assert line.startswith("Computed in this build: ") and "short of 2: " in line
    assert req["providerExtensions"]["computed"] == ext
    assert req["frrImplementationStatus"] == "Not Implemented"


def test_the_package_maintainer_requires_two_methods_and_the_deploy_supplies_the_vdr_signature():
    wf = REPO / ".github" / "workflows"
    maint = (wf / "package-maintenance.yml").read_text()
    assert "--require-two-methods" in maint and "--vdr-bundle vdr-report.bundle" in maint
    deploy = (wf / "deploy-with-opa.yml").read_text()
    step = deploy[deploy.index("- name: Build Security Decision Record"):]
    step = step[:step.index("- name:", 10)]
    assert "--vdr-bundle vdr-report.bundle" in step
    assert deploy.index("- name: Sign VDR Report") < deploy.index("- name: Build Security Decision Record")
    deploy_jobs = deploy.split("\n  package-maintainer:\n", 1)[1]
    assert "needs: [deploy]" in deploy_jobs.split("\n\n", 1)[0] or "needs: [deploy]" in deploy_jobs[:400]


# --- the deploy holds it: staged runtime run, then the VVK claim checked ----------------------

THIS = "a" * 40


def test_the_runtime_signal_counts_only_for_this_commits_inventory():
    assert sdr.runtime_bound(FIX / "runtime-this-commit.json", THIS) is None
    why = sdr.runtime_bound(FIX / "runtime-previous-commit.json", THIS)
    assert "re-validated commit bbbbbbbbbbbb, not this build's aaaaaaaaaaaa" in why
    assert sdr.runtime_bound(FIX / "missing.json", THIS) == "the runtime signal is unreadable"


def _main_args(tmp_path, out, records=None):
    sig = tmp_path / "ksi-signal.json"
    sig.write_text(json.dumps(_signal()))
    args = ["--catalog", str(REPO / "infrastructure" / "schemas" / "ksi-catalog.json"),
            "--ksi-signal", str(sig),
            "--runtime-signal", str(FIX / "runtime-previous-commit.json"),
            "--vdr", str(FIX / "vdr-good.json"), "--profile", str(REPO / "data" / "system-profile.json"),
            "--output", str(out), "--md-output", "", "--runtime-commit", THIS, "--require-two-methods"]
    if records:
        p = tmp_path / "frr.json"
        p.write_text(json.dumps(records))
        args += ["--frr-records", str(p)]
    return args


def test_known_bad_the_deploys_sdr_step_fails_on_an_overclaiming_vvk_and_writes_nothing(tmp_path):
    """The deploy's invocation: --require-two-methods with --runtime-commit. A
    runtime signal from the previously published inventory counts for
    nothing, KSIs are short, and a VVK record claiming Implemented stops the
    build before the SDR exists."""
    out = tmp_path / "sdr.json"
    with pytest.raises(SystemExit, match="claims more than the per-KSI method counts support; nothing written"):
        sdr.main(_main_args(tmp_path, out, _records_with_vvk("Implemented", **IMPLEMENTED_VVK)))
    assert not out.exists()


def test_the_deploys_sdr_step_publishes_an_honest_vvk_with_short_ksis(tmp_path):
    """The same build with the committed record (Not Demonstrated): the
    shortfall is stated, not a reason to stop."""
    out = tmp_path / "sdr.json"
    assert sdr.main(_main_args(tmp_path, out)) == 0
    doc = json.loads(out.read_text())
    req = next(r for r in doc["fedRampRequirements"] if r["frrID"] == sdr.VVK)
    assert req["providerExtensions"]["computed"]["short"]


def _step(text, name):
    at = text.index(f"- name: {name}")
    return text[at:text.index("\n    - name:", at + 10)]


def test_the_deploy_invokes_the_emitter_after_apply_and_requires_two_methods_before_publishing():
    deploy = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    name = "Re-validate the deployed system against this inventory (runtime emitter, FRC-CSX-VVK)"
    order = [deploy.index(f"- name: {n}") for n in (
        "Terraform Apply", "Sign KSI signal", name, "Build VDR Report (FedRAMP 20x Class C)",
        "Build Security Decision Record", "Publish all signed artifacts to /.well-known/")]
    assert order == sorted(order)
    step = _step(deploy, name)
    assert "check-published-redaction.py ksi-signal.json" in step  # before the staged copy
    assert '"{\\"stage\\":\\"${COMMIT}\\"}"' in step and "trap cleanup EXIT" in step
    assert ".FunctionError" in step and "exit 1" in step
    assert "Fetch the signed runtime signal" not in deploy
    sdr_step = _step(deploy, "Build Security Decision Record")
    assert '--runtime-commit "$COMMIT" --require-two-methods' in sdr_step
    assert "COMMIT: ${{ github.sha }}" in sdr_step


def test_the_emitter_accepts_only_a_commit_sha_as_its_stage():
    import shutil
    import subprocess
    if shutil.which("node") is None:
        pytest.skip("node not available")
    script = """
const { stageKeys } = require('./infrastructure/lambda/stage.js');
const out = { none: stageKeys({}), ok: stageKeys({ stage: 'a'.repeat(40) }), refused: [] };
for (const bad of ['../../.well-known/x', 'A'.repeat(40), 'a'.repeat(39), 7, null]) {
  try { stageKeys({ stage: bad }); } catch (e) { out.refused.push(String(bad)); }
}
console.log(JSON.stringify(out));
"""
    r = json.loads(subprocess.run(["node", "-e", script], cwd=REPO, capture_output=True, text=True,
                                  check=True).stdout)
    assert r["none"] is None
    assert r["ok"] == {"deploySignal": f"deploy-staging/{'a' * 40}/ksi-signal.json",
                       "runtimeSignal": f"deploy-staging/{'a' * 40}/ksi-signal-runtime.json"}
    assert len(r["refused"]) == 5


def test_the_emitter_may_write_only_the_staged_runtime_signal():
    tf = (REPO / "infrastructure" / "main.tf").read_text()
    assert '"${data.aws_s3_bucket.website.arn}/deploy-staging/*/ksi-signal-runtime.json"' in tf
    js = (REPO / "infrastructure" / "lambda" / "index.js").read_text()
    assert "staged ? staged.runtimeSignal : '.well-known/ksi-signal-runtime.json'" in js
    assert "if (!staged) await publishPublicKey" in js


