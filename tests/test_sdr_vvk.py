"""FRC-CSX-VVK: the automated methods the SDR counts per KSI. Beyond the plan
gate and the runtime re-validation: dependency vulnerability scanning for a KSI
with npm or PyPI package components (only when the bound VDR verifies and is
fresh), and for KSI-CED-RAT the two training checks (scripts/_training.py).
A KSI short of two methods without an in-force accepted decision fails the
build when --require-two-methods is given (the package maintainer)."""
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
import _rules  # noqa: E402

spec = importlib.util.spec_from_file_location("build_sdr_vvk", REPO / "scripts" / "build-sdr.py")
sdr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdr)

FIX = REPO / "tests" / "fixtures" / "vvk"
CATALOG = json.loads((REPO / "infrastructure" / "schemas" / "ksi-catalog.json").read_text())
NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
SIGNED = (True, None)
PKG = "pkg:npm/left-pad@1.3.0"


def _vdr(name="vdr-good.json"):
    return json.loads((FIX / name).read_text())


def _signal():
    """Every KSI validated against the plan over a function; the SCR KSIs over
    an npm package only (no runtime reaches a package); KSI-CED-RAT over
    nothing, evidenced by documentation."""
    comps = [{"component_id": "aws::function::app", "type": "function"},
             {"component_id": PKG, "type": "npm_package"}]
    ksis = []
    for f in CATALOG["KSI"].values():
        for i in f["indicators"]:
            refs = {"KSI-SCR-MIT": [PKG], "KSI-SCR-MON": [PKG], "KSI-CED-RAT": []}.get(i["id"],
                                                                                    ["aws::function::app"])
            doc = i["id"] == "KSI-CED-RAT"
            ksis.append({"id": i["id"], "status": "pass", "method": "documentation" if doc else "policy-validation",
                         "evidence": {"validation_ids": [] if doc else ["v-1"], "failed_validation_ids": [],
                                      "component_refs": refs}})
    return {"signal_id": "sig-1", "components": comps, "ksis": ksis}


RUNTIME = [{"validation_id": "r-1", "component_refs": ["aws::function::app"], "result": "pass"}]


def _build(dep_scan, training, accepted):
    sig = _signal()
    return sdr.build(CATALOG, sig, _frr.load(), _rules.applicable_provider_rules(), _controls.project(sig, CATALOG),
                     sdr.moderate_ids(), {}, RUNTIME, None, [], {"fedramp_class": "C", "impact_level": "Moderate"},
                     {}, {}, NOW, {"ac": "https://example.invalid/ac.md"},
                     dep_scan=dep_scan, training=training, accepted=accepted)


def _methods(doc):
    return {k["ksiId"]: k["providerExtensions"]["automatedMethods"] for k in doc["keySecurityIndicators"]}


# --- dependency scanning ------------------------------------------------------------------

def test_a_bound_signed_fresh_vdr_with_passing_grype_scans_counts():
    assert sdr.dependency_scan(_vdr(), _signal(), NOW, SIGNED, 24) == (True, None)


@pytest.mark.parametrize("fixture,signature,reason", [
    ("vdr-unbound.json", SIGNED, "not bound to this inventory"),
    ("vdr-stale.json", SIGNED, "not within its 24-hour window"),
    ("vdr-grype-failed.json", SIGNED, "a Grype dependency scan failed the detection gate"),
    ("vdr-no-grype.json", SIGNED, "lists no Grype dependency scan"),
    ("vdr-good.json", (False, "the VDR signature does not verify against the allowed identities"), "does not verify"),
])
def test_known_bad_vdrs_do_not_count_each_for_its_reason(fixture, signature, reason):
    ok, why = sdr.dependency_scan(_vdr(fixture), _signal(), NOW, signature, 24)
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


def test_dependency_scanning_counts_only_for_ksis_with_package_components():
    with_scan = _methods(_build(SIGNED, sdr.NO_TRAINING, {}))
    without = _methods(_build((False, "unsigned"), sdr.NO_TRAINING, {}))
    assert with_scan["KSI-SCR-MIT"] == with_scan["KSI-SCR-MON"] == 2
    assert without["KSI-SCR-MIT"] == without["KSI-SCR-MON"] == 1
    assert with_scan["KSI-SVC-VRI"] == without["KSI-SVC-VRI"] == 2  # no package component: plan + runtime


# --- training (KSI-CED-RAT): two automated methods, a simulated trainee --------------------

INCIDENTS = json.loads((REPO / "data" / "incidents.json").read_text())


def _training(reg=None, prev=None, now=NOW):
    reg = reg or _decisions.load()
    return sdr.training_methods(prev or {}, reg, INCIDENTS, len(_frr.load()["records"]),
                                sdr._ksi_count(CATALOG), now)


def test_the_committed_data_gives_ksi_ced_rat_two_training_methods():
    t = _training()
    assert t["currency"] == (True, None) and t["completion"] == (True, None)
    assert t["summary"]["simulated"] is True and "(simulated)" in t["summary"]["trainee"]


# --- shortfalls -----------------------------------------------------------------------------

def test_with_the_committed_register_every_ksi_has_two_methods_and_none_is_accepted_short():
    reg = _decisions.load()
    accepted = sdr.vvk_acceptances(reg, NOW)
    assert accepted == {}
    doc = _build(SIGNED, _training(reg), accepted)
    m = _methods(doc)
    assert m["KSI-CED-RAT"] == 2 and all(v >= 2 for v in m.values())
    assert sdr.vvk_shortfalls(doc) == []
    rat = next(k for k in doc["keySecurityIndicators"] if k["ksiId"] == "KSI-CED-RAT")
    assert "fewerMethodsAccepted" not in rat["providerExtensions"]
    assert any(line.startswith("Training currency check: ") for line in rat["ksiValidation"])
    assert any(line.startswith("Training completion and effectiveness check: ") for line in rat["ksiValidation"])
    assert doc["providerExtensions"]["training"]["methods"]["currency"]["ok"] is True


def test_known_bad_without_the_training_methods_ksi_ced_rat_is_a_shortfall():
    doc = _build(SIGNED, sdr.NO_TRAINING, {})
    short = sdr.vvk_shortfalls(doc)
    assert len(short) == 1 and short[0].startswith("KSI-CED-RAT: 0 automated method(s)")


def test_an_unsigned_vdr_leaves_the_supply_chain_ksis_short():
    reg = _decisions.load()
    doc = _build((False, "unsigned"), _training(reg), sdr.vvk_acceptances(reg, NOW))
    assert sorted(s.split(":")[0] for s in sdr.vvk_shortfalls(doc)) == ["KSI-SCR-MIT", "KSI-SCR-MON"]


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


# --- the deploy holds it: staged runtime run, then two methods required ---------------------

THIS = "a" * 40


def test_the_runtime_signal_counts_only_for_this_commits_inventory():
    assert sdr.runtime_bound(FIX / "runtime-this-commit.json", THIS) is None
    why = sdr.runtime_bound(FIX / "runtime-previous-commit.json", THIS)
    assert "re-validated commit bbbbbbbbbbbb, not this build's aaaaaaaaaaaa" in why
    assert sdr.runtime_bound(FIX / "missing.json", THIS) == "the runtime signal is unreadable"


def test_known_bad_the_deploys_sdr_step_fails_on_a_shortfall_and_writes_nothing(tmp_path):
    """The deploy's invocation: --require-two-methods with --runtime-commit. A
    runtime signal from the previously published inventory counts for
    nothing, so KSIs are short and the build stops before the SDR exists."""
    out = tmp_path / "sdr.json"
    sig = tmp_path / "ksi-signal.json"
    sig.write_text(json.dumps(_signal()))
    args = ["--catalog", str(REPO / "infrastructure" / "schemas" / "ksi-catalog.json"),
            "--ksi-signal", str(sig),
            "--runtime-signal", str(FIX / "runtime-previous-commit.json"),
            "--vdr", str(FIX / "vdr-good.json"), "--profile", str(REPO / "data" / "system-profile.json"),
            "--output", str(out), "--md-output", "", "--runtime-commit", THIS, "--require-two-methods"]
    with pytest.raises(SystemExit, match="short of 2 automated methods; nothing written"):
        sdr.main(args)
    assert not out.exists()


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


# --- the scheduled reviews (scripts/_scheduled_review.py): one more method each ----------

SCHEDULED_KSIS = {"KSI-MLA-RVL", "KSI-CMT-RVP", "KSI-PIY-RIS", "KSI-PIY-RES", "KSI-SVC-EIS", "KSI-INR-RPI",
                  "KSI-RPL-TRC"}


def _build_with(scheduled):
    sig = _signal()
    return sdr.build(CATALOG, sig, _frr.load(), _rules.applicable_provider_rules(), _controls.project(sig, CATALOG),
                     sdr.moderate_ids(), {}, RUNTIME, None, [], {"fedramp_class": "C", "impact_level": "Moderate"},
                     {}, {}, NOW, {"ac": "https://example.invalid/ac.md"},
                     dep_scan=SIGNED, training=sdr.NO_TRAINING, accepted={}, scheduled=scheduled)


def test_the_method_table_names_each_scheduled_ksi_once_and_keeps_training():
    assert sdr.KSI_METHODS["KSI-CED-RAT"] == ["training-currency", "training-completion"]
    assert {k for k, ms in sdr.KSI_METHODS.items() if set(ms) & set(sdr._sched.KSI_METHODS)} == SCHEDULED_KSIS
    assert all(len(sdr.KSI_METHODS[k]) == 1 for k in SCHEDULED_KSIS)


def test_each_scheduled_ksi_gains_one_method_when_its_record_passes():
    before = _methods(_build_with(None))
    after = _methods(_build_with({k: (True, None) for k in sdr._sched.KSI_METHODS}))
    assert {k for k in after if after[k] != before[k]} == SCHEDULED_KSIS
    assert all(after[k] == before[k] + 1 for k in SCHEDULED_KSIS)


def test_known_bad_a_failing_record_is_not_counted_and_says_why():
    doc = _build_with({"audit-log-review": (False, "the planted simulated intruder was not caught")})
    k = next(k for k in doc["keySecurityIndicators"] if k["ksiId"] == "KSI-MLA-RVL")
    assert k["providerExtensions"]["automatedMethods"] == 2
    assert any("not counted for this build: the planted simulated intruder was not caught" in v
               for v in k["ksiValidation"])


def _records(tmp_path, doc):
    out = {}
    for key, name in sdr._sched.METHOD_FILES.items():
        p = tmp_path / name
        p.write_text(json.dumps(doc(key)))
        (tmp_path / (name[:-5] + ".bundle")).write_text("{}")
        out[key] = (p, tmp_path / (name[:-5] + ".bundle"))
    return out


def _passing(key):
    if key == "audit-log-review":
        return {"schema": "audit-log-review/1", "generated_at": NOW.isoformat(), "result": "pass",
                "exercise": {"caught": True}}
    return {"schema": "scheduled-reviews/1", "review": key,
            "reviews": [{"dueDate": "2026-11-0" + ("1" if key == "recovery-exercise" else "5"), "sha256": "0" * 64,
                         "result": "pass"}]}


def test_scheduled_records_count_only_when_signed_by_their_publisher(tmp_path):
    seen = {}

    def verifier(path, bundle, ids):
        seen[Path(path).name] = ids
        return True
    res = sdr.scheduled_methods(_records(tmp_path, _passing), NOW, verifier)
    assert res == {k: (True, None) for k in sdr._sched.KSI_METHODS}
    nightly = "https://github.com/sam-aydlette/samaydlette.com/.github/workflows/evidence-nightly.yml@refs/heads/main"
    maint = ("https://github.com/sam-aydlette/samaydlette.com/.github/workflows/package-maintenance.yml"
             "@refs/heads/main")
    assert seen == {"vdr-audit-log-review.json": [nightly], "vdr-recovery-exercises.json": [nightly],
                    "security-reviews.json": [maint]}


def test_known_bad_an_unsigned_or_missing_record_is_not_counted(tmp_path):
    res = sdr.scheduled_methods(_records(tmp_path, _passing), NOW, lambda *_a: False)
    assert all(not ok and "does not verify" in why for ok, why in res.values())
    assert sdr.scheduled_methods({}, NOW) == {k: sdr.NOT_EVALUATED for k in sdr._sched.KSI_METHODS}
    gone = {"audit-log-review": (tmp_path / "nope.json", tmp_path / "nope.bundle")}
    assert "not published" in sdr.scheduled_methods(gone, NOW, lambda *_a: True)["audit-log-review"][1]


def test_the_scheduled_record_argument_is_validated():
    assert sdr._scheduled_args(["security-review=d/security-reviews.json"]) == {
        "security-review": ("d/security-reviews.json", "d/security-reviews.bundle")}
    with pytest.raises(SystemExit):
        sdr._scheduled_args(["nonsense=x.json"])
