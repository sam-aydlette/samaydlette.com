"""Every allowed-signer list agrees with the workflows that write each file.

A published artifact is signed keylessly by the workflow that put it, so the
identities a verifier must accept for a file are exactly the workflows whose
publish steps write it. The table below maps each publishing workflow to its
publish steps; the put-list is read from those steps and the identity from the
workflow's file name. Every list a verifier relies on is then held to it: the
shared table (scripts/_signers.py), the assessor guide the simulated assessor
follows, the trust manifest, scripts/verify-published.sh and
docs/verification.md. A list that leaves out a writer fails here, before a
deploy whose assessor would refuse the file.
"""
import importlib.util
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _freshness  # noqa: E402
import _signers  # noqa: E402

WORKFLOWS = REPO / ".github" / "workflows"
FIXTURES = REPO / "tests" / "fixtures" / "signers"
WF_URL = "https://github.com/sam-aydlette/samaydlette.com/.github/workflows"

# workflow -> the steps that write under /.well-known/. The identity is the
# workflow's own: a reusable workflow called by the deploy still signs as itself.
PUBLISHERS = {
    "deploy-with-opa.yml": ["Publish all signed artifacts to /.well-known/",
                            "Attest artifact provenance (SLSA/in-toto)"],
    "evidence-nightly.yml": ["Publish VDR + trend to /.well-known/"],
    "package-maintenance.yml": ["Publish the certification package to /.well-known/"],
    "incident-reports.yml": ["Publish incident reports to /.well-known/"],
}
# Put by the deploy, signed by another workflow: the simulated assessor's set.
RELAYED = {"simulated-assessment.json": "simulated-assessor.yml",
           "simulated-assessment.bundle": "simulated-assessor.yml"}


def identity(workflow):
    return f"{WF_URL}/{workflow}@refs/heads/main"


def _step(text, name):
    start = text.index(f"- name: {name}")
    end = text.find("\n    - name:", start + 1)
    return text[start:end if end > 0 else None]


def puts(workflow):
    """Object names the workflow's publish steps write under .well-known/, with
    for-loops over literal names expanded (globs and read-loops are dynamic)."""
    text = (WORKFLOWS / workflow).read_text()
    names = set()
    for step in (_step(text, s) for s in PUBLISHERS[workflow]):
        for loop in re.finditer(r"for (\w+) in ([^;\n]+); do(.*?)\n\s*done", step, re.S):
            var, items, body = loop.groups()
            literal = [i for i in items.split() if "*" not in i and "$" not in i]
            for tmpl in re.findall(r'(?:\.well-known/|\bput ")\$\{?' + var + r'\}?(\.[\w.]+)', body):
                names |= {item + tmpl for item in literal}
        names |= set(re.findall(r"\.well-known/([A-Za-z0-9][\w.-]*)(?![\w.*$-])", step))
        names |= set(re.findall(r"^\s*put ([\w.-]+)\s", step, re.M))
        names |= {f"{a}.intoto.jsonl" for a in re.findall(r"^\s*attest (\S+)\s+scripts/", step, re.M)}
    return names


PUT = {wf: puts(wf) for wf in PUBLISHERS}


def writers(name):
    """The identities of the workflows that write (and so sign) a file."""
    out = {identity(RELAYED.get(name, wf)) for wf, names in PUT.items() if name in names}
    return out


def signed_artifacts():
    """Every artifact the freshness config governs that a workflow signs keylessly:
    a Sigstore bundle beside it, or an in-toto attestation. (The runtime signal
    is signed in-band by the runtime Lambda's KMS key, not by a workflow.)"""
    out = []
    for a in _freshness.load_freshness_config(REPO / "infrastructure" / "schemas" / "freshness-config.json")["artifacts"]:
        if a.get("signature") or a["path"].endswith(".intoto.jsonl"):
            out.append(a["path"].rsplit("/", 1)[1])
    return out


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def guide_mismatches(guide):
    """[(artifact, allowed identities, writers)] for every artifact check in an
    assessor guide whose allowed signers are not exactly the file's writers."""
    out = []
    for r in guide["rules"]:
        for ev in r["evidence"]:
            chk = ev["check"].get("artifact")
            if not chk or not chk.get("bundle_url"):
                continue
            name = chk["url"].rsplit("/", 1)[1]
            allowed = {guide["identities"][i] for i in chk["identities"]}
            if allowed != writers(name):
                out.append((name, sorted(allowed), sorted(writers(name))))
    return out


# --- the derivation itself ---------------------------------------------------------------

def test_every_publish_step_exists_and_writes_something():
    for wf in PUBLISHERS:
        assert PUT[wf], f"{wf}: no objects found in its publish steps"
    assert {"security-decision-record.json", "ocr-issues.json"} <= PUT["package-maintenance.yml"]
    assert {"incident-reports.json", "incident-deliveries.json"} <= PUT["incident-reports.yml"]
    assert {"incident-reports.json", "ksi-signal.json.intoto.jsonl"} <= PUT["deploy-with-opa.yml"]


def test_no_other_workflow_writes_to_the_bucket():
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        if wf.name in PUBLISHERS:
            continue
        text = wf.read_text()
        assert not re.search(r"put-object|aws s3 cp|aws s3 sync", text), (
            f"{wf.name} writes to S3 but is not in this test's publisher table")


def test_every_signed_artifact_has_a_writer():
    for name in signed_artifacts():
        if name == "boundary-corroboration.json":  # the operator commits it; the deploy publishes and signs it
            assert writers(name) == {identity("deploy-with-opa.yml")}
        assert writers(name), f"{name} is signed but no publish step writes it"


# --- every allowed-signer list ------------------------------------------------------------

def test_the_shared_table_names_exactly_the_writers():
    for name in signed_artifacts():
        allowed = {_signers.IDENTITIES[k] for k in _signers.signers(name)}
        assert allowed == writers(name), name
    for k, wf in _signers.WORKFLOWS.items():
        assert _signers.IDENTITIES[k] == identity(wf)


def test_the_assessor_guide_accepts_exactly_the_writers():
    ag = _load("assessor_guide_signers", "build-assessor-guide.py")
    fresh = {x["path"]: x for x in _freshness.load_freshness_config(
        REPO / "infrastructure" / "schemas" / "freshness-config.json")["artifacts"]}
    for path, entry in fresh.items():
        if not entry.get("signature"):
            continue
        chk = ag._artifact_check(path, fresh)
        name = path.rsplit("/", 1)[1]
        assert {ag.IDENTITIES[i] for i in chk["identities"]} == writers(name), name
        cmd, _ = ag.reproduce({"kind": "artifact", "ref": path}, fresh)
        for ident in writers(name):
            assert ident in cmd, f"{name}: the command a person runs omits {ident}"


def test_the_built_guide_has_no_mismatch():
    import _frr
    import _rules
    ag = _load("assessor_guide_signers2", "build-assessor-guide.py")
    fresh = {x["path"]: x for x in _freshness.load_freshness_config(
        REPO / "infrastructure" / "schemas" / "freshness-config.json")["artifacts"]}
    catalog = json.loads((REPO / "infrastructure" / "schemas" / "ksi-catalog.json").read_text())
    g = ag.build(_frr.load(_frr.DEFAULT_PATH), _rules.applicable_provider_rules(), catalog, fresh,
                 datetime(2026, 11, 6, tzinfo=timezone.utc), "abc")
    assert guide_mismatches(g) == []


def test_known_bad_a_guide_missing_the_maintainer_fails():
    bad = json.loads((FIXTURES / "guide-missing-maintainer.json").read_text())
    found = guide_mismatches(bad)
    assert [m[0] for m in found] == ["security-decision-record.json"]
    assert identity("package-maintenance.yml") in found[0][2]
    assert identity("package-maintenance.yml") not in found[0][1]


def test_the_trust_manifest_names_exactly_the_writers(tmp_path):
    tm = _load("trust_manifest_signers", "build-trust-manifest.py")
    fresh = _freshness.load_freshness_config(REPO / "infrastructure" / "schemas" / "freshness-config.json")
    m = tm.build(fresh, tmp_path, {"entries": []}, datetime(2026, 11, 6, tzinfo=timezone.utc))
    for a in m["artifacts"]:
        if "signature" not in a:
            continue
        named = {m["signers"][k] for k in a["signed_by"].split(" or ")}
        assert named == writers(a["name"]), a["name"]


def _script_signers(names):
    """Run verify-published.sh's signers_for over each name, without running the script."""
    text = (REPO / "scripts" / "verify-published.sh").read_text()
    idents = "\n".join(re.findall(r"^[A-Z_]*IDENTITY='[^']+'$", text, re.M))
    func = text[text.index("signers_for() {"):text.index("# signers-end")]
    prog = idents + "\n" + func + "\n" + "\n".join(f"echo \"{n}=$(signers_for {n})\"" for n in names)
    out = subprocess.run(["bash", "-c", prog], capture_output=True, text=True, check=True).stdout
    return {line.split("=", 1)[0]: set(line.split("=", 1)[1].split()) for line in out.splitlines()}


def test_verify_published_accepts_exactly_the_writers():
    names = signed_artifacts()
    got = _script_signers(names)
    for n in names:
        assert got[n] == writers(n), n


def test_verify_published_checks_the_incident_logs_with_the_publisher_identity():
    text = (REPO / "scripts" / "verify-published.sh").read_text()
    assert "for art in incident-reports incident-deliveries; do" in text
    assert identity("incident-reports.yml") in text


@pytest.mark.parametrize("wf", sorted(set(PUBLISHERS) | set(RELAYED.values())))
def test_the_verification_page_names_every_signing_identity(wf):
    assert identity(wf) in (REPO / "docs" / "verification.md").read_text()


# --- readable views stay in step with the JSON each publisher rewrites ---------------------

GOVERNED_JSON = {a["path"].rsplit("/", 1)[1] for a in _freshness.load_freshness_config(
    REPO / "infrastructure" / "schemas" / "freshness-config.json")["artifacts"] if a["path"].endswith(".json")}


def _view_step_files(workflow):
    """The JSON files the workflow's view step (build-human-views.py) is given,
    and whether that step runs before its publish step."""
    text = (WORKFLOWS / workflow).read_text()
    step = _step(text, "Rebuild the human-readable views (format parity)")
    given = set(re.findall(r"([\w.-]+\.json)", step.split("build-human-views.py", 1)[1]))
    before = text.index(step) < text.index(f"- name: {PUBLISHERS[workflow][0]}")
    return given, before


@pytest.mark.parametrize("wf", ["evidence-nightly.yml", "package-maintenance.yml", "incident-reports.yml"])
def test_each_unattended_publisher_rebuilds_and_puts_the_view_of_every_json_it_puts(wf):
    rewritten = {n for n in PUT[wf] if n in GOVERNED_JSON}
    assert rewritten, wf
    given, before = _view_step_files(wf)
    assert before, f"{wf}: the views are built after the publish step"
    for n in sorted(rewritten):
        assert n in given, f"{wf} republishes {n} without rebuilding its view"
        assert n[:-len(".json")] + ".view.md" in PUT[wf], f"{wf} republishes {n} without putting its view"


def test_the_deploy_builds_a_view_of_every_governed_json_and_publishes_them():
    text = (WORKFLOWS / "deploy-with-opa.yml").read_text()
    assert "build-human-views.py --freshness schemas/freshness-config.json --dir . --list published-docs.txt" in text
    assert "done < published-docs.txt" in _step(text, PUBLISHERS["deploy-with-opa.yml"][0])
