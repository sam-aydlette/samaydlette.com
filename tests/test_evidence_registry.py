"""The evidence registry: infrastructure/schemas/freshness-config.json.

One entry per published artifact names its window, signature, publishers and
generator. These tests hold the code to it: each generator exists and runs in
the workflows that publish its artifact, the provenance attestations name the
same generators, and every artifact the rule register cites as evidence is
registered.
"""

import copy
import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _freshness  # noqa: E402

FRR = REPO / "data" / "frr-records.json"
WORKFLOWS = {"deploy": REPO / ".github" / "workflows" / "deploy-with-opa.yml",
             "nightly": REPO / ".github" / "workflows" / "evidence-nightly.yml"}


def _reach(workflow):
    """The workflow's text plus every repository shell script it runs (run-gates.sh
    calls build-vdr-report.py, for example)."""
    text = workflow.read_text()
    for sh in sorted(set(re.findall(r"scripts/([A-Za-z0-9_-]+\.sh)", text))):
        if (REPO / "scripts" / sh).is_file():
            text += (REPO / "scripts" / sh).read_text()
    return text


def problems(cfg, frr=None):
    """Every way the registry disagrees with the code and the rule register."""
    out = []
    reach = {by: _reach(wf) for by, wf in WORKFLOWS.items()}
    for a in cfg["artifacts"]:
        path, gen = a["path"], a["generator"]
        if not (REPO / gen).is_file():
            out.append(f"{path}: generator {gen} does not exist")
            continue
        if a["cadence"] == "operator":
            # The operator runs it by hand; the deploy only republishes its output.
            if not gen.startswith("tools/"):
                out.append(f"{path}: an operator-run artifact's generator is an operator tool under tools/")
            continue
        for by in a["published_by"]:
            if by == "runtime":
                if not gen.startswith("infrastructure/lambda/"):
                    out.append(f"{path}: a runtime artifact is written by the runtime Lambda")
            elif gen.startswith(".github/workflows/"):
                if REPO / gen != WORKFLOWS[by]:
                    out.append(f"{path}: written by a step of {gen}, but published by the {by} workflow")
            elif Path(gen).name not in reach[by]:
                out.append(f"{path}: the {by} workflow never runs its generator {gen}")
    # The deploy's provenance attestations name each artifact's generator too.
    reg = {a["path"]: a for a in cfg["artifacts"]}
    for art, gen in re.findall(r"^\s*attest ([A-Za-z0-9._-]+)\s+(scripts/[A-Za-z0-9_-]+\.py)\s*$",
                               WORKFLOWS["deploy"].read_text(), re.M):
        a = reg.get(f".well-known/{art}")
        if a is None or a["generator"] != gen:
            out.append(f"{art}: the deploy attests it as built by {gen}, the registry says "
                       f"{a['generator'] if a else 'nothing (not registered)'}")
        if f".well-known/{art}.intoto.jsonl" not in reg:
            out.append(f"{art}.intoto.jsonl: attested by the deploy but not registered")
    # Every artifact the rule register cites as evidence must be one we publish.
    for r in (frr or json.loads(FRR.read_text()))["records"]:
        for e in r.get("evidence", []):
            if e.get("kind") == "artifact" and e["ref"].startswith(".well-known/") and e["ref"] not in reg:
                out.append(f"{r['frr_id']}: cites {e['ref']} as evidence, which is not a registered artifact")
    return out


@pytest.fixture(scope="module")
def cfg():
    return _freshness.load_freshness_config()


def test_the_registry_agrees_with_the_code_and_the_rule_register(cfg):
    assert problems(cfg) == []


def _with(cfg, path, **change):
    bad = copy.deepcopy(cfg)
    next(a for a in bad["artifacts"] if a["path"] == path).update(change)
    return bad


def test_a_missing_generator_is_caught(cfg):
    bad = _with(cfg, ".well-known/trust-center.json", generator="scripts/build-nothing.py")
    assert problems(bad) == [".well-known/trust-center.json: generator scripts/build-nothing.py does not exist"]


def test_a_generator_the_publishing_workflow_never_runs_is_caught(cfg):
    # build-ocr.py runs in the deploy only; a nightly-published artifact can't claim it.
    bad = _with(cfg, ".well-known/vdr-trend.json", generator="scripts/build-ocr.py")
    assert ".well-known/vdr-trend.json: the nightly workflow never runs its generator scripts/build-ocr.py" in problems(bad)


def test_a_workflow_generator_must_be_the_publishing_workflow(cfg):
    bad = _with(cfg, ".well-known/vdr-status.json", generator=".github/workflows/deploy-with-opa.yml")
    assert any("vdr-status.json: written by a step of" in p for p in problems(bad))


def test_an_attestation_that_names_another_generator_is_caught(cfg):
    bad = _with(cfg, ".well-known/iiw.csv", generator="scripts/build-ksi-signal.py")
    assert any(p.startswith("iiw.csv: the deploy attests it as built by scripts/build-iiw.py") for p in problems(bad))


def test_unregistered_rule_evidence_is_caught(cfg):
    frr = {"records": [{"frr_id": "X-Y-Z", "evidence": [{"kind": "artifact", "ref": ".well-known/not-published.json"}]}]}
    assert problems(cfg, frr) == ["X-Y-Z: cites .well-known/not-published.json as evidence, which is not a registered artifact"]


@pytest.mark.parametrize("gen", ["", "../outside.py", "scripts/../x.py", "website/x.js", "/abs/scripts/x.py", None])
def test_a_malformed_generator_is_refused(cfg, gen):
    raw = json.loads(_freshness.DEFAULT_PATH.read_text())
    raw["artifacts"][0]["generator"] = gen
    with pytest.raises(SystemExit, match="generator"):
        _freshness.validate_freshness_config(raw)


def test_an_entry_without_a_generator_is_refused():
    raw = json.loads(_freshness.DEFAULT_PATH.read_text())
    del raw["artifacts"][0]["generator"]
    with pytest.raises(SystemExit, match="missing keys \\['generator'\\]"):
        _freshness.validate_freshness_config(raw)
