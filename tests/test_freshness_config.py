"""Governed freshness windows (REQ-PUB-2, REQ-GOV-1).

One schema-validated, version-controlled file (infrastructure/schemas/
freshness-config.json) sets the maximum age of every output published under
/.well-known/. The trust center, the published-evidence check and the watchdog
all read it, and each fails closed when it is missing or invalid (T18). These
tests pin the loader, the known-bad fixture, and that every artifact the deploy
and the nightly publish is listed, so a new output cannot ship unwatched.
"""

import copy
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CONFIG = REPO / "infrastructure" / "schemas" / "freshness-config.json"
SCHEMA = REPO / "infrastructure" / "schemas" / "freshness-config.schema.json"
BAD = REPO / "tests" / "fixtures" / "freshness" / "freshness-config-invalid.json"

sys.path.insert(0, str(REPO / "scripts"))
from _freshness import load_freshness_config  # noqa: E402


def good():
    return json.loads(CONFIG.read_text())


def write(tmp_path, cfg):
    p = tmp_path / "freshness-config.json"
    p.write_text(json.dumps(cfg))
    return p


def test_committed_config_loads_and_matches_its_schema():
    jsonschema = pytest.importorskip("jsonschema")
    cfg = load_freshness_config(CONFIG)
    jsonschema.validate(good(), json.loads(SCHEMA.read_text()))
    assert cfg["version"] and len(cfg["sha256"]) == 64
    windows = cfg["windows"]
    assert windows[".well-known/vdr-report.json"] == 24
    assert windows[".well-known/ksi-signal-runtime.json"] == 26
    assert windows[".well-known/vdr-status.json"] == 26


def test_the_known_bad_fixture_is_rejected_by_the_loader_and_the_schema():
    jsonschema = pytest.importorskip("jsonschema")
    with pytest.raises(SystemExit):
        load_freshness_config(BAD)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(json.loads(BAD.read_text()), json.loads(SCHEMA.read_text()))


def test_a_missing_or_unparseable_config_fails_closed(tmp_path):
    with pytest.raises(SystemExit, match="not found"):
        load_freshness_config(tmp_path / "absent.json")
    p = tmp_path / "freshness-config.json"
    p.write_text("{not json")
    with pytest.raises(SystemExit, match="not valid JSON"):
        load_freshness_config(p)


def _break(cfg, how):
    arts = cfg["artifacts"]
    if how == "no_version":
        del cfg["version"]
    elif how == "no_decided_by":
        del cfg["decided_by"]
    elif how == "bad_review_by":
        cfg["review_by"] = "next year"
    elif how == "unknown_key":
        cfg["max_age_override"] = 1
    elif how == "no_artifacts":
        cfg["artifacts"] = []
    elif how == "string_window":
        arts[0]["max_age_hours"] = "24"
    elif how == "bool_window":
        arts[0]["max_age_hours"] = True
    elif how == "zero_window":
        arts[0]["max_age_hours"] = 0
    elif how == "path_escape":
        arts[0]["path"] = ".well-known/../index.html"
    elif how == "outside_well_known":
        arts[0]["path"] = "index.html"
    elif how == "duplicate":
        arts.append(copy.deepcopy(arts[0]))
    elif how == "bad_timestamp":
        arts[0]["timestamp"] = {"source": "now"}
    elif how == "bad_field":
        arts[0]["timestamp"] = {"source": "json", "field": "a..b"}
    elif how == "bad_cadence":
        arts[0]["cadence"] = "whenever"
    elif how == "signed_not_bool":
        arts[0]["signed"] = "yes"
    elif how == "missing_required_artifact":
        cfg["artifacts"] = [a for a in arts if a["path"] != ".well-known/ksi-signal-runtime.json"]
    return cfg


@pytest.mark.parametrize("how", ["no_version", "no_decided_by", "bad_review_by", "unknown_key", "no_artifacts",
                                 "string_window", "bool_window", "zero_window", "path_escape", "outside_well_known",
                                 "duplicate", "bad_timestamp", "bad_field", "bad_cadence", "signed_not_bool",
                                 "missing_required_artifact"])
def test_each_invalid_config_fails_closed(tmp_path, how):
    with pytest.raises(SystemExit):
        load_freshness_config(write(tmp_path, _break(good(), how)))


def _published(workflow, step_name, signatures=False):
    """Object names a workflow step writes under .well-known/, with for-loops
    expanded. Signatures, schemas and markdown renderings are covered through
    the artifact they accompany."""
    text = (REPO / ".github" / "workflows" / workflow).read_text()
    start = text.index(f"- name: {step_name}")
    end = text.find("\n    - name:", start + 1)
    step = text[start:end if end > 0 else None]
    names = set()
    for loop in re.finditer(r"for (\w+) in ([^;\n]+); do(.*?)\n\s*done", step, re.S):
        var, items, body = loop.groups()
        for tmpl in re.findall(r"\.well-known/\$" + var + r"(\.[\w.]+)", body):
            names |= {item + tmpl for item in items.split()}
    names |= set(re.findall(r"\.well-known/([A-Za-z0-9][\w.-]*)(?![\w.*-])", step))
    names |= {m for m in re.findall(r"^\s*put ([\w.-]+)\s", step, re.M)}
    for items, body in re.findall(r"for (?:\w+) in ([^;\n]+); do(.*?)\n\s*done", step, re.S):
        for suffix in re.findall(r'put "\$\w+(\.[\w.]+)"', body):
            names |= {i + suffix for i in items.split()}
    if signatures:
        return {n for n in names if n.endswith(".bundle")}
    return {n for n in names if not n.endswith((".bundle", ".md", ".schema.json"))}


def test_every_artifact_the_pipelines_publish_has_a_governed_window():
    """The deploy publishes only what the config lists (tests/test_published_set.py
    runs its steps); the nightly keeps an explicit put list that mirrors its
    role's grant, so its steps are read here."""
    cfg = good()
    listed = {a["path"].removeprefix(".well-known/") for a in cfg["artifacts"]}
    deploy_text = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    for step in ("Publication redaction gate (no AWS account ID)", "Publish all signed artifacts to /.well-known/",
                 "Post-publish round-trip verify"):
        body = deploy_text[deploy_text.index(f"- name: {step}"):]
        body = body[:body.find("\n    - name:")]
        assert "published-set.py" in body and "--by deploy" in body, step
    nightly = _published("evidence-nightly.yml", "Publish VDR + trend to /.well-known/") \
        | _published("evidence-nightly.yml", "Write status beacon for the evidence watchdog")
    assert "vdr-report.json" in nightly and "vdr-status.json" in nightly
    assert not nightly - listed, f"published without a governed freshness window: {sorted(nightly - listed)}"
    by_nightly = {a["path"].removeprefix(".well-known/") for a in cfg["artifacts"] if "nightly" in a["published_by"]}
    assert nightly == by_nightly, "the nightly's put list and the config's published_by disagree"


def test_every_listed_signature_is_published():
    nightly = _published("evidence-nightly.yml", "Publish VDR + trend to /.well-known/", signatures=True) \
        | _published("evidence-nightly.yml", "Write status beacon for the evidence watchdog", signatures=True)
    for a in good()["artifacts"]:
        if "signature" in a:
            assert a["signed"], a["path"]
            if "nightly" in a["published_by"]:
                assert a["signature"].removeprefix(".well-known/") in nightly, a["path"]


def _btc():
    spec = importlib.util.spec_from_file_location("btc_fresh", REPO / "scripts" / "build-trust-center.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_the_trust_center_reports_against_the_governed_windows():
    btc = _btc()
    cfg = load_freshness_config(CONFIG)
    assert btc.VDR_MAX_AGE_HOURS == cfg["windows"][".well-known/vdr-report.json"]
    assert btc.RUNTIME_MAX_AGE_HOURS == cfg["windows"][".well-known/ksi-signal-runtime.json"]
    assert btc.CORROBORATION_MAX_AGE_DAYS * 24 == cfg["windows"][".well-known/boundary-corroboration.json"]


def test_the_trust_center_fails_closed_on_an_invalid_config(tmp_path, monkeypatch):
    monkeypatch.setenv("FRESHNESS_CONFIG", str(BAD))
    with pytest.raises(SystemExit):
        _btc()
