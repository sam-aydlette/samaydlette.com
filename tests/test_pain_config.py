"""PR-A: governed PAIN classifier configuration.

Pins the committed config's values and the loader's fail-closed validation. The
config holds the only tunable knobs of the CVSS-Environmental method; the
FedRAMP remediation-day matrix is NOT here (it stays verbatim in code).
"""
import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CONFIG = REPO / "infrastructure" / "schemas" / "vdr-pain-config.json"


def _vdr():
    spec = importlib.util.spec_from_file_location("vdr", REPO / "scripts" / "build-vdr-report.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vdr = _vdr()


def test_committed_config_loads_and_validates():
    cfg, sha = vdr.load_pain_config(str(CONFIG))
    assert len(sha) == 64
    assert cfg["version"]
    t = cfg["pain_word_thresholds"]
    assert (t["minimal_to_narrow"], t["narrow_to_disruptive"], t["disruptive_to_debilitating"]) == (0.25, 0.55, 0.80)
    assert cfg["epss_threshold"] == 0.70
    assert cfg["isc_cap"] == 0.915
    assert cfg["cvss_impact_weights"] == {"none": 0.0, "low": 0.22, "high": 0.56}
    assert cfg["requirement_weights"] == {"low": 0.5, "medium": 1.0, "high": 1.5}


def test_multi_agency_default_is_hardwired_zero():
    """Single operator, no agency data: the scope term m is always 0."""
    cfg, _ = vdr.load_pain_config(str(CONFIG))
    assert cfg["multi_agency_default"] == 0


def test_tag_to_requirement_maps_cover_every_tag_value():
    cfg, _ = vdr.load_pain_config(str(CONFIG))
    assert set(cfg["data_sensitivity_to_requirement"]) == {"public", "internal", "pii", "cui"}
    assert set(cfg["mission_criticality_to_requirement"]) == {"low", "moderate", "high"}
    levels = set(cfg["requirement_weights"])
    for v in cfg["data_sensitivity_to_requirement"].values():
        assert v in levels
    for v in cfg["mission_criticality_to_requirement"].values():
        assert v in levels


def test_loader_fails_closed_on_missing_file(tmp_path):
    with pytest.raises(SystemExit):
        vdr.load_pain_config(str(tmp_path / "does-not-exist.json"))


def test_loader_fails_closed_on_non_ascending_thresholds(tmp_path):
    cfg = json.loads(CONFIG.read_text())
    cfg["pain_word_thresholds"]["narrow_to_disruptive"] = 0.20  # below minimal_to_narrow
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(cfg))
    with pytest.raises(SystemExit):
        vdr.load_pain_config(str(bad))


def test_loader_fails_closed_on_bad_multi_agency_value(tmp_path):
    cfg = json.loads(CONFIG.read_text())
    cfg["multi_agency_default"] = 2
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(cfg))
    with pytest.raises(SystemExit):
        vdr.load_pain_config(str(bad))


def test_loader_fails_closed_on_missing_required_key(tmp_path):
    cfg = json.loads(CONFIG.read_text())
    del cfg["epss_threshold"]
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(cfg))
    with pytest.raises(SystemExit):
        vdr.load_pain_config(str(bad))


def test_committed_config_matches_its_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((CONFIG.parent / "vdr-pain-config.schema.json").read_text())
    jsonschema.validate(json.loads(CONFIG.read_text()), schema)
