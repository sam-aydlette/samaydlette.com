"""External services inside the boundary (Rule of Thumb #2) are inventoried and placed.

The Anthropic API was drawn on the boundary but missing from the canonical
inventory, so the map could show it only as "declared, not inventoried".
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bks = _load("bks", REPO / "scripts" / "build-ksi-signal.py")
bbg = _load("bbg", REPO / "scripts" / "build-boundary-graph.py")
CLASSIFICATION = json.loads((REPO / "docs" / "boundary" / "boundary-classification.json").read_text())


def test_anthropic_api_is_an_inventoried_external_service():
    comps = {c["component_id"]: c for c in bks.build_external_components()}
    api = comps["ext::anthropic-api"]
    assert api["type"] == "external_service"
    assert api["native_id"] == "https://api.anthropic.com"
    assert "POAM-020" in api["attributes"]["fedramp_status"]
    assert {f["direction"] for f in api["information_flow"]} == {"inbound", "outbound"}


def test_every_external_service_is_placed_in_the_external_zone():
    groups = CLASSIFICATION["groups"]
    for c in bks.build_external_components():
        g = bbg.group_for(c["component_id"], groups)
        assert g is not None and g["zone"] == "external", c["component_id"]


def test_nothing_the_classification_declares_is_also_inventoried():
    ids = {c["component_id"] for c in bks.build_external_components()}
    for d in CLASSIFICATION["declared"]:
        assert d.get("kind") != "not_inventoried" or f"ext::{d['key']}" not in ids
    assert not any(d["key"] == "anthropic" for d in CLASSIFICATION["declared"])
