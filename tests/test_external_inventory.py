"""External services inside the boundary (Rule of Thumb #2) are inventoried and placed.

The Anthropic API was once drawn on the boundary but missing from the canonical
inventory. Since SCN-2026-006 the app's LLM feedback is off in this deployment,
so the interconnection must be gone from the inventory and the map.
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


def test_anthropic_api_is_not_in_the_inventory_or_the_map():
    ids = {c["component_id"] for c in bks.build_external_components()}
    assert "ext::anthropic-api" not in ids
    matched = [m for g in CLASSIFICATION["groups"] for m in g.get("match", [])]
    assert "ext::anthropic-api" not in matched
    for flow in CLASSIFICATION["flows"]:
        assert {"component": "ext::anthropic-api"} not in flow["path"], flow["id"]


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
