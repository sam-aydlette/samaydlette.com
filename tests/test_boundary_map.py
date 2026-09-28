"""The live boundary map page draws the signed, generated map and nothing hand-made.

The map's data is built on every deploy (scripts/build-boundary-graph.py; tested in
test_build_boundary_graph.py) and bound to the build by reconciliation invariant (l).
These checks cover what the site commits: the page wiring, the classification that
drives the build, and the icons served from this origin.
"""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ICONS = REPO / "website" / "assets" / "boundary-map" / "icons"
CLASSIFICATION = REPO / "docs" / "boundary" / "boundary-classification.json"
PAGE = REPO / "website" / "research" / "authorization-boundary.html"


def classification() -> dict:
    return json.loads(CLASSIFICATION.read_text())


def test_page_draws_the_signed_generated_map():
    html = PAGE.read_text()
    assert 'data-boundary-map="/.well-known/boundary-map.json"' in html
    assert "data-boundary-map-text" in html
    assert 'src="/assets/js/boundary-map.js' in html
    assert "/assets/boundary-map/boundary-map.json" not in html  # the retired hand-exported snapshot


def test_classification_is_well_formed():
    c = classification()
    zones = {z["key"] for z in c["zones"]}
    for g in c["groups"]:
        assert g["zone"] in zones and g["match"], g["key"]
    declared = {d["key"] for d in c["declared"]}
    for d in c["declared"]:
        assert d["zone"] in zones and d["kind"] in {"actor", "not_inventoried"}, d["key"]
    for f in c["flows"]:
        assert len(f["path"]) >= 2, f["id"]
        for ref in f["path"]:
            assert ("component" in ref) != ("declared" in ref), f["id"]
            if "declared" in ref:
                assert ref["declared"] in declared, (f["id"], ref)
    assert [f["id"] for f in c["flows"]] == sorted(f["id"] for f in c["flows"])


def test_every_flow_endpoint_pattern_is_placed_by_some_group():
    # A component a flow names must also be classified, or the flow would point at
    # something the map cannot place.
    c = classification()
    patterns = [p for g in c["groups"] for p in g["match"]]
    for f in c["flows"]:
        for ref in f["path"]:
            comp = ref.get("component")
            # A wildcard endpoint ("every function") spans groups by design.
            if comp and "*" not in comp:
                assert any(fnmatch.fnmatchcase(comp, p) for p in patterns), (f["id"], comp)


def test_icons_cannot_run_script():
    # Icons are served from the site's own origin; opened directly, an SVG is a document.
    unsafe = re.compile(rb"<script|\son[a-z]+\s*=|javascript:|<foreignObject|<iframe|<embed|<object", re.IGNORECASE)
    for icon in ICONS.glob("*"):
        assert re.fullmatch(r"[a-z0-9-]+\.svg", icon.name), icon.name
        assert not unsafe.search(icon.read_bytes()), icon.name


def test_every_icon_the_viewer_names_exists():
    js = (REPO / "website" / "assets" / "js" / "boundary-map.js").read_text()
    maps = js[js.index("const ICON_BY_TYPE"):js.index("const CLASSIFICATION_LABELS")]
    names = set(re.findall(r":\s*'([a-z0-9-]+)'", maps))
    assert names, "the viewer names no icons"
    for name in names:
        assert (ICONS / f"{name}.svg").is_file(), name
