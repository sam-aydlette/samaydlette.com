"""The committed live-boundary-map snapshot is well formed, attributable and public-safe.

The snapshot is generated on the operator's machine by tools/boundary-map/export.py from
a local RAMPART (TAP) instance; CI cannot regenerate it. These hermetic checks are what
CI can hold it to: it matches the committed classification, every reference in it
resolves, it credits the platform that produced it, and it carries nothing the exporter
promises to strip.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MAP_DIR = REPO / "website" / "assets" / "boundary-map"
SNAPSHOT = MAP_DIR / "boundary-map.json"
CLASSIFICATION = REPO / "docs" / "boundary" / "boundary-classification.json"
PAGE = REPO / "website" / "research" / "authorization-boundary.html"

PUBLIC_TAGS = {
    "Archetype",
    "DataClassification",
    "DataSensitivity",
    "InternetReachable",
    "MissionCriticality",
    "Environment",
}


def snapshot() -> dict:
    return json.loads(SNAPSHOT.read_text())


def classification() -> dict:
    return json.loads(CLASSIFICATION.read_text())


def test_schema_and_attribution():
    s = snapshot()
    assert s["schema"] == "rampart-boundary-map/1"
    assert "RAMPART" in s["attribution"]["text"] and "TAP" in s["attribution"]["text"]
    assert s["attribution"]["tap_url"].startswith(
        "https://github.com/unified-systems-com/"
    )
    dt.datetime.fromisoformat(s["collected_at"])


def test_exported_from_the_committed_classification():
    # Editing the classification without re-exporting would publish a map that no
    # longer says what the classification says.
    committed = hashlib.sha256(CLASSIFICATION.read_bytes()).hexdigest()
    assert snapshot()["source"]["classification_sha256"] == committed, (
        "docs/boundary/boundary-classification.json changed since the last export; run `make boundary-map`"
    )


def test_carries_no_arn_account_id_or_email():
    text = SNAPSHOT.read_text()
    assert not re.search(r"arn:aws[a-z-]*:", text)
    assert not re.search(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])", text)
    assert not re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)


def test_only_public_classification_tags():
    for n in snapshot()["nodes"]:
        assert set(n.get("tags", {})) <= PUBLIC_TAGS, n["name"]


def test_every_reference_resolves():
    s = snapshot()
    ids = [n["id"] for n in s["nodes"]]
    assert len(ids) == len(set(ids))
    groups = {g["key"] for g in s["groups"]}
    zones = {z["key"] for z in s["zones"]}
    for n in s["nodes"]:
        assert n["group"] in groups and n["zone"] in zones, n["name"]
        if "icon" in n:
            assert (MAP_DIR / n["icon"]).is_file(), n["icon"]
    known = set(ids)
    for e in s["edges"]:
        assert e["source"] in known and e["target"] in known
    for f in s["flows"]:
        assert f["hops"], f"flow {f['id']} has no hop"
        assert all(a in known and b in known for a, b in f["hops"]), f["id"]


def test_flows_are_the_classifications_flows():
    assert [f["id"] for f in snapshot()["flows"]] == [
        f["id"] for f in classification()["flows"]
    ]


def test_health_matches_the_nodes():
    s = snapshot()
    flags = [f for n in s["nodes"] for f in n.get("flags", [])]
    h = s["health"]
    assert h["unclassified"] == sum(
        1 for n in s["nodes"] if n["group"] == "unclassified"
    )
    assert h["untagged"] == flags.count("untagged")
    assert h["declared_not_collected"] == sum(
        1 for n in s["nodes"] if n["kind"] == "not_collected"
    )
    assert h["flows_with_unmatched_endpoint"] == sum(
        1 for f in s["flows"] if f["unmatched_endpoints"]
    )


def test_page_hosts_the_map_and_credits_tap():
    html = PAGE.read_text()
    assert 'data-boundary-map="/assets/boundary-map/boundary-map.json"' in html
    assert "data-boundary-map-text" in html
    assert 'src="/assets/js/boundary-map.js' in html
    assert "https://github.com/unified-systems-com/tap" in html


def test_icons_cannot_run_script():
    # Icons are served from the site's own origin; opened directly, an SVG is a document.
    unsafe = re.compile(
        rb"<script|\son[a-z]+\s*=|javascript:|<foreignObject|<iframe|<embed|<object",
        re.IGNORECASE,
    )
    for icon in (MAP_DIR / "icons").glob("*"):
        assert re.fullmatch(r"[a-z0-9-]+\.svg", icon.name), icon.name
        assert not unsafe.search(icon.read_bytes()), icon.name


def test_links_are_same_origin_or_https():
    for n in snapshot()["nodes"]:
        link = n.get("link")
        if link:
            assert (
                link.startswith("/") and not link.startswith("//")
            ) or link.startswith("https://"), link
