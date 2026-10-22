"""The service model: CSP -> CSO -> feature -> service -> component -> owner.

Services place components through the boundary groups (which already place
every AWS and external component) or through selectors for the inventory types
the boundary map leaves out. Every boundary group belongs to exactly one
service, every owner is a governed domain, and a service consumed by more than
one CSO is a shared service.
"""
import json
from pathlib import Path

import jsonschema

REPO = Path(__file__).resolve().parent.parent
MODEL = REPO / "docs" / "portfolio" / "service-model.json"
SCHEMA = REPO / "infrastructure" / "schemas" / "service-model.schema.json"
REGISTRY = REPO / "docs" / "governance" / "domains.json"
CLASSIFICATION = REPO / "docs" / "boundary" / "boundary-classification.json"


def _load(path):
    return json.loads(path.read_text())


def test_model_validates_against_schema():
    jsonschema.validate(_load(MODEL), _load(SCHEMA))


def test_keys_are_unique():
    m = _load(MODEL)
    for section in ("csos", "features", "sources", "services"):
        keys = [x["key"] for x in m[section]]
        assert len(keys) == len(set(keys)), section


def test_every_boundary_group_is_exactly_one_service():
    groups = [g["key"] for g in _load(CLASSIFICATION)["groups"]]
    used = [s["group"] for s in _load(MODEL)["services"] if "group" in s]
    assert sorted(used) == sorted(groups)


def test_every_owner_is_a_governed_domain():
    m = _load(MODEL)
    domains = {d["id"] for d in _load(REGISTRY)["domains"]}
    for x in m["csos"] + m["services"]:
        assert x["owner_domain"] in domains, x["key"]


def test_references_resolve():
    m = _load(MODEL)
    csos = {c["key"] for c in m["csos"]}
    features = {f["key"]: f["cso"] for f in m["features"]}
    sources = {s["key"] for s in m["sources"]}
    assert set(features.values()) <= csos
    for s in m["services"]:
        assert set(s["consumed_by"]) <= csos, s["key"]
        for f in s["features"]:
            assert f in features, (s["key"], f)
            # A service only supports features of the offerings that consume it.
            assert features[f] in s["consumed_by"], (s["key"], f)
        for sel in s.get("selectors", []):
            if "source" in sel:
                assert sel["source"] in sources, (s["key"], sel["source"])


def test_every_feature_is_supported_by_a_service():
    m = _load(MODEL)
    supported = {f for s in m["services"] for f in s["features"]}
    assert {f["key"] for f in m["features"]} <= supported


def test_every_source_is_selected_exactly_once():
    m = _load(MODEL)
    selected = [sel["source"] for s in m["services"] for sel in s.get("selectors", []) if "source" in sel]
    assert sorted(selected) == sorted(src["key"] for src in m["sources"])


def test_in_repo_sources_exist():
    for src in _load(MODEL)["sources"]:
        if "repo_path" in src:
            assert (REPO / src["repo_path"]).is_file(), src["repo_path"]


def test_each_cso_has_its_own_service_and_shares_the_rest():
    m = _load(MODEL)
    shared = [s for s in m["services"] if len(s["consumed_by"]) > 1]
    assert shared, "no shared services"
    for c in m["csos"]:
        own = [s for s in m["services"] if s["consumed_by"] == [c["key"]]]
        assert own, f"{c['key']} has no service of its own"


def test_owners_are_not_people():
    text = MODEL.read_text()
    assert "@" not in text
    holder = _load(REGISTRY)["holder"]["name"]
    assert holder not in text
