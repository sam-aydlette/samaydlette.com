"""Every Terraform resource type declared under infrastructure/ is accounted
for by the inventory builder: a component (TYPE_BY_TF_TYPE), a facet folded
into one (ATTRIBUTE_PARENTS), or excluded with a stated reason
(NOT_INVENTORIED). A resource added to the Terraform cannot silently fall out
of the canonical inventory, as the edge access-log delivery and the edge
function once did."""
import importlib.util
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "inventory-types"

spec = importlib.util.spec_from_file_location("bks_types", REPO / "scripts" / "build-ksi-signal.py")
bks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bks)


def declared_types(paths):
    out = {}
    for f in paths:
        for t in re.findall(r'^resource "(\w+)" "', f.read_text(), re.M):
            out.setdefault(t, set()).add(f.name)
    return out


def unaccounted(paths):
    known = set(bks.TYPE_BY_TF_TYPE) | set(bks.ATTRIBUTE_PARENTS) | set(bks.NOT_INVENTORIED)
    return sorted(set(declared_types(paths)) - known)


def _terraform():
    return [f for f in (REPO / "infrastructure").rglob("*.tf") if ".terraform" not in f.parts]


def test_every_declared_type_is_mapped_folded_or_excluded_with_a_reason():
    assert unaccounted(_terraform()) == []


def test_the_three_lists_do_not_overlap_and_every_exclusion_has_a_reason():
    a, b, c = set(bks.TYPE_BY_TF_TYPE), set(bks.ATTRIBUTE_PARENTS), set(bks.NOT_INVENTORIED)
    assert not (a & b) and not (a & c) and not (b & c)
    for t, why in bks.NOT_INVENTORIED.items():
        assert isinstance(why, str) and len(why) > 20, t


def test_no_exclusion_is_stale():
    declared = set(declared_types(_terraform()))
    assert set(bks.NOT_INVENTORIED) <= declared


def test_the_edge_function_and_access_log_delivery_are_in_the_inventory():
    for t in ("aws_cloudfront_function", "aws_cloudwatch_log_delivery_source",
              "aws_cloudwatch_log_delivery_destination", "aws_cloudwatch_log_delivery"):
        assert bks.ATTRIBUTE_PARENTS[t] == "cdn_distribution", t
    state = {"values": {"root_module": {"resources": [
        {"address": "aws_cloudfront_distribution.website", "type": "aws_cloudfront_distribution",
         "name": "website", "values": {"id": "E123", "arn": "arn:aws:cloudfront::123456789012:distribution/E123"}},
        {"address": "aws_cloudfront_function.directory_index", "type": "aws_cloudfront_function",
         "name": "directory_index", "values": {"name": "directory-index", "runtime": "cloudfront-js-2.0"}},
        {"address": "aws_cloudwatch_log_delivery.edge_access", "type": "aws_cloudwatch_log_delivery",
         "name": "edge_access", "values": {"record_fields": ["date", "time"]}},
    ]}}}
    comps = bks.build_cloud_components(state, {}, module_dir="infrastructure/bootstrap")
    cdn = next(c for c in comps if c["type"] == "cdn_distribution")
    cfg = cdn["attributes"]["config"]
    assert cfg["aws_cloudfront_function"]["runtime"] == "cloudfront-js-2.0"
    assert cfg["aws_cloudwatch_log_delivery"]["record_fields"] == ["date", "time"]


def test_known_bad_an_unmapped_type_is_reported():
    assert unaccounted([FIX / "unmapped.tf.fixture"]) == ["aws_elasticache_cluster"]


def test_facets_declared_in_bootstrap_reach_the_distribution_the_main_stack_inventoried(tmp_path, monkeypatch):
    """The distribution is managed in bootstrap and read by the main stack, so
    it is inventoried once; the edge function and log delivery bootstrap
    declares are still folded into that one entry."""
    import json
    dist = {"address": "aws_cloudfront_distribution.website", "type": "aws_cloudfront_distribution",
            "name": "website", "values": {"id": "E123", "arn": "arn:aws:cloudfront::123456789012:distribution/E123"}}
    main = bks.build_cloud_components({"values": {"root_module": {"resources": [dist]}}}, {})
    snap = tmp_path / "bootstrap.json"
    snap.write_text(json.dumps({"values": {"root_module": {"resources": [dist, {
        "address": "aws_cloudwatch_log_delivery_source.edge_access", "type": "aws_cloudwatch_log_delivery_source",
        "name": "edge_access", "values": {"log_type": "ACCESS_LOGS"}}]}}}))
    monkeypatch.setenv("BOOTSTRAP_STATE_JSON", str(snap))
    assert bks.build_bootstrap_components(main) == []
    cdn = next(c for c in main if c["type"] == "cdn_distribution")
    assert cdn["attributes"]["managed_by"] == "bootstrap"
    assert cdn["attributes"]["config"]["aws_cloudwatch_log_delivery_source"]["log_type"] == "ACCESS_LOGS"
