"""Invariant (l): the published boundary map describes exactly this build's inventory."""

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("reconcile_l", REPO / "scripts" / "reconcile.py")
rec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rec)

SIGNAL = {"signal_id": "sig-1", "components": [
    {"component_id": "aws::function::app", "type": "function"},
    {"component_id": "ext::github-repo", "type": "external_service"},
    {"component_id": "npm::x@1", "type": "npm_package"},
]}


def good_map():
    return {
        "ksi_signal_id": "sig-1", "commit": "abc", "unclassified": [],
        "nodes": [
            {"id": "aws::function::app", "kind": "collected"},
            {"id": "ext::github-repo", "kind": "collected"},
            {"id": "declared:users", "kind": "actor"},
        ],
    }


def test_absent_map_is_skipped():
    assert rec.check_l_boundary_map(SIGNAL, None, "abc") == []


def test_a_map_of_this_build_passes():
    assert rec.check_l_boundary_map(SIGNAL, good_map(), "abc") == []


def test_binding_and_freshness():
    m = good_map() | {"ksi_signal_id": "other", "commit": "old"}
    v = rec.check_l_boundary_map(SIGNAL, m, "abc")
    assert any("signal_id" in x for x in v) and any("commit" in x for x in v)


def test_missing_and_extra_components_fail():
    m = good_map()
    m["nodes"] = [n for n in m["nodes"] if n["id"] != "ext::github-repo"] + [{"id": "aws::queue::ghost", "kind": "collected"}]
    v = rec.check_l_boundary_map(SIGNAL, m, "abc")
    assert any("ext::github-repo is missing" in x for x in v)
    assert any("aws::queue::ghost is not in the inventory" in x for x in v)


def test_unclassified_fails_the_gate():
    m = good_map() | {"unclassified": ["aws::function::app"]}
    assert any("unclassified" in x for x in rec.check_l_boundary_map(SIGNAL, m, "abc"))


def test_identifiers_fail_the_gate():
    m = good_map()
    m["nodes"][0]["name"] = "arn:aws:lambda:us-east-2:123456789012:function:app"
    v = rec.check_l_boundary_map(SIGNAL, m, "abc")
    assert any("an ARN" in x for x in v) and any("account ID" in x for x in v)


def test_report_lists_held_and_deferred_invariants():
    r = rec.build_report(SIGNAL, "abc", deferred={"a": True, "i": True, "k": False, "l": False})
    status = {i["id"]: i["status"] for i in r["invariants"]}
    assert r["result"] == "pass" and r["ksi_signal_id"] == "sig-1"
    assert status["a"] == "deferred" and status["l"] == "held" and status["e"] == "held"
