"""Unit tests for scripts/_common.py — the shared generator helpers.

These helpers were extracted from verbatim duplicates across the generators. The
extraction was verified output-neutral by byte-diffing regenerated artifacts, but
that check needs build products; these tests pin the behavior itself so a future
edit to a shared helper cannot quietly change what four artifacts assert.
"""
import hashlib
import json
import sys
import uuid
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import _common as c  # noqa: E402


# ---------------------------------------------------------------------------
# classify — the reason this module exists
# ---------------------------------------------------------------------------
# Status wins over origination: a control that is N/A or planned has no
# inheritance story yet. Everything else projects the FedRAMP control-origination
# onto the shared-responsibility vocabulary the CRM, CMMC SRM, coverage figures
# and framework spokes all read.
@pytest.mark.parametrize("status,origination,expected", [
    # status short-circuits, whatever the origination says
    ("not-applicable", "inherited",           "not-applicable"),
    ("not-applicable", "sp-system",           "not-applicable"),
    ("planned",        "shared",              "planned"),
    ("planned",        None,                  "planned"),
    # origination decides for everything that is actually implemented
    ("implemented",    "inherited",           "fully-inherited"),
    ("partial",        "inherited",           "fully-inherited"),
    ("implemented",    "shared",              "partially-inherited"),
    ("implemented",    "customer-configured", "customer-responsibility"),
    ("implemented",    "customer-provided",   "customer-responsibility"),
    ("implemented",    "sp-system",           "implemented"),
    ("implemented",    "sp-corporate",        "implemented"),
    # the provider-implements default also catches an absent origination
    ("implemented",    None,                  "implemented"),
    ("alternative",    "unrecognised-value",  "implemented"),
])
def test_classify_truth_table(status, origination, expected):
    assert c.classify(status, origination) == expected


def test_classify_covers_the_published_vocabulary():
    """Every value classify can return is one the downstream artifacts know."""
    known = {"implemented", "partially-inherited", "fully-inherited",
             "customer-responsibility", "planned", "not-applicable"}
    produced = {c.classify(s, o)
                for s in ("implemented", "partial", "planned", "not-applicable", "alternative")
                for o in ("inherited", "shared", "customer-configured", "customer-provided",
                          "sp-system", "sp-corporate", None)}
    assert produced <= known


# ---------------------------------------------------------------------------
# sha256_file
# ---------------------------------------------------------------------------
def test_sha256_file_matches_hashlib(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"the quick brown fox")
    assert c.sha256_file(f) == hashlib.sha256(b"the quick brown fox").hexdigest()


def test_sha256_file_spans_the_chunk_boundary(tmp_path):
    """Reads in 64 KiB chunks, so a payload larger than one chunk is the case
    that would break if the loop were wrong."""
    payload = bytes(range(256)) * 1024  # 256 KiB
    f = tmp_path / "big.bin"
    f.write_bytes(payload)
    assert c.sha256_file(f) == hashlib.sha256(payload).hexdigest()


def test_sha256_file_handles_empty(tmp_path):
    f = tmp_path / "empty"
    f.write_bytes(b"")
    assert c.sha256_file(f) == hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# sid
# ---------------------------------------------------------------------------
NS_A = uuid.UUID("a1b2c3d4-e5f6-5a7b-8c9d-0e1f2a3b4c5d")
NS_B = uuid.UUID("b1b2c3d4-e5f6-5a7b-8c9d-0e1f2a3b4c5d")


def test_sid_is_deterministic():
    assert c.sid(NS_A, "map", "ac-1") == c.sid(NS_A, "map", "ac-1")


def test_sid_matches_uuid5_over_colon_joined_parts():
    assert c.sid(NS_A, "map", "ac-1") == str(uuid.uuid5(NS_A, "map:ac-1"))


def test_sid_namespace_is_load_bearing():
    """The namespace is a parameter precisely so two generators cannot collide
    into one another's UUID space."""
    assert c.sid(NS_A, "map", "ac-1") != c.sid(NS_B, "map", "ac-1")


def test_sid_parts_are_not_ambiguous():
    assert c.sid(NS_A, "a", "b") != c.sid(NS_A, "ab")


# ---------------------------------------------------------------------------
# prop
# ---------------------------------------------------------------------------
def test_prop_reads_a_named_value():
    obj = {"props": [{"name": "implementation-status", "value": "implemented"}]}
    assert c.prop(obj, "implementation-status") == "implemented"


def test_prop_returns_none_for_absent_missing_or_null_props():
    assert c.prop({"props": [{"name": "x", "value": "1"}]}, "y") is None
    assert c.prop({}, "anything") is None
    assert c.prop({"props": None}, "anything") is None
    assert c.prop({"props": []}, "anything") is None


def test_prop_returns_the_first_match():
    obj = {"props": [{"name": "n", "value": "first"}, {"name": "n", "value": "second"}]}
    assert c.prop(obj, "n") == "first"


# ---------------------------------------------------------------------------
# load_hub
# ---------------------------------------------------------------------------
def _ssp(irs):
    return {"system-security-plan": {"control-implementation": {"implemented-requirements": irs}}}


def test_load_hub_maps_control_id_to_status_and_origination(tmp_path):
    p = tmp_path / "ssp.json"
    p.write_text(json.dumps(_ssp([
        {"control-id": "ac-1", "props": [
            {"name": "implementation-status", "value": "implemented"},
            {"name": "control-origination", "value": "sp-system"}]},
        {"control-id": "au-2", "props": [
            {"name": "implementation-status", "value": "not-applicable"},
            {"name": "control-origination", "value": "inherited"}]},
    ])))
    assert c.load_hub(p) == {"ac-1": ("implemented", "sp-system"),
                             "au-2": ("not-applicable", "inherited")}


def test_load_hub_tolerates_a_requirement_with_no_props(tmp_path):
    p = tmp_path / "ssp.json"
    p.write_text(json.dumps(_ssp([{"control-id": "ac-1"}])))
    assert c.load_hub(p) == {"ac-1": (None, None)}


def test_load_hub_output_feeds_classify(tmp_path):
    """The two are always used together: hub -> classify -> the artifact."""
    p = tmp_path / "ssp.json"
    p.write_text(json.dumps(_ssp([
        {"control-id": "ac-1", "props": [
            {"name": "implementation-status", "value": "implemented"},
            {"name": "control-origination", "value": "shared"}]},
    ])))
    status, origination = c.load_hub(p)["ac-1"]
    assert c.classify(status, origination) == "partially-inherited"


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
def test_oscal_version_is_the_published_pin():
    """Bumping this changes every consumer's view of the SSP and POA&M. If this
    test fails, the change was intended to be a reviewed artifact change."""
    assert c.OSCAL_VERSION == "1.1.2"


def test_fedramp_ns_is_the_published_namespace():
    assert c.FEDRAMP_NS == "https://fedramp.gov/ns/oscal"
