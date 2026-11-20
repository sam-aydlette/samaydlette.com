"""The inventory builder refuses a Terraform resource type it does not classify.

Every managed resource type is a component (TYPE_BY_TF_TYPE), folds into one
(ATTRIBUTE_PARENTS), or is listed with a reason (NOT_COMPONENTS). Anything else
used to be skipped silently, so a new resource could drop out of the inventory.
"""
import importlib.util
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ksi_types", REPO / "scripts" / "build-ksi-signal.py")
ksi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ksi)
LISTS = (ksi.TYPE_BY_TF_TYPE, ksi.ATTRIBUTE_PARENTS, ksi.NOT_COMPONENTS)


def _state(*resources):
    return {"values": {"root_module": {"resources": list(resources)}}}


def test_an_unclassified_resource_type_fails_the_build_and_is_named():
    state = _state({"type": "aws_s3_bucket", "name": "site", "address": "aws_s3_bucket.site", "values": {}},
                   {"type": "aws_new_thing", "name": "x", "address": "aws_new_thing.x", "values": {}})
    with pytest.raises(SystemExit, match="aws_new_thing.x"):
        ksi.build_cloud_components(state, {})


def test_listed_types_and_data_sources_are_not_refused():
    state = _state({"type": "aws_kms_alias", "name": "a", "address": "aws_kms_alias.a", "values": {}},
                   {"mode": "data", "type": "aws_caller_identity", "name": "c",
                    "address": "data.aws_caller_identity.c", "values": {}})
    assert ksi.build_cloud_components(state, {}) == []


def test_every_type_in_the_terraform_is_classified_exactly_once():
    types = {t for f in (REPO / "infrastructure").rglob("*.tf") if ".terraform" not in f.parts
             for t in re.findall(r'^resource "([a-z0-9_]+)"', f.read_text(), re.M)}
    assert types and not {t for t in types if sum(t in m for m in LISTS) != 1}


def test_every_type_left_out_has_a_reason():
    assert all(isinstance(r, str) and r.strip() for r in ksi.NOT_COMPONENTS.values())
