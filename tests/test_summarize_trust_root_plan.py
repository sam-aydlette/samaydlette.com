"""The trust-root plan summary reports drift as data and never leaks attribute values."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "summarize-trust-root-plan.py"
)
spec = importlib.util.spec_from_file_location("summarize_trust_root_plan", SCRIPT)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

NOW = "2026-09-28T12:00:00+00:00"


def plan(*changes):
    return {
        "resource_changes": [
            {
                "address": addr,
                "mode": mode,
                "change": {
                    "actions": actions,
                    "before": {
                        "arn": "arn:aws:iam::123456789012:role/x",
                        "policy": "{}",
                    },
                    "after": {
                        "arn": "arn:aws:iam::123456789012:role/x",
                        "policy": '{"Statement":[]}',
                    },
                },
            }
            for addr, mode, actions in changes
        ]
    }


def test_in_sync_when_nothing_changes():
    s = mod.summarize(
        plan(("aws_iam_role.deploy", "managed", ["no-op"])), 0, "abc", NOW
    )
    assert s["status"] == "in_sync" and s["changes"] == []


def test_pending_changes_are_listed_by_address_and_action():
    s = mod.summarize(
        plan(
            ("aws_iam_role.plan", "managed", ["create"]),
            ("aws_iam_role.deploy", "managed", ["update"]),
            ("data.aws_iam_policy_document.trust", "data", ["read"]),
        ),
        2,
        "abc",
        NOW,
    )
    assert s["status"] == "changes_pending"
    assert s["changes"] == [
        {"address": "aws_iam_role.deploy", "actions": ["update"]},
        {"address": "aws_iam_role.plan", "actions": ["create"]},
    ]


def test_error_when_the_plan_could_not_run():
    assert mod.summarize(None, 1, "abc", NOW)["status"] == "error"


def test_never_carries_attribute_values():
    text = json.dumps(
        mod.summarize(
            plan(("aws_iam_role.deploy", "managed", ["update"])), 2, "abc", NOW
        )
    )
    assert (
        "arn:aws" not in text and "123456789012" not in text and "Statement" not in text
    )


def test_not_observable_before_the_state_migration():
    s = mod.summarize(None, 1, "abc", NOW, state_empty=True)
    assert s["status"] == "not_observable" and s["changes"] == []
