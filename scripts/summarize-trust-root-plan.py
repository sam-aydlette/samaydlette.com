#!/usr/bin/env python3
"""Summarize a plan of the bootstrap stack (the IAM trust root) for the trust center.

The bootstrap stack is applied by the operator, never by CI: it creates the roles
CI itself assumes. So instead of applying it, every build plans it read-only and
reports the result. A pending change is a decision waiting on a person, and the
trust center shows it as one.

Input is `terraform show -json <planfile>` output (or nothing, when the plan could
not run). Output is deliberately metadata-only: resource addresses and the actions
Terraform would take. No attribute values, before or after, ever leave this script:
the plan of an IAM stack is full of policy documents, ARNs and account IDs.

    terraform plan -detailed-exitcode -out=trust-root.tfplan; rc=$?
    terraform show -json trust-root.tfplan > plan.json
    summarize-trust-root-plan.py --exit-code $rc --plan-json plan.json --commit $SHA > trust-root-plan.json

Exit code is always 0: reporting drift is this script's job, not failing the build.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA = "trust-root-plan/1"


def summarize(
    plan: dict[str, Any] | None,
    exit_code: int,
    commit: str,
    now: str,
    state_empty: bool = False,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "schema": SCHEMA,
        "planned_at": now,
        "commit": commit,
        "stack": "infrastructure/bootstrap",
    }
    if state_empty:
        out.update(
            status="not_observable",
            changes=[],
            note="The bootstrap stack's remote state is empty: its one-time migration (infrastructure/bootstrap/backend.tf) has not run, so CI cannot see the trust root yet.",
        )
        return out
    # terraform plan -detailed-exitcode: 0 = no changes, 1 = error, 2 = changes present.
    if exit_code == 1 or plan is None:
        out.update(
            status="error",
            changes=[],
            note="The trust-root plan could not run; see the compliance-check log.",
        )
        return out
    changes = []
    for rc in plan.get("resource_changes", []):
        actions = rc.get("change", {}).get("actions", [])
        if rc.get("mode") != "managed" or actions in (["no-op"], ["read"]):
            continue
        changes.append({"address": rc["address"], "actions": actions})
    changes.sort(key=lambda c: c["address"])
    out["changes"] = changes
    out["status"] = "changes_pending" if changes else "in_sync"
    out["note"] = (
        "The bootstrap stack defines changes that have not been applied. Applying the trust root is the operator's decision."
        if changes
        else "The live trust root matches its code."
    )
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--exit-code",
        type=int,
        required=True,
        help="terraform plan -detailed-exitcode result",
    )
    ap.add_argument(
        "--plan-json",
        type=Path,
        help="terraform show -json output; omit when the plan failed",
    )
    ap.add_argument("--commit", default="")
    ap.add_argument(
        "--state-empty",
        action="store_true",
        help="the remote state holds no resources yet",
    )
    args = ap.parse_args()
    plan = None
    if args.plan_json and args.plan_json.is_file() and args.plan_json.stat().st_size:
        plan = json.loads(args.plan_json.read_text())
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    json.dump(
        summarize(plan, args.exit_code, args.commit, now, args.state_empty),
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
