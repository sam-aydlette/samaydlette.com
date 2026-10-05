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
    summarize-trust-root-plan.py --exit-code $rc --plan-json plan.json --commit $SHA \
        --state-serial $SERIAL --state-lineage $LINEAGE > trust-root-plan.json

The plan runs in compliance-check, before the deploy's approval gate; the deploy
job reads the bootstrap state again afterwards, possibly hours later. If the
operator applied the trust root in between, the plan's pending changes describe
a state that no longer exists. So the summary records which state version it
planned against (Terraform's state serial and lineage, metadata only), and the
deploy job checks it against the state it actually reads:

    summarize-trust-root-plan.py --reconcile-state $SERIAL $LINEAGE --in trust-root-plan.json

A different version marks the summary "superseded": nothing is reported as
pending, because nothing about the current state is known from this plan.

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
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "schema": SCHEMA,
        "planned_at": now,
        "commit": commit,
        "stack": "infrastructure/bootstrap",
    }
    if state and state.get("serial") is not None and state.get("lineage"):
        out["state"] = {"serial": int(state["serial"]), "lineage": str(state["lineage"])}
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


def reconcile_state(summary: dict[str, Any], serial: int | None, lineage: str | None) -> dict[str, Any]:
    """Mark the summary superseded if the state now differs from the one planned against.

    Only a known, different version supersedes. When either side's version is
    unknown (the state could not be read, or the plan predates this field), the
    summary is returned unchanged: there is no evidence it is stale.
    """
    planned = summary.get("state") or {}
    if serial is None or not lineage or planned.get("serial") is None or not planned.get("lineage"):
        return summary
    if planned["serial"] == serial and planned["lineage"] == lineage:
        return summary
    if summary.get("status") not in ("changes_pending", "in_sync"):
        return summary
    out = dict(summary)
    out["changes_at_plan"] = summary.get("changes", [])
    out["changes"] = []
    out["status"] = "superseded"
    out["state_at_build"] = {"serial": serial, "lineage": lineage}
    out["note"] = "The trust root was applied after this build planned it. The next build re-plans it."
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--exit-code",
        type=int,
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
    ap.add_argument("--state-serial", type=int, help="bootstrap state serial the plan read")
    ap.add_argument("--state-lineage", help="bootstrap state lineage the plan read")
    ap.add_argument(
        "--reconcile-state",
        nargs=2,
        metavar=("SERIAL", "LINEAGE"),
        help="compare an existing summary (--in) against the state the deploy read, and rewrite it in place",
    )
    ap.add_argument("--in", dest="in_path", type=Path, help="existing summary, with --reconcile-state")
    args = ap.parse_args()
    if args.reconcile_state:
        if not args.in_path:
            ap.error("--reconcile-state needs --in")
        raw_serial, lineage = args.reconcile_state
        serial = int(raw_serial) if raw_serial.isdigit() else None
        summary = json.loads(args.in_path.read_text())
        result = reconcile_state(summary, serial, lineage or None)
        args.in_path.write_text(json.dumps(result, indent=2) + "\n")
        print(f"Trust root: {result.get('status')}")
        return
    if args.exit_code is None:
        ap.error("--exit-code is required")
    plan = None
    if args.plan_json and args.plan_json.is_file() and args.plan_json.stat().st_size:
        plan = json.loads(args.plan_json.read_text())
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    json.dump(
        summarize(plan, args.exit_code, args.commit, now, args.state_empty,
                  {"serial": args.state_serial, "lineage": args.state_lineage}),
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
