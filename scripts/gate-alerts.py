#!/usr/bin/env python3
"""One alert issue per failing gate, routed to its owner (design principle 9).

Reads the results a run's gates recorded (GATE_RESULTS_FILE, written by
scripts/run-gates.sh) and, for every gate the register lists for the given
stages, keeps one GitHub issue per gate command:

    fail                         open it (or reopen it) and comment with this run
    pass                         close it, if open, with a comment naming this run
    not run / not on the runner  leave it alone: this run says nothing about it

The unit is the gate command, the thing that ran and reported. Several register
checks can share one command (the reconcile.* invariants); they pass or fail
together, so they share one issue, labelled with every owner they name. One
issue per check would open several identical issues for a single failure.

A run that failed while no gate failed (a build, apply or signing step) keeps a
single fallback issue for that workflow, closed by the next run that succeeds.

Issues carry the `gate-alert` label and an owner label per register role; the
workflow passes CONTEXT (deploy or nightly), so each workflow's gates keep their
own issues. Usage, from the repository root:

    gate-alerts.py CONTEXT RESULTS_FILE STAGE[,STAGE...] --run-failed true|false [--dry-run]

`--dry-run` prints the actions without calling GitHub. Otherwise it uses `gh`
with GH_TOKEN, in the repository GITHUB_REPOSITORY names.
"""

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _gates  # noqa: E402
from _common import fedramp_id  # noqa: E402

LABEL = "gate-alert"
CONTEXTS = ("deploy", "nightly")


def title_for(context, run):
    return f"[{context}] gate failing: {run}"


def fallback_title(context):
    return f"[{context}] run failed outside any gate"


def plan(register, context, stages, results_path, run_failed):
    """The actions this run implies: [{action, title, labels, checks}], where
    action is open (a failure) or close (a pass). Pure: no GitHub calls."""
    groups = {}
    for stage in stages:
        for r in _gates.stage_results(register, stage, results_path):
            run = register["checks"][r["check"]].get("run")
            if run is None:
                continue
            g = groups.setdefault(run, {"checks": {}, "result": r["result"]})
            g["checks"][r["check"]] = r["owner"]
    actions = []
    for run, g in groups.items():
        if g["result"] not in ("pass", "fail"):
            continue
        actions.append({
            "action": "open" if g["result"] == "fail" else "close",
            "title": title_for(context, run),
            "labels": [LABEL] + sorted(set(g["checks"].values())),
            "checks": sorted(g["checks"].items()),
        })
    gate_failed = any(a["action"] == "open" for a in actions)
    if run_failed and not gate_failed:
        actions.append({"action": "open", "title": fallback_title(context),
                        "labels": [LABEL, "role:platform-owner"], "checks": []})
    elif not run_failed:
        actions.append({"action": "close", "title": fallback_title(context), "labels": [LABEL], "checks": []})
    return actions


def _body(a, context):
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo, run_id = os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_RUN_ID", "")
    run_url = f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else "(local run)"
    sha = os.environ.get("GITHUB_SHA", "")
    fid = f"FedRAMP ID: {fedramp_id()}"  # CDS-CSO-FID: every notification names the offering
    if a["action"] == "close":
        return f"Passed in the {context} run {run_url} (commit {sha}). Closing.\n\n{fid}"
    lines = [f"Failed in the {context} run {run_url} (commit {sha}).", "", fid, ""]
    if a["checks"]:
        lines += ["| Check | Owner |", "|---|---|"] + [f"| `{c}` | `{o}` |" for c, o in a["checks"]]
        lines += ["", "The run log names the cause. Fix it, or record a decision for it; "
                      "the next run where this gate passes closes this issue."]
    else:
        lines += ["The run failed in a step that is not a registered gate (a build, apply or "
                  "signing step). The run log names it. The next successful run closes this issue."]
    return "\n".join(lines)


def _gh(*args):
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def apply(actions, context):
    found = json.loads(_gh("issue", "list", "--label", LABEL, "--state", "all", "--limit", "500",
                           "--json", "number,title,state"))
    for a in actions:
        # Prefer an open issue, then the oldest, so one gate never gets two.
        matches = sorted((i for i in found if i["title"] == a["title"]),
                         key=lambda i: (i["state"] != "OPEN", i["number"]))
        match = matches[0] if matches else None
        body = _body(a, context)
        if a["action"] == "close":
            if match and match["state"] == "OPEN":
                _gh("issue", "close", str(match["number"]), "--comment", body)
                print(f"closed #{match['number']}: {a['title']}")
            continue
        for label in a["labels"]:
            _gh("label", "create", label, "--force", "--color", "B60205" if label == LABEL else "C5DEF5")
        if match:
            if match["state"] != "OPEN":
                _gh("issue", "reopen", str(match["number"]))
            _gh("issue", "comment", str(match["number"]), "--body", body)
            print(f"updated #{match['number']}: {a['title']}")
        else:
            args = ["issue", "create", "--title", a["title"], "--body", body]
            for label in a["labels"]:
                args += ["--label", label]
            # Every role is held by one person here: assign the repository
            # owner, so the issue reaches a person and not only a label.
            if os.environ.get("GITHUB_REPOSITORY_OWNER"):
                args += ["--assignee", os.environ["GITHUB_REPOSITORY_OWNER"]]
            print(f"created: {a['title']} {_gh(*args).strip()}")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("context", choices=CONTEXTS)
    p.add_argument("results")
    p.add_argument("stages")
    p.add_argument("--run-failed", required=True, choices=("true", "false"))
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args(argv)
    stages = a.stages.split(",")
    for s in stages:
        if s not in _gates.STAGES:
            raise SystemExit(f"unknown stage {s!r}; one of {list(_gates.STAGES)}")
    actions = plan(_gates.load_gate_modes(), a.context, stages, a.results, a.run_failed == "true")
    if a.dry_run:
        for x in actions:
            print(f"{x['action']}: {x['title']} {x['labels']}")
        return 0
    apply(actions, a.context)
    return 0


if __name__ == "__main__":
    sys.exit(main())
