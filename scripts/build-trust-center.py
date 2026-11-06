#!/usr/bin/env python3
"""Build /.well-known/trust-center.json: the Authorizing Official's view of this system.

The trust center answers five questions, in order:
  1. Is this picture true?            -> picture
  2. What is waiting on a decision?   -> decisions_pending
  3. Where am I exposed?              -> the boundary map (/.well-known/boundary-map.json)
  4. How are decisions made here?     -> policy_catalog, escalation_rate
  5. What was decided, by whom, why?  -> decision_log

Every entry is derived from an artifact this build produced or a register in the
repository; nothing here is typed by hand. Where a register does not record a
field (who decided, when, when to review it), the entry says so and the gap is
counted. It is never filled in with a guess.

Runs in the deploy job after the reconciliation gate passes, so the artifacts it
summarizes are the ones about to be published. It fails closed if they are not
bound to one inventory (signal_id), and on any ARN, account ID or email address.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

SCHEMA = "trust-center/1"
REPO = Path(__file__).resolve().parent.parent

# Freshness windows, from the governed config (infrastructure/schemas/
# freshness-config.json) that the watchdog alarms and the published-evidence
# check also read, so the trust center reports against the thresholds that page
# the operator. Loaded at import and fail-closed: no config, no trust center.
# FRESHNESS_CONFIG names another file (tests); it is validated the same way.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _freshness import load_freshness_config  # noqa: E402
import _decisions  # noqa: E402
import _gates  # noqa: E402
import _offering  # noqa: E402
import _redact  # noqa: E402

FRESHNESS: dict[str, Any] = load_freshness_config(os.environ.get("FRESHNESS_CONFIG") or None)
VDR_MAX_AGE_HOURS = FRESHNESS["windows"][".well-known/vdr-report.json"]
RUNTIME_MAX_AGE_HOURS = FRESHNESS["windows"][".well-known/ksi-signal-runtime.json"]
# The independent corroboration (RAMPART on TAP) runs on the operator's machine;
# older than this, the map is no longer independently checked.
CORROBORATION_MAX_AGE_HOURS = FRESHNESS["windows"][".well-known/boundary-corroboration.json"]
CORROBORATION_MAX_AGE_DAYS = CORROBORATION_MAX_AGE_HOURS / 24
FRESHNESS_SOURCE = "infrastructure/schemas/freshness-config.json"
# An accepted exception this close to expiry is a renewal decision now, not later.
EXCEPTION_WARNING_DAYS = 30
# Days of escalation-rate history the artifact carries forward.
HISTORY_DAYS = 180

ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SCN_VERIFIED = re.compile(r"verification complete|implemented and verified", re.I)
DECISIONS_PATH = REPO / "data" / "decisions.json"

WHY_YOURS = {
    "vdr_blocking": "The vulnerability gate stops deploys on this finding. Fixing, dispositioning or accepting it is a person's call.",
    "vdr_undispositioned": "No recorded precedent covers this finding, so the pipeline cannot resolve it on its own.",
    "decision_overdue": "A recorded decision's planned completion date has passed. Extending it, accepting the risk or stopping is the Authorizing Official's decision.",
    "exception_expiring": "An accepted policy exception expires soon. Renewing it is a new decision, not a formality.",
    "runtime_diverged": "The running system no longer matches what was deployed and approved.",
    "runtime_unassessed": "The runtime emitter could not assess some KSIs, so they rest on deploy-time evidence alone. Whether that is enough is a judgment.",
    "runtime_stale": "The runtime signal is older than its freshness window, so the running system is not currently observed.",
    "trust_root_change": "A merged change to the IAM trust root is not applied. Applying the trust root is deliberately left to a person.",
    "boundary_unclassified": "Resources exist that no boundary rule places. Whether they are inside the boundary is a scoping decision.",
    "boundary_untagged": "Resources lack the classification tags that drive risk scoring.",
    "boundary_not_inventoried": "Something the system depends on is not in the canonical inventory.",
    "scn_unverified": "A significant change was approved but its post-implementation verification is not recorded as complete.",
    "manual_setting": "A setting applied by hand no longer matches what this system expects. Restoring it, or accepting the change, is a person's call.",
    "decision_review_due": "A recorded risk decision has reached its review date. Reaffirming, changing or ending it is the Authorizing Official's call.",
    "vulnerability_evidence_stale": "The published vulnerability evidence is older than its freshness window, so current exposure is not known. Whether to rely on the system meanwhile is a judgment.",
    "gate_detect_recover": "A gate check running in detect-and-recover mode failed, so the run continued without it. Whether to repair, accept or return the gate to block is a judgment.",
    "decision_records_incomplete": "Recorded decisions are missing who made them, when, or when to revisit them. Setting that governance is the Authorizing Official's call.",
}

# What the owner can do about each kind of queue item (REQ-QUE-1). Static, kept
# beside WHY_YOURS so a new kind cannot ship without its options; published in
# every item and in live_queue so the page can attach them to items it rebuilds.
OPTIONS = {
    "vdr_blocking": ["Remediate: upgrade or remove the affected package and redeploy",
                     "Record a disposition (false positive or not affected) with its justification",
                     "Accept the risk in a decision record with a review date"],
    "vdr_undispositioned": ["Remediate: upgrade or remove the affected package",
                            "Record a disposition (false positive or not affected) with its justification",
                            "Accept the risk in a decision record with a review date"],
    "decision_overdue": ["Close the record: complete the remediation and record it",
                     "Set a new completion date, with the reason for the delay",
                     "Accept the risk, recording who decided, when and the review date"],
    "exception_expiring": ["Renew the exception with a new expiry and justification",
                           "Fix the resource so the rule passes and remove the exception",
                           "Let it expire; the policy gate will then stop deploys on the resource"],
    "runtime_diverged": ["Restore the deployed configuration by redeploying",
                         "Change the code to match the running system, through review",
                         "Accept the divergence in a decision record with a review date"],
    "runtime_unassessed": ["Fix the runtime emitter so it can assess these KSIs",
                           "Accept deploy-time evidence for them, recording the decision"],
    "runtime_stale": ["Investigate and restore the runtime emitter",
                      "Accept the gap for a stated period, recording the decision"],
    "trust_root_change": ["Apply the merged trust-root change from a synced tree",
                          "Revert the merged change"],
    "boundary_unclassified": ["Classify the resource in docs/boundary/boundary-classification.json",
                              "Remove the resource"],
    "boundary_untagged": ["Add the classification tags in Terraform",
                          "Record why the resource carries no classification"],
    "boundary_not_inventoried": ["Add the resource or dependency to the canonical inventory",
                                 "Remove it, or record it as outside the boundary with the reason"],
    "scn_unverified": ["Complete the post-implementation verification and record it",
                       "Roll the change back"],
    "manual_setting": ["Restore the expected setting by hand",
                       "Accept the new setting and update what this system expects, through review"],
    "decision_review_due": ["Reaffirm the decision with a new review date",
                            "Change the decision",
                            "End it: remediate or close the underlying item"],
    "vulnerability_evidence_stale": ["Investigate and rerun the nightly vulnerability scan",
                                     "Accept reliance on the last published evidence for a stated period, recording the decision"],
    "gate_detect_recover": ["Repair the failed check so the next run passes it",
                            "Return the check to block mode in infrastructure/schemas/gate-modes.json",
                            "Renew the detect-and-recover decision with a reason and review date"],
    "decision_records_incomplete": ["Record who decided, when and the review date on each record",
                                    "Retire the decisions no one will own"],
}

# Where each kind's opening time ("since") comes from (REQ-QUE-1). It is the
# time the condition began, from a date the records carry or an artifact's own
# timestamp; never the time this build ran. Bases:
#   recorded       a date recorded on the item itself
#   derived        computed from a recorded date (an expiry less the warning window)
#   observed       the timestamp of the artifact that observed the condition
#   first_observed the same condition's opening time in the previous trust center,
#                  when earlier (observed kinds only)
# An observed kind whose artifact carries no timestamp falls back to the
# inventory's emitted_at; with neither, the build fails rather than guess.
SINCE_BASES = ("recorded", "derived", "observed", "first_observed")
SINCE_SOURCE = {
    "vdr_blocking": "The finding's first_detected; else the VDR's emitted_at (observed).",
    "vdr_undispositioned": "The finding's first_detected; else the VDR's emitted_at (observed).",
    "decision_overdue": "The decision record's planned completion date: the day it became overdue (recorded).",
    "exception_expiring": "The exception's expiry less the renewal warning window: the day it entered the window (derived).",
    "runtime_diverged": "The runtime signal's emitted_at (observed).",
    "runtime_unassessed": "The runtime signal's emitted_at (observed).",
    "runtime_stale": "The runtime signal's emitted_at plus its freshness window: the moment it went stale (derived).",
    "trust_root_change": "The trust-root plan's planned_at; else the boundary map's generated_at (observed).",
    "boundary_unclassified": "The boundary map's generated_at (observed).",
    "boundary_untagged": "The boundary map's generated_at (observed).",
    "boundary_not_inventoried": "The boundary map's generated_at, or the corroboration's checked_at for resources only TAP sees (observed).",
    "scn_unverified": "The change's date_initiated in the SCN register (recorded); else the inventory's emitted_at (observed).",
    "manual_setting": "The manual-settings check's checked_at (observed).",
    "decision_review_due": "The decision's review_by date (recorded).",
    "vulnerability_evidence_stale": "Raised only by the page's live re-check: the VDR's emitted_at.",
    "decision_records_incomplete": "The inventory's emitted_at (observed).",
    "gate_detect_recover": "When the run recorded the gate event (observed); the earliest such time is carried forward.",
}


# Settings a person applies by hand; scripts/check-manual-settings.py observes them.
MANUAL_SETTINGS = {
    "github_settings": "GitHub environments and branch protection",
    "dnssec": "DNSSEC chain of trust",
    "sns_subscription": "Evidence-alarm email subscription",
}


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _parse_date(value: Any) -> date | None:
    if isinstance(value, str) and ISO_DATE.match(value.strip()):
        return date.fromisoformat(value.strip())
    return None


def _age_hours(value: Any, now: datetime) -> float | None:
    t = _parse_time(value)
    return None if t is None else round((now - t).total_seconds() / 3600, 1)


def _props(item: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in item.get("props", []) if "name" in p}


def _published_scope(applies_to: dict[str, Any] | None) -> dict[str, Any]:
    """A decision's scope as published: IAM user names withheld."""
    scope = dict(applies_to or {})
    if "resources" in scope:
        scope["resources"] = _redact.withhold_iam_users(scope["resources"])
    return scope


def register_items(decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The decision register's records (data/decisions.json), flattened for the
    queue, the precedent count and the decision log. In force reads as open."""
    out = []
    for r in decisions:
        out.append({
            "id": r.get("id"), "former_id": r.get("former_id"), "title": r.get("title", ""),
            "description": r.get("justification", ""),
            "status": "open" if r.get("status") == "in-force" else "closed", "disposition": r.get("disposition"),
            "scheduled_completion": r.get("planned_completion"),
            "applies_to": _published_scope(r.get("applies_to")),
            "decided_by": r.get("decided_by"), "decided_on": r.get("decided_on"), "review_by": r.get("review_by"),
        })
    return out


def read_scn_register(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def read_checkov_skips(path: Path) -> list[str]:
    """The check ids under skip-check in .checkov.yaml (no YAML dependency in the deploy job)."""
    skips: list[str] = []
    in_block = False
    for line in path.read_text().splitlines():
        if re.match(r"^skip-check:\s*$", line):
            in_block = True
        elif in_block and re.match(r"^\S", line):
            in_block = False
        elif in_block and (m := re.match(r"^\s*-\s*(CKV\w+)", line)):
            skips.append(m.group(1))
    return skips


def _brief(text: str, limit: int = 400) -> str:
    text = " ".join(str(text or "").split())
    if len(text) <= limit:
        return text
    # Cut at a word boundary, never mid-word.
    cut = text[: limit - 1].rsplit(" ", 1)[0].rstrip(",;:—-(")
    return cut + "…"


# ---------------------------------------------------------------------------
# 1. Is this picture true?
# ---------------------------------------------------------------------------

def corroboration_verdict(report: dict[str, Any] | None, now: datetime) -> tuple[str, str]:
    """(status, detail) for the independent corroboration of the boundary map."""
    if not report:
        return "not_observed", "No independent corroboration has been run."
    s = report.get("summary", {})
    age = _age_hours(report.get("checked_at"), now)
    days = None if age is None else round(age / 24, 1)
    parts = [f"{s.get('agree', 0)} of {s.get('in_scope', 0)} components agree"]
    if s.get("tap_only"):
        parts.append(f"{s['tap_only']} resource(s) only TAP sees")
    if s.get("map_only"):
        parts.append(f"{s['map_only']} on the map that TAP did not observe")
    if s.get("tag_differences"):
        parts.append(f"{s['tag_differences']} tag difference(s)")
    if s.get("relationships_tap_only"):
        parts.append(f"{s['relationships_tap_only']} relationship(s) the map does not draw")
    if s.get("relationships_compared") == 0:
        parts.append("no relationship was compared")
    stale = days is None or days > CORROBORATION_MAX_AGE_DAYS
    when = "" if days is None else ("today" if days < 1 else f"{days:g} days ago")
    detail = "; ".join(parts) + (f"; checked {when} (window {CORROBORATION_MAX_AGE_DAYS:g} days)." if when else ".")
    differs = (any(s.get(k) for k in ("tap_only", "map_only", "tag_differences", "relationships_tap_only"))
               or s.get("relationships_compared") == 0)
    # rampart-corroboration/2: one line per section. Anything short of agreement,
    # including a section that could not be checked, needs attention.
    sections = report.get("checks") or {}
    if sections:
        lines = [f"{name.replace('_', ' ')}: {sec.get('status', 'missing').replace('_', ' ')}"
                 + (f" ({len(sec.get('findings') or [])} difference(s))" if sec.get("status") == "differs" else "")
                 for name, sec in sections.items()]
        detail += " Sections: " + "; ".join(lines) + "."
        differs = differs or any(sec.get("status") != "agrees" for sec in sections.values())
    return ("attention" if stale or differs else "ok"), detail


def add_corroboration(add: Any, report: dict[str, Any] | None, now: datetime) -> None:
    status, detail = corroboration_verdict(report, now)
    add("corroboration", "Independent corroboration (RAMPART on TAP)", status, detail,
        (report or {}).get("checked_at"), "/.well-known/boundary-corroboration.json" if report else None)


def build_picture(inp: dict[str, Any], now: datetime) -> list[dict[str, Any]]:
    signal, report, bmap = inp["signal"], inp["reconcile"], inp["boundary_map"]
    picture: list[dict[str, Any]] = []

    def add(id_: str, label: str, status: str, detail: str, as_of: Any = None, source: str | None = None) -> None:
        picture.append({"id": id_, "label": label, "status": status, "detail": detail, "as_of": as_of, "source": source})

    add("inventory", "Canonical inventory", "ok",
        f"{len(signal.get('components', []))} components, built from this deploy's Terraform state and SBOMs.",
        signal.get("emitted_at"), "/.well-known/ksi-signal.json")

    deferred = [i["id"] for i in report.get("invariants", []) if i.get("status") != "held"]
    held = len(report.get("invariants", [])) - len(deferred)
    add("reconciliation", "Cross-artifact reconciliation",
        "ok" if report.get("result") == "pass" and not deferred else "attention",
        f"{held} of {len(report.get('invariants', []))} invariants held"
        + (f"; deferred: {', '.join(deferred)}" if deferred else "") + ". Nothing publishes unless this passes.",
        report.get("generated_at"), "/.well-known/reconcile-report.json")

    health = bmap.get("health", {})
    problems = {k: v for k, v in health.items() if v and k != "pending_trust_root_changes"}
    add("boundary", "Authorization boundary map",
        "attention" if problems else "ok",
        "Every inventoried resource is placed and tagged." if not problems
        else "; ".join(f"{v} {k.replace('_', ' ')}" for k, v in sorted(problems.items())) + ".",
        bmap.get("generated_at"), "/.well-known/boundary-map.json")
    plan: dict[str, Any] = inp.get("trust_root_plan") or {}
    status = plan.get("status")
    status = (plan or {}).get("status")
    if status == "in_sync":
        add("trust_root", "IAM trust root (operator-applied)", "ok", "The applied trust root matches its merged definition.", plan.get("planned_at"))
    elif status == "changes_pending":
        add("trust_root", "IAM trust root (operator-applied)", "attention",
            f"{len(plan.get('changes', []))} merged change(s) not yet applied.", plan.get("planned_at"))
    elif status == "superseded":
        # The operator applied the trust root after this build planned it (the
        # state version moved while the run waited at the approval gate). What
        # the plan said is no longer true, and what is true is unknown until the
        # next build re-plans: not observed, not "needs attention".
        add("trust_root", "IAM trust root (operator-applied)", "not_observed",
            "Applied after this build planned it; the next deploy re-checks it.", plan.get("planned_at"))
    else:
        add("trust_root", "IAM trust root (operator-applied)", "not_observed",
            "This build could not plan the trust root" + (f" ({status})." if status else "."), plan.get("planned_at"))

    runtime = inp.get("runtime")
    if runtime is None:
        add("runtime", "Runtime evidence (daily emitter)", "not_observed", "The runtime signal could not be read at build time.")
    else:
        div = runtime.get("divergence") or {}
        age = _age_hours(runtime.get("emitted_at"), now)
        stale = age is None or age > RUNTIME_MAX_AGE_HOURS
        detail = f"{div.get('status', 'unknown')}: {div.get('ksis_compared', 0)} KSIs compared, {len(div.get('regressions', []))} regressed, {len(div.get('unassessed', []))} not assessed"
        detail += f"; {age} h old (window {RUNTIME_MAX_AGE_HOURS:g} h)." if age is not None else "."
        add("runtime", "Runtime evidence (daily emitter)",
            "ok" if div.get("status") == "converged" and not stale else "attention",
            detail, runtime.get("emitted_at"), "/.well-known/ksi-signal-runtime.json")

    nightly = inp.get("vdr_status")
    if nightly is None:
        add("vulnerability_scan", "Nightly vulnerability evidence", "not_observed", "The nightly status beacon could not be read at build time.")
    else:
        age = _age_hours(nightly.get("finished_at"), now)
        fresh = age is not None and age <= VDR_MAX_AGE_HOURS
        add("vulnerability_scan", "Nightly vulnerability evidence",
            "ok" if nightly.get("result") == "success" and fresh else "attention",
            f"Last nightly run: {nightly.get('result', 'unknown')}"
            + (f", {age} h ago (window {VDR_MAX_AGE_HOURS:g} h)." if age is not None else "."),
            nightly.get("finished_at"), "/.well-known/vdr-status.json")

    add_corroboration(add, inp.get("corroboration"), now)

    # REQ-GOV-2: the method profile this build conforms to, and how much of its
    # conformance suite is implemented and passing. Read from the VDR it built.
    prof = ((inp["vdr"].get("methodology") or {}).get("profile")) or None
    if not prof or not isinstance(prof.get("summary"), dict):
        add("conformance", "Method conformance", "not_observed",
            "The VDR names no conformance results.")
    else:
        sm = prof["summary"]
        whole = sm.get("failed", 0) == 0 and sm.get("partial", 0) == 0 and sm.get("not-implemented", 0) == 0
        add("conformance", "Method conformance", "ok" if whole else "attention",
            f"Profile {prof.get('profile_version')}: {sm.get('implemented', 0)} conformance tests implemented, "
            f"{sm.get('partial', 0)} partly, {sm.get('not-implemented', 0)} not yet, "
            f"{sm.get('not-applicable', 0)} not applicable; {sm.get('failed', 0)} failing.",
            prof.get("conformance_generated_at"), "/.well-known/conformance-results.json")

    manual = inp.get("manual_settings") or {}
    observed = {c.get("id"): c for c in manual.get("checks", [])}
    for id_, label in MANUAL_SETTINGS.items():
        c = observed.get(id_)
        if c is None:
            add(id_, label, "not_observed", "Configured by hand; this build could not check it.")
        else:
            add(id_, label, c.get("status", "not_observed"), c.get("detail", ""), manual.get("checked_at"),
                "scripts/check-manual-settings.py")
    return picture


# ---------------------------------------------------------------------------
# 2. What is waiting on a decision?
# ---------------------------------------------------------------------------

def _decision(kind: str, id_: str, title: str, *, since: Any = None, basis: str = "observed", due: Any = None,
              refs: list[str] | None = None) -> dict[str, Any]:
    return {"kind": kind, "id": id_, "title": title, "why_yours": WHY_YOURS[kind], "options": list(OPTIONS[kind]),
            "since": since or None, "since_basis": basis if since else None, "due": due, "refs": refs or []}


def _previous_since(previous: Any, now: datetime) -> dict[tuple[str, str], tuple[datetime, str]]:
    """Opening times of observed items in the previous trust center (read back
    from the live site: only well-formed, past timestamps are kept)."""
    out: dict[tuple[str, str], tuple[datetime, str]] = {}
    items = previous.get("decisions_pending") if isinstance(previous, dict) else None
    for d in items if isinstance(items, list) else []:
        if not isinstance(d, dict) or not isinstance(d.get("kind"), str) or not isinstance(d.get("id"), str):
            continue
        t = _parse_time(d.get("since"))
        if t is not None and t <= now:
            # Re-serialized from the parsed time: nothing from the live site is echoed verbatim.
            out[(d["kind"], d["id"])] = (t, t.isoformat(timespec="seconds"))
    return out


def _settle_since(items: list[dict[str, Any]], inp: dict[str, Any], now: datetime) -> None:
    """Give every item its opening time: an observed item without one takes the
    inventory's emitted_at, and keeps an earlier opening time from the previous
    trust center. Fails closed on an item whose opening time is unknown."""
    fallback = inp["signal"].get("emitted_at") if _parse_time(inp["signal"].get("emitted_at")) else None
    previous = _previous_since(inp.get("previous"), now)
    for d in items:
        if not d["since"] and fallback:
            d["since"], d["since_basis"] = fallback, "observed"
        if d["since_basis"] == "observed":
            prior = previous.get((d["kind"], d["id"]))
            current = _parse_time(d["since"])
            if prior and current and prior[0] < current:
                d["since"], d["since_basis"] = prior[1], "first_observed"
        if not d["since"]:
            sys.exit(f"build-trust-center: queue item {d['kind']}:{d['id']} has no known opening time; "
                     "refusing to publish it stamped with the build time")


def build_decisions_pending(inp: dict[str, Any], now: datetime, log: list[dict[str, Any]],
                            log_gaps: dict[str, int]) -> list[dict[str, Any]]:
    out = _queue_items(inp, now, log, log_gaps)
    _settle_since(out, inp, now)
    return out


def gate_events(inp: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Detect-and-recover gate events published by this build's VDR (deploy)
    and the nightly status beacon, one per check, earliest first."""
    events: dict[str, dict[str, Any]] = {}
    sources = [((inp.get("vdr") or {}).get("methodology") or {}).get("gate_events"),
               (inp.get("vdr_status") or {}).get("gate_events")]
    for src in sources:
        for e in src if isinstance(src, list) else []:
            # Read back from published JSON: only checks the register knows, with a real time.
            if (not isinstance(e, dict) or e.get("check") not in _gates.CHECKS
                    or not _parse_time(e.get("at"))):
                continue
            prior = events.get(e["check"])
            if prior is None or _parse_time(e["at"]) < _parse_time(prior["at"]):  # type: ignore[operator]
                events[e["check"]] = e
    return events


def _queue_items(inp: dict[str, Any], now: datetime, log: list[dict[str, Any]],
                 log_gaps: dict[str, int]) -> list[dict[str, Any]]:
    today = now.date()
    out: list[dict[str, Any]] = []
    bmap = inp["boundary_map"]

    for check, e in sorted(gate_events(inp).items()):
        out.append(_decision("gate_detect_recover", check,
                             f"{e.get('gate', '?')} {check} failed and ran in detect-and-recover: "
                             f"{_brief(str(e.get('detail', '')), 160)}",
                             since=e["at"], refs=["infrastructure/schemas/gate-modes.json"]))

    for f in inp["vdr"].get("findings", []):
        if f.get("is_blocking"):
            kind = "vdr_blocking"
        elif (f.get("final_disposition") or "open") == "open":
            kind = "vdr_undispositioned"
        else:
            continue
        first = f.get("first_detected")
        out.append(_decision(kind, f.get("tracking_id", ""), f.get("title", ""),
                             since=first or inp["vdr"].get("emitted_at"), basis="recorded" if first else "observed",
                             due=f.get("remediation_due_at"),
                             refs=[r for r in ("/.well-known/vdr-report.json", f.get("component_id")) if r]))

    for p in register_items(inp["decisions"]):
        due = _parse_date(p["scheduled_completion"])
        if p["status"] == "open" and due and due < today:
            out.append(_decision("decision_overdue", p["id"], p["title"], since=due.isoformat(), basis="recorded",
                                 due=due.isoformat(), refs=["data/decisions.json"]))

    for e in inp["exceptions"]:
        exp = _parse_date(e.get("expiry"))
        if exp and (exp - today).days <= EXCEPTION_WARNING_DAYS:
            out.append(_decision("exception_expiring", f"{e.get('rule_id')}:{e.get('resource')}",
                                 f"Policy exception {e.get('rule_id')} on {e.get('resource')}",
                                 since=(exp - timedelta(days=EXCEPTION_WARNING_DAYS)).isoformat(), basis="derived",
                                 due=exp.isoformat(),
                                 refs=[str(e.get("ticket", ""))]))

    runtime = inp.get("runtime")
    if runtime is not None:
        div = runtime.get("divergence") or {}
        for r in div.get("regressions", []):
            out.append(_decision("runtime_diverged", r.get("ksi_id", ""), f"{r.get('ksi_id')} passed at deploy but fails at runtime",
                                 since=runtime.get("emitted_at"), refs=["/.well-known/ksi-signal-runtime.json"]))
        unassessed = [u.get("ksi_id", "") for u in div.get("unassessed", [])]
        if unassessed:
            out.append(_decision("runtime_unassessed", "runtime-unassessed",
                                 f"{len(unassessed)} KSI(s) not assessed at runtime: {', '.join(unassessed)}",
                                 since=runtime.get("emitted_at"), refs=["/.well-known/ksi-signal-runtime.json"]))
        age = _age_hours(runtime.get("emitted_at"), now)
        if age is None or age > RUNTIME_MAX_AGE_HOURS:
            emitted = _parse_time(runtime.get("emitted_at"))
            stale_at = (emitted + timedelta(hours=RUNTIME_MAX_AGE_HOURS)).isoformat(timespec="seconds") if emitted else None
            out.append(_decision("runtime_stale", "runtime-stale", "The runtime signal is past its freshness window",
                                 since=stale_at, basis="derived"))

    planned_at = (inp.get("trust_root_plan") or {}).get("planned_at") or bmap.get("generated_at")
    for c in bmap.get("trust_root_changes", []):
        out.append(_decision("trust_root_change", c["address"],
                             f"{'/'.join(c.get('actions', []))} {c['address']}", since=planned_at,
                             refs=[r for r in ("/.well-known/boundary-map.json", c.get("component")) if r]))

    mapped_at = bmap.get("generated_at")
    for cid in bmap.get("unclassified", []):
        out.append(_decision("boundary_unclassified", cid, f"{cid} is not placed in the boundary", since=mapped_at, refs=[cid]))
    for n in bmap.get("nodes", []):
        if "untagged" in n.get("flags", []) or "classification tags incomplete" in n.get("flags", []):
            out.append(_decision("boundary_untagged", n["id"], f"{n.get('name', n['id'])} lacks classification tags",
                                 since=mapped_at, refs=[n["id"]]))
        if n.get("kind") == "not_inventoried":
            out.append(_decision("boundary_not_inventoried", n["id"], f"{n.get('name', n['id'])} is used but not inventoried",
                                 since=mapped_at, refs=[n["id"]]))

    for r in (inp.get("corroboration") or {}).get("tap_only", []):
        out.append(_decision("boundary_not_inventoried", f"tap:{r.get('type')}:{r.get('name')}",
                             f"{r.get('name')} ({r.get('type')}) exists in the account but is not in the inventory",
                             since=(inp.get("corroboration") or {}).get("checked_at"),
                             refs=["/.well-known/boundary-corroboration.json"]))

    for c in (inp.get("manual_settings") or {}).get("checks", []):
        if c.get("status") == "attention" and c.get("id") in MANUAL_SETTINGS:
            out.append(_decision("manual_setting", c["id"], f"{MANUAL_SETTINGS[c['id']]}: {c.get('detail', '')}",
                                 since=(inp.get("manual_settings") or {}).get("checked_at")))

    for row in inp["scn_register"]:
        if not SCN_VERIFIED.search(row.get("status", "")):
            initiated = (row.get("date_initiated") or "").strip()
            out.append(_decision("scn_unverified", row.get("scn_id", ""), _brief(row.get("short_description", ""), 160),
                                 since=initiated if _parse_date(initiated) else None, basis="recorded", refs=["docs/scn/"]))

    for e in log:
        review = _parse_date(e.get("review_by"))
        # A policy exception's review date is its expiry, queued above.
        if review and review <= today and e["kind"] != "policy_exception":
            out.append(_decision("decision_review_due", e["id"], f"Review due: {e['subject']}",
                                 since=review.isoformat(), basis="recorded", due=review.isoformat(),
                                 refs=[e["source"]]))

    if any(log_gaps.values()):
        parts = [f"{v} lack {k.replace('_', ' ')}" for k, v in sorted(log_gaps.items()) if v]
        out.append(_decision("decision_records_incomplete", "decision-record-gaps",
                             "Decision records: " + "; ".join(parts)))
    return out


# ---------------------------------------------------------------------------
# 4. How are decisions made here?
# ---------------------------------------------------------------------------

def build_policy_catalog(inp: dict[str, Any]) -> dict[str, Any]:
    rules = sorted(inp["rules"], key=lambda r: (r.get("path", ""), r.get("custom", {}).get("id", "")))
    config = inp["policy_config"].get("gate", {})
    in_force = [p for p in register_items(inp["decisions"]) if p["status"] == "open"]
    return {
        "immutable": {
            "about": "OPA rules the deploy cannot pass while they are violated. A person can change a rule only by changing the code, in review.",
            "rules": [{"id": r.get("custom", {}).get("id"), "title": r.get("title"), "severity": r.get("custom", {}).get("severity"),
                       "package": r.get("path", "").rsplit(".", 1)[0], "ksi_ids": r.get("custom", {}).get("ksi_ids", [])}
                      for r in rules],
        },
        "thresholds": {
            "about": "Numbers the automation acts on. Each is set in code and changes only in review.",
            "items": [
                {"name": "Remediation SLA (FedRAMP Class C)", "value": "2 to 192 days by PAIN, internet reachability and exploitability; none for N1", "source": "FedRAMP machine-readable rules (VDR-TFR-PVR), pinned in infrastructure/schemas/fedramp-rules/"},
                {"name": "Vulnerability evidence freshness", "value": f"{VDR_MAX_AGE_HOURS:g} hours", "source": FRESHNESS_SOURCE},
                {"name": "Runtime evidence freshness", "value": f"{RUNTIME_MAX_AGE_HOURS:g} hours", "source": FRESHNESS_SOURCE},
                {"name": "Runtime divergence pre-flight staleness", "value": "48 hours", "source": "scripts/check-runtime-divergence.py"},
                {"name": "Independent corroboration freshness", "value": f"{CORROBORATION_MAX_AGE_DAYS:g} days", "source": FRESHNESS_SOURCE},
                {"name": "Published evidence freshness (every /.well-known/ output)",
                 "value": f"{len(FRESHNESS['windows'])} artifacts, {min(FRESHNESS['windows'].values()):g} to {max(FRESHNESS['windows'].values()):g} hours",
                 "source": FRESHNESS_SOURCE},
                {"name": "Exception renewal warning", "value": f"{EXCEPTION_WARNING_DAYS} days before expiry", "source": "scripts/build-trust-center.py"},
                {"name": "Minimum TLS policy", "value": str(config.get("tls", {}).get("minimum")), "source": "infrastructure/policy/config/data.json"},
                {"name": "Required resource tags", "value": ", ".join(config.get("required_tags", [])), "source": "infrastructure/policy/config/data.json"},
            ],
        },
        "precedent": {
            "about": "Recorded human decisions the automation applies again without asking: the same finding, the same answer.",
            "registers": [
                {"name": "Decision register (in force)", "entries": len(in_force), "source": "data/decisions.json"},
                {"name": "Policy exceptions", "entries": len(inp["exceptions"]), "source": "infrastructure/policy/exceptions/data.json"},
                {"name": "Checkov suppressions", "entries": len(inp["checkov_skips"]), "source": ".checkov.yaml"},
            ],
        },
        "escalation": {
            "about": "Points where the automation stops and waits for a person.",
            "gates": [
                {"name": "Production deploy approval", "stops": "every deploy", "decided_by": "a required reviewer on the prod GitHub environment"},
                {"name": "Vulnerability gate", "stops": "a deploy with an unhandled finding", "decided_by": "the operator, by fixing it or recording a disposition"},
                {"name": "Reconciliation gate", "stops": "publishing when artifacts disagree", "decided_by": "the operator, by fixing the disagreement"},
                {"name": "Runtime divergence pre-flight", "stops": "a deploy while the running system has regressed", "decided_by": "the operator; break-glass requires a recorded reason"},
                {"name": "IAM trust root", "stops": "nothing; CI reports pending changes", "decided_by": "the operator, who applies it by hand"},
            ],
        },
    }


# ---------------------------------------------------------------------------
# 5. What was decided, by whom, and why?
# ---------------------------------------------------------------------------

def build_decision_log(inp: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    log: list[dict[str, Any]] = []

    def add(kind: str, id_: str, subject: str, decision: str, *, decided_by: Any, decided_on: Any,
            reasoning: str, review_by: Any, source: str, review_applies: bool = True, **extra: Any) -> None:
        entry = {"kind": kind, "id": id_, "subject": subject, "decision": decision, "decided_by": decided_by or None,
                 "decided_on": decided_on or None, "reasoning": _brief(reasoning), "review_by": review_by or None,
                 "source": source, **extra}
        entry["gaps"] = [f for f in ("decided_by", "decided_on") if not entry[f]] + \
            (["review_by"] if review_applies and not entry["review_by"] else [])
        log.append(entry)

    for e in inp["exceptions"]:
        add("policy_exception", f"{e.get('rule_id')}:{e.get('resource')}", f"{e.get('rule_id')} on {e.get('resource')}",
            "excepted", decided_by=e.get("decided_by"), decided_on=e.get("decided_on"), reasoning=e.get("justification", ""),
            review_by=e.get("expiry"), source="infrastructure/policy/exceptions/data.json", ticket=e.get("ticket"))
    for p in register_items(inp["decisions"]):
        if p["status"] != "open":
            continue
        # Who decided, when, and the review date come from the record itself; a
        # record without them is reported as a gap.
        applies = p["applies_to"]
        add("decision", p["id"], p["title"], p["disposition"], decided_by=p["decided_by"],
            decided_on=p["decided_on"], reasoning=p["description"], review_by=p["review_by"],
            source="data/decisions.json", former_id=p["former_id"],
            applies_to=sorted(applies.get("check_ids", []) + applies.get("vuln_ids", [])))
    for row in inp["scn_register"]:
        m = SCN_VERIFIED.search(row.get("status", ""))
        add("significant_change", row.get("scn_id", ""), _brief(row.get("short_description", ""), 160),
            f"approved ({row.get('scn_type', '')})", decided_by=row.get("approver_name"), decided_on=row.get("date_initiated"),
            reasoning=row.get("categorization_rationale", ""), review_by=None, review_applies=False,
            source="docs/scn/scn-register.csv", verified=bool(m))

    gaps = {f: sum(1 for e in log if f in e["gaps"]) for f in ("decided_by", "decided_on", "review_by")}
    return log, gaps


# Queue kinds that arise when recorded precedent does not settle something the
# build encountered. Other kinds (a pending trust-root change, a drifted
# setting, an unclassified resource) are always a person's call and are not
# part of the rate.
PRECEDENT_KINDS = {"vdr_blocking", "vdr_undispositioned", "exception_expiring", "decision_overdue", "decision_review_due"}


def build_escalation_rate(inp: dict[str, Any], pending: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    """Settled vs escalated over one population: the vulnerability findings and
    policy exceptions this build encountered, plus the recorded decisions that
    settle them. Settled = covered by a current recorded decision; escalated =
    the queue items raised because precedent did not settle something."""
    escalated = sum(1 for d in pending if d["kind"] in PRECEDENT_KINDS)
    findings = inp["vdr"].get("findings", [])
    settled_findings = sum(1 for f in findings
                           if not f.get("is_blocking") and (f.get("final_disposition") or "open") != "open")
    queued_exceptions = {d["id"] for d in pending if d["kind"] == "exception_expiring"}
    settled_exceptions = sum(1 for e in inp["exceptions"]
                             if f"{e.get('rule_id')}:{e.get('resource')}" not in queued_exceptions)
    auto = settled_findings + settled_exceptions
    today = now.date().isoformat()
    previous = (inp.get("previous") or {}).get("escalation_rate", {}).get("history", [])
    # The previous trust center is read back from the live site: carry forward
    # only well-formed entries, and only their three fields.
    history = [{"date": h["date"], "resolved_by_precedent": h["resolved_by_precedent"], "escalated": h["escalated"]}
               for h in previous if isinstance(h, dict) and isinstance(h.get("date"), str) and ISO_DATE.match(h["date"])
               and h["date"] != today and isinstance(h.get("resolved_by_precedent"), int) and isinstance(h.get("escalated"), int)]
    history.append({"date": today, "resolved_by_precedent": auto, "escalated": escalated})
    return {
        "about": "Of the vulnerability findings and policy exceptions this build encountered, how many a current recorded decision settled, and how many came to a person because no decision covered them or the one that did had lapsed.",
        "resolved_by_precedent": auto, "escalated": escalated, "denominator": auto + escalated,
        "rate": round(escalated / (auto + escalated), 3) if auto + escalated else 0.0,
        "kinds": sorted(PRECEDENT_KINDS),
        "by_kind": escalation_by_kind(inp, pending),
        "not_measured": {"vulnerability_evidence_stale": "Raised only by the page's live re-check of the published VDR, never by the build."},
        "history": sorted(history, key=lambda h: h["date"])[-HISTORY_DAYS:],
    }


def escalation_by_kind(inp: dict[str, Any], pending: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """REQ-QUE-1: for each kind of queue item the build raises, how many were
    raised (escalated) out of the population that kind is drawn from (the
    denominator). Kinds outside PRECEDENT_KINDS go to a person by design; their
    rate says how much of their population needs one now."""
    findings = inp["vdr"].get("findings", [])
    open_decisions = [p for p in register_items(inp["decisions"]) if p["status"] == "open"]
    log, _ = build_decision_log(inp)
    reviewable = [e for e in log if e["kind"] == "decision"]
    runtime = inp.get("runtime")
    div = (runtime or {}).get("divergence") or {}
    bmap = inp["boundary_map"]
    nodes = bmap.get("nodes", [])
    tap_only = (inp.get("corroboration") or {}).get("tap_only", [])
    components = {str(c.get("id", i)) for i, c in enumerate(inp["signal"].get("components", []))}
    count: dict[str, int] = {}
    for d in pending:
        count[d["kind"]] = count.get(d["kind"], 0) + 1
    populations: dict[str, tuple[int, str]] = {
        "vdr_blocking": (len(findings), "vulnerability findings in this build's VDR"),
        "vdr_undispositioned": (len(findings), "vulnerability findings in this build's VDR"),
        "decision_overdue": (len(open_decisions), "in-force decision records"),
        "exception_expiring": (len(inp["exceptions"]), "recorded policy exceptions"),
        "decision_review_due": (len(reviewable), "in-force decision records"),
        "runtime_diverged": (max(int(div.get("ksis_compared") or 0), len(div.get("regressions", []))),
                             "KSIs compared between deploy and runtime"),
        "runtime_unassessed": (1 if runtime is not None else 0, "runtime signals read by this build"),
        "runtime_stale": (1 if runtime is not None else 0, "runtime signals read by this build"),
        "trust_root_change": (len(bmap.get("trust_root_changes", [])), "merged trust-root changes not yet applied"),
        "boundary_unclassified": (len(components | {str(c) for c in bmap.get("unclassified", [])}),
                                  "inventoried components and unplaced resources"),
        "boundary_untagged": (len(nodes), "nodes on the boundary map"),
        "boundary_not_inventoried": (len(nodes) + len(tap_only), "nodes on the boundary map and resources only TAP sees"),
        "scn_unverified": (len(inp["scn_register"]), "significant changes in the SCN register"),
        "manual_setting": (len(MANUAL_SETTINGS), "hand-applied settings this system expects"),
        "decision_records_incomplete": (1, "the decision log"),
        "gate_detect_recover": (len({c.get("check") for c in (((inp["vdr"].get("methodology") or {}).get("gates") or {})
                                                            .get("checks") or []) if isinstance(c, dict)}
                                    | set(gate_events(inp))),
                                "gate checks in the published gate-mode register"),
    }
    out: dict[str, dict[str, Any]] = {}
    for kind, (den, population) in populations.items():
        n = count.get(kind, 0)
        if n > den:
            sys.exit(f"build-trust-center: {n} {kind} item(s) out of a population of {den}; the denominator is wrong")
        out[kind] = {"escalated": n, "denominator": den, "rate": round(n / den, 3) if den else None,
                     "population": population, "precedent": kind in PRECEDENT_KINDS}
    return out


def framework_figures(irs: list[dict[str, Any]]) -> dict[str, str]:
    """The Rev5 Moderate view of the control projection (scripts/_controls.py):
    baseline coverage, measured rather than assumed (the projection's controls
    inside the FedRAMP Moderate baseline over the baseline's size, so a baseline
    control missing from the projection lowers it), and the projection's
    responsibility split. The SDR publishes the same projection per control."""
    import _common
    import _controls
    baseline = set(_controls.BASELINE_CONTROLS)
    control_ids = {ir["control-id"] for ir in irs}
    stack: dict[str, int] = {}
    for ir in irs:
        cls = _common.classify(_common.prop(ir, "implementation-status"), _common.prop(ir, "control-origination"))
        stack[cls] = stack.get(cls, 0) + 1
    return {
        "moderate_coverage": f"{len(control_ids & baseline)}/{len(baseline)}",
        "moderate_baseline": str(len(baseline)),
        "moderate_beyond": str(len(control_ids - baseline)),
        "moderate_implemented": str(stack.get("implemented", 0)),
        "moderate_inherited": str(stack.get("fully-inherited", 0) + stack.get("partially-inherited", 0)),
        "moderate_na": str(stack.get("not-applicable", 0)),
    }


def build_posture(inp: dict[str, Any]) -> dict[str, Any]:
    ksis = inp["signal"].get("ksis", [])
    by_status: dict[str, int] = {}
    for k in ksis:
        by_status[k.get("status", "unknown")] = by_status.get(k.get("status", "unknown"), 0) + 1
    return {"ksis": {"total": len(ksis), "by_status": dict(sorted(by_status.items()))},
            "frameworks": inp.get("figures") or {}}


def build(inp: dict[str, Any], commit: str, now: datetime) -> dict[str, Any]:
    signal_id = inp["signal"].get("signal_id")
    for name in ("reconcile", "boundary_map"):
        bound = inp[name].get("ksi_signal_id")
        if bound != signal_id:
            sys.exit(f"build-trust-center: {name} is bound to signal {bound!r}, not this build's {signal_id!r}")
    log, gaps = build_decision_log(inp)
    pending = build_decisions_pending(inp, now, log, gaps)
    return {
        "schema": SCHEMA,
        "fedRampId": _offering.fedramp_id(),
        "generated_at": now.isoformat(timespec="seconds"),
        "commit": commit,
        "ksi_signal_id": signal_id,
        "system": {"id": inp["signal"].get("system_id"), "impact_level": (inp["signal"].get("categorization") or {}).get("impact_level")},
        # The program sought and that it is not held (scripts/_offering.py; the CPO and SDR carry the same).
        "certification": _offering.certification(),
        "picture": build_picture(inp, now),
        # REQ-GOV-2: the profile and conformance results this build conforms to.
        "profile": (inp["vdr"].get("methodology") or {}).get("profile"),
        # The page re-checks the two evidence streams that change between
        # deploys (runtime signal, nightly beacon) live, against these windows.
        "freshness_windows_hours": {"runtime": RUNTIME_MAX_AGE_HOURS, "vulnerability_scan": VDR_MAX_AGE_HOURS,
                                    "corroboration": CORROBORATION_MAX_AGE_HOURS},
        # Which governed windows this build used (REQ-GOV-1: outputs record the
        # version of the configuration they were built under).
        "freshness_config": {"version": FRESHNESS["version"], "sha256": FRESHNESS["sha256"], "source": FRESHNESS_SOURCE,
                             "decided_by": FRESHNESS["decided_by"], "decided_on": FRESHNESS["decided_on"],
                             "review_by": FRESHNESS["review_by"], "windows_hours": FRESHNESS["windows"]},
        "decisions_pending": pending,
        # What the page needs to rebuild the date-driven part of the queue live,
        # so an empty queue is true on the day it is read, not only the day it
        # was deployed. The reasons travel with the data (one source of truth).
        "live_queue": {
            "why_yours": WHY_YOURS,
            "options": OPTIONS,
            "since_source": SINCE_SOURCE,
            "exception_warning_days": EXCEPTION_WARNING_DAYS,
            "decision_due": [{"id": p["id"], "title": p["title"], "due": d.isoformat()}
                         for p in register_items(inp["decisions"])
                         if p["status"] == "open" and (d := _parse_date(p["scheduled_completion"]))],
        },
        "policy_catalog": build_policy_catalog(inp),
        "escalation_rate": build_escalation_rate(inp, pending, now),
        "decision_log": log,
        "decision_log_gaps": gaps,
        "posture": build_posture(inp),
    }


REDACTION_CHECKS = {
    "ARN": re.compile(r"arn:aws[a-z-]*:"),
    "AWS account ID": re.compile(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])"),
    "email address": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
}


def check_redaction(text: str) -> None:
    for label, pattern in REDACTION_CHECKS.items():
        m = pattern.search(text)
        if m:
            start = max(0, m.start() - 40)
            sys.exit(f"build-trust-center: refusing to write, found an {label} near: …{text[start:m.end() + 10]}…")


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the trust center's data from this build's artifacts and registers.")
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--vdr", default="vdr-report.json")
    ap.add_argument("--reconcile-report", default="reconcile-report.json")
    ap.add_argument("--boundary-map", default="boundary-map.json")
    ap.add_argument("--trust-root-plan", default="trust-root-plan.json")
    ap.add_argument("--runtime", default="ksi-signal-runtime.json", help="the published runtime signal (optional)")
    ap.add_argument("--vdr-status", default="vdr-status.json", help="the nightly status beacon (optional)")
    ap.add_argument("--manual-settings", default="manual-settings.json", help="scripts/check-manual-settings.py output (optional)")
    ap.add_argument("--corroboration", default="boundary-corroboration.json", help="tools/boundary-map/corroborate.py output (optional)")
    ap.add_argument("--previous", default="trust-center-previous.json", help="the last published trust center (optional)")
    ap.add_argument("--decisions", default=str(DECISIONS_PATH))
    ap.add_argument("--exceptions", default=str(REPO / "infrastructure" / "policy" / "exceptions" / "data.json"))
    ap.add_argument("--policy-config", default=str(REPO / "infrastructure" / "policy" / "config" / "data.json"))
    ap.add_argument("--policy-dir", default=str(REPO / "infrastructure" / "policy"))
    ap.add_argument("--checkov-config", default=str(REPO / ".checkov.yaml"))
    ap.add_argument("--scn-register", default=str(REPO / "docs" / "scn" / "scn-register.csv"))
    ap.add_argument("--no-figures", action="store_true", help="skip the Rev5 Moderate figures (needs the built inventory)")
    ap.add_argument("--commit", default="")
    ap.add_argument("--output", default="trust-center.json")
    a = ap.parse_args()

    def load(path: str, required: bool = True) -> Any:
        p = Path(path)
        if not p.exists() or p.stat().st_size == 0:
            if required:
                sys.exit(f"build-trust-center: missing input {path}")
            return None
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            if required:
                sys.exit(f"build-trust-center: {path} is not JSON")
            return None

    annotations = _load_module("check_policy_annotations", REPO / "scripts" / "check-policy-annotations.py")
    figures = None
    if not a.no_figures:
        import _controls
        figures = framework_figures(_controls.load(a.ksi_signal))

    inp = {
        "signal": load(a.ksi_signal), "vdr": load(a.vdr),
        "reconcile": load(a.reconcile_report), "boundary_map": load(a.boundary_map),
        "trust_root_plan": load(a.trust_root_plan, required=False),
        "runtime": load(a.runtime, required=False), "vdr_status": load(a.vdr_status, required=False),
        "previous": load(a.previous, required=False),
        "manual_settings": load(a.manual_settings, required=False),
        "corroboration": load(a.corroboration, required=False),
        "decisions": _decisions.load(a.decisions)["decisions"],
        "exceptions": load(a.exceptions) or [],
        "policy_config": load(a.policy_config) or {},
        "rules": annotations.load_rule_annotations(a.policy_dir),
        "scn_register": read_scn_register(Path(a.scn_register)),
        "checkov_skips": read_checkov_skips(Path(a.checkov_config)),
        "figures": figures,
    }
    doc = build(inp, a.commit, datetime.now(timezone.utc))
    text = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    check_redaction(text)
    Path(a.output).write_text(text)
    print(f"build-trust-center: {len(doc['decisions_pending'])} decision(s) pending, "
          f"{len(doc['decision_log'])} recorded decision(s), picture: "
          + ", ".join(f"{p['id']}={p['status']}" for p in doc["picture"]))


if __name__ == "__main__":
    main()
