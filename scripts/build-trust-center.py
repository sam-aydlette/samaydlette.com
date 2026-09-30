#!/usr/bin/env python3
"""Build /.well-known/trust-center.json: the Authorizing Official's view of this system.

The trust center answers five questions, in order:
  1. Is this picture true?            -> picture
  2. What needs my decision?          -> decisions_pending
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
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

SCHEMA = "trust-center/1"
REPO = Path(__file__).resolve().parent.parent

# Freshness windows. They mirror the watchdog alarms in infrastructure/watchdog.tf
# (vdr-age > 24h, runtime-age > 26h); the trust center reports against the same
# thresholds that page the operator.
VDR_MAX_AGE_HOURS = 24
RUNTIME_MAX_AGE_HOURS = 26
# An accepted exception this close to expiry is a renewal decision now, not later.
EXCEPTION_WARNING_DAYS = 30
# Days of escalation-rate history the artifact carries forward.
HISTORY_DAYS = 180

ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SCN_VERIFIED = re.compile(r"verification complete|implemented and verified", re.I)
POAM_DECISIONS = {"risk-accepted", "false-positive", "operational-requirement"}

WHY_YOURS = {
    "vdr_blocking": "The vulnerability gate stops deploys on this finding. Fixing, dispositioning or accepting it is a person's call.",
    "vdr_undispositioned": "No recorded precedent covers this finding, so the pipeline cannot resolve it on its own.",
    "poam_overdue": "The committed completion date has passed. Extending it, accepting the risk or stopping is the AO's decision.",
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
    "decision_review_due": "A recorded risk decision has reached its review date. Reaffirming, changing or ending it is the AO's call.",
    "decision_records_incomplete": "Recorded decisions are missing who made them, when, or when to revisit them. Setting that governance is the AO's call.",
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


def poam_items(poam: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for item in poam.get("plan-of-action-and-milestones", {}).get("poam-items", []):
        pr = _props(item)
        out.append({
            "id": pr.get("poam-id"), "title": item.get("title", ""), "description": item.get("description", ""),
            "status": pr.get("status"), "disposition": pr.get("disposition"),
            "scheduled_completion": pr.get("scheduled-completion-date"),
            "point_of_contact": pr.get("point-of-contact"), "status_date": pr.get("status-date"),
            # The human decision behind an open item (data/poam-items.json).
            "decided_by": pr.get("decided-by"), "decided_on": pr.get("decided-on"), "review_by": pr.get("review-by"),
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
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


# ---------------------------------------------------------------------------
# 1. Is this picture true?
# ---------------------------------------------------------------------------

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
        detail += f"; {age}h old (window {RUNTIME_MAX_AGE_HOURS}h)." if age is not None else "."
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
            + (f", {age}h ago (window {VDR_MAX_AGE_HOURS}h)." if age is not None else "."),
            nightly.get("finished_at"), "/.well-known/vdr-status.json")

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
# 2. What needs my decision?
# ---------------------------------------------------------------------------

def _decision(kind: str, id_: str, title: str, *, since: Any = None, due: Any = None,
              refs: list[str] | None = None) -> dict[str, Any]:
    return {"kind": kind, "id": id_, "title": title, "why_yours": WHY_YOURS[kind],
            "since": since, "due": due, "refs": refs or []}


def build_decisions_pending(inp: dict[str, Any], now: datetime, log: list[dict[str, Any]],
                            log_gaps: dict[str, int]) -> list[dict[str, Any]]:
    today = now.date()
    out: list[dict[str, Any]] = []

    for f in inp["vdr"].get("findings", []):
        if f.get("is_blocking"):
            kind = "vdr_blocking"
        elif (f.get("final_disposition") or "open") == "open":
            kind = "vdr_undispositioned"
        else:
            continue
        out.append(_decision(kind, f.get("tracking_id", ""), f.get("title", ""), since=f.get("first_detected"),
                             due=f.get("remediation_due_at"),
                             refs=[r for r in ("/.well-known/vdr-report.json", f.get("component_id")) if r]))

    for p in poam_items(inp["poam"]):
        due = _parse_date(p["scheduled_completion"])
        if p["status"] == "open" and due and due < today:
            out.append(_decision("poam_overdue", p["id"], p["title"], due=due.isoformat(), refs=["/.well-known/oscal-poam.json"]))

    for e in inp["exceptions"]:
        exp = _parse_date(e.get("expiry"))
        if exp and (exp - today).days <= EXCEPTION_WARNING_DAYS:
            out.append(_decision("exception_expiring", f"{e.get('rule_id')}:{e.get('resource')}",
                                 f"Policy exception {e.get('rule_id')} on {e.get('resource')}", due=exp.isoformat(),
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
            out.append(_decision("runtime_stale", "runtime-stale", "The runtime signal is past its freshness window",
                                 since=runtime.get("emitted_at")))

    for c in inp["boundary_map"].get("trust_root_changes", []):
        out.append(_decision("trust_root_change", c["address"],
                             f"{'/'.join(c.get('actions', []))} {c['address']}",
                             refs=[r for r in ("/.well-known/boundary-map.json", c.get("component")) if r]))

    bmap = inp["boundary_map"]
    for cid in bmap.get("unclassified", []):
        out.append(_decision("boundary_unclassified", cid, f"{cid} is not placed in the boundary", refs=[cid]))
    for n in bmap.get("nodes", []):
        if "untagged" in n.get("flags", []) or "classification tags incomplete" in n.get("flags", []):
            out.append(_decision("boundary_untagged", n["id"], f"{n.get('name', n['id'])} lacks classification tags", refs=[n["id"]]))
        if n.get("kind") == "not_inventoried":
            out.append(_decision("boundary_not_inventoried", n["id"], f"{n.get('name', n['id'])} is used but not inventoried", refs=[n["id"]]))

    for c in (inp.get("manual_settings") or {}).get("checks", []):
        if c.get("status") == "attention" and c.get("id") in MANUAL_SETTINGS:
            out.append(_decision("manual_setting", c["id"], f"{MANUAL_SETTINGS[c['id']]}: {c.get('detail', '')}",
                                 since=(inp.get("manual_settings") or {}).get("checked_at")))

    for row in inp["scn_register"]:
        if not SCN_VERIFIED.search(row.get("status", "")):
            out.append(_decision("scn_unverified", row.get("scn_id", ""), _brief(row.get("short_description", ""), 160),
                                 since=row.get("date_initiated") or None, refs=["docs/scn/"]))

    for e in log:
        review = _parse_date(e.get("review_by"))
        # A policy exception's review date is its expiry, queued above.
        if review and review <= today and e["kind"] != "policy_exception":
            out.append(_decision("decision_review_due", e["id"], f"Review due: {e['subject']}", due=review.isoformat(),
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
    poam_decisions = [p for p in poam_items(inp["poam"]) if p["status"] == "open" and p["disposition"] in POAM_DECISIONS]
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
                {"name": "Remediation SLA (FedRAMP Class C)", "value": "2 to 192 days by PAIN, internet reachability and exploitability; none for N1", "source": "scripts/build-vdr-report.py CLASS_C_SLA_DAYS"},
                {"name": "Vulnerability evidence freshness", "value": f"{VDR_MAX_AGE_HOURS} hours", "source": "infrastructure/watchdog.tf"},
                {"name": "Runtime evidence freshness", "value": f"{RUNTIME_MAX_AGE_HOURS} hours", "source": "infrastructure/watchdog.tf"},
                {"name": "Runtime divergence pre-flight staleness", "value": "48 hours", "source": "scripts/check-runtime-divergence.py"},
                {"name": "Exception renewal warning", "value": f"{EXCEPTION_WARNING_DAYS} days before expiry", "source": "scripts/build-trust-center.py"},
                {"name": "Minimum TLS policy", "value": str(config.get("tls", {}).get("minimum")), "source": "infrastructure/policy/config/data.json"},
                {"name": "Required resource tags", "value": ", ".join(config.get("required_tags", [])), "source": "infrastructure/policy/config/data.json"},
            ],
        },
        "precedent": {
            "about": "Recorded human decisions the automation applies again without asking: the same finding, the same answer.",
            "registers": [
                {"name": "Vulnerability dispositions", "entries": len(inp["dispositions"]), "source": "data/vuln-dispositions.json"},
                {"name": "Policy exceptions", "entries": len(inp["exceptions"]), "source": "infrastructure/policy/exceptions/data.json"},
                {"name": "Checkov suppressions", "entries": len(inp["checkov_skips"]), "source": ".checkov.yaml"},
                {"name": "POA&M risk decisions (open)", "entries": len(poam_decisions), "source": "/.well-known/oscal-poam.json"},
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

    for key, d in sorted(inp["dispositions"].items()):
        add("vulnerability_disposition", key, key, d.get("disposition", ""), decided_by=d.get("decided_by"),
            decided_on=d.get("decided_on"), reasoning=d.get("justification", ""), review_by=d.get("review_by"),
            source="data/vuln-dispositions.json", poam_ref=d.get("poam_ref"))
    for e in inp["exceptions"]:
        add("policy_exception", f"{e.get('rule_id')}:{e.get('resource')}", f"{e.get('rule_id')} on {e.get('resource')}",
            "excepted", decided_by=e.get("decided_by"), decided_on=e.get("decided_on"), reasoning=e.get("justification", ""),
            review_by=e.get("expiry"), source="infrastructure/policy/exceptions/data.json", ticket=e.get("ticket"))
    for p in poam_items(inp["poam"]):
        if p["status"] != "open" or p["disposition"] not in POAM_DECISIONS:
            continue
        # Who decided, when, and the review date come from the POA&M's own
        # decision props. The point of contact is never taken as the decider;
        # an item without the props is reported as a gap.
        add("poam_risk_decision", p["id"], p["title"], p["disposition"], decided_by=p["decided_by"],
            decided_on=p["decided_on"], reasoning=p["description"], review_by=p["review_by"],
            source="/.well-known/oscal-poam.json",
            point_of_contact=p["point_of_contact"], status_date=p["status_date"])
    for row in inp["scn_register"]:
        m = SCN_VERIFIED.search(row.get("status", ""))
        add("significant_change", row.get("scn_id", ""), _brief(row.get("short_description", ""), 160),
            f"approved ({row.get('scn_type', '')})", decided_by=row.get("approver_name"), decided_on=row.get("date_initiated"),
            reasoning=row.get("categorization_rationale", ""), review_by=None, review_applies=False,
            source="docs/scn/scn-register.csv", verified=bool(m))

    gaps = {f: sum(1 for e in log if f in e["gaps"]) for f in ("decided_by", "decided_on", "review_by")}
    return log, gaps


def build_escalation_rate(inp: dict[str, Any], pending: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    auto = int(inp["vdr"].get("summary", {}).get("dispositioned_findings", 0))
    escalated = len(pending)
    today = now.date().isoformat()
    previous = (inp.get("previous") or {}).get("escalation_rate", {}).get("history", [])
    # The previous trust center is read back from the live site: carry forward
    # only well-formed entries, and only their three fields.
    history = [{"date": h["date"], "resolved_by_precedent": h["resolved_by_precedent"], "escalated": h["escalated"]}
               for h in previous if isinstance(h, dict) and isinstance(h.get("date"), str) and ISO_DATE.match(h["date"])
               and h["date"] != today and isinstance(h.get("resolved_by_precedent"), int) and isinstance(h.get("escalated"), int)]
    history.append({"date": today, "resolved_by_precedent": auto, "escalated": escalated})
    return {
        "about": "Of the items this build had to resolve, how many the recorded policy settled and how many came to a person.",
        "resolved_by_precedent": auto, "escalated": escalated,
        "rate": round(escalated / (auto + escalated), 3) if auto + escalated else 0.0,
        "history": sorted(history, key=lambda h: h["date"])[-HISTORY_DAYS:],
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
        "generated_at": now.isoformat(timespec="seconds"),
        "commit": commit,
        "ksi_signal_id": signal_id,
        "system": {"id": inp["signal"].get("system_id"), "impact_level": (inp["signal"].get("categorization") or {}).get("impact_level")},
        "picture": build_picture(inp, now),
        "decisions_pending": pending,
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
    ap.add_argument("--poam", default="oscal-poam.json")
    ap.add_argument("--reconcile-report", default="reconcile-report.json")
    ap.add_argument("--boundary-map", default="boundary-map.json")
    ap.add_argument("--trust-root-plan", default="trust-root-plan.json")
    ap.add_argument("--runtime", default="ksi-signal-runtime.json", help="the published runtime signal (optional)")
    ap.add_argument("--vdr-status", default="vdr-status.json", help="the nightly status beacon (optional)")
    ap.add_argument("--manual-settings", default="manual-settings.json", help="scripts/check-manual-settings.py output (optional)")
    ap.add_argument("--previous", default="trust-center-previous.json", help="the last published trust center (optional)")
    ap.add_argument("--dispositions", default=str(REPO / "data" / "vuln-dispositions.json"))
    ap.add_argument("--exceptions", default=str(REPO / "infrastructure" / "policy" / "exceptions" / "data.json"))
    ap.add_argument("--policy-config", default=str(REPO / "infrastructure" / "policy" / "config" / "data.json"))
    ap.add_argument("--policy-dir", default=str(REPO / "infrastructure" / "policy"))
    ap.add_argument("--checkov-config", default=str(REPO / ".checkov.yaml"))
    ap.add_argument("--scn-register", default=str(REPO / "docs" / "scn" / "scn-register.csv"))
    ap.add_argument("--no-figures", action="store_true", help="skip framework coverage (needs the built SSP)")
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
        figures = _load_module("inject_figures", REPO / "scripts" / "inject-figures.py").compute_figures()

    inp = {
        "signal": load(a.ksi_signal), "vdr": load(a.vdr), "poam": load(a.poam),
        "reconcile": load(a.reconcile_report), "boundary_map": load(a.boundary_map),
        "trust_root_plan": load(a.trust_root_plan, required=False),
        "runtime": load(a.runtime, required=False), "vdr_status": load(a.vdr_status, required=False),
        "previous": load(a.previous, required=False),
        "manual_settings": load(a.manual_settings, required=False),
        "dispositions": (load(a.dispositions) or {}).get("dispositions", {}),
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
