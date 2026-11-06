#!/usr/bin/env python3
"""Agency access to the certification package: the inventory, its history, and
the five-business-day denial clock (CDS-TRC-AAI, CDS-TRC-SSM, CDS-UTC-AAD,
CDS-UTC-AGA).

No engagement (DEC-194): no real agency or FedRAMP is served, notified or
answered. Every requester is simulated, and the register
(data/agency-access.json) may hold only entries marked `simulated: true` for
an agency whose name ends "(simulated)"; anything else fails the deploy. The
package is public, so access needs no provisioning. Nobody decides a request
by hand: `decide()` applies fixed rules (RULES) to what the request asks for,
and `notify()` is the automated notifier, which writes each denial notice to
the simulated FedRAMP as a log entry (docs/procedures/agency-access.md). From
the requests this computes:

  inventory      the agencies and systems with access on record today;
  history        every request, decision and withdrawal, in date order;
  denial notices FedRAMP must be told within 5 business days of a denial
                 (US federal holidays excluded); each notice is on time,
                 pending (inside the window), late, or overdue.

`validate` fails the deploy on an invalid or non-simulated record, a late
notice, or an overdue one. `inventory` prints the inventory and history.
`exercise` runs the rules and the notifier over
data/agency-access-exercise.json, a scenario of plainly fictional agencies
dated relative to today (with a simulated notifier outage), and fails unless
every outcome is the expected one, including the late and overdue cases it
must catch. Nothing is ever sent to FedRAMP or anyone: a notice is a log entry.
"""

import argparse
import json
import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _engagement  # noqa: E402
import _offering  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
REGISTER = REPO / "data" / "agency-access.json"
SCENARIO = REPO / "data" / "agency-access-exercise.json"
NOTICE_DAYS = 5
KINDS = ("access", "withdrawal", "inventory-request")
DECISIONS = ("granted", "denied")
ID_RE = re.compile(r"^AAR-[A-Z0-9]{2,8}$")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
RECORD_KEYS = {"id", "agency", "system", "kind", "channel", "received_on", "decision", "decided_on", "decided_by",
               "reason", "rule", "fedramp_notified_on", "withdraws", "simulated", "asks"}
SIMULATED_SUFFIX = "(simulated)"
DECIDER = "scripts/agency-access.py rules (automated)"
# The rules, in order; the first that matches what a request asks for denies it.
# A request no rule denies is granted: the package is public and read-only.
RULES = [
    ("R1-write", re.compile(r"\b(?:write|edit|modify|delete|admin)\b", re.I),
     "The package is read-only for everyone; write access does not exist to grant."),
    ("R2-channel", re.compile(r"\b(?:fax|carrier pigeon|floppy|cd-rom|in person)\b", re.I),
     "The package is delivered over HTTPS only."),
    ("R3-nonpublic", re.compile(r"\b(?:non-public|unpublished|private|customer data|raw logs?)\b", re.I),
     "The system holds nothing beyond the public package to give."),
    ("R4-unverifiable", re.compile(r"\bunverifiable\b|\bdoes not exist\b", re.I),
     "The requesting agency could not be verified."),
]


def _fail(msg):
    raise SystemExit(f"::error::agency access: {msg} (fail-closed)")


# --- business days ------------------------------------------------------------------------

def _nth_weekday(year, month, weekday, n):
    d = date(year, month, 1)
    d += timedelta(days=(weekday - d.weekday()) % 7)
    return d + timedelta(weeks=n - 1)


def _last_weekday(year, month, weekday):
    d = date(year, month + 1, 1) - timedelta(days=1) if month < 12 else date(year, 12, 31)
    return d - timedelta(days=(d.weekday() - weekday) % 7)


def _observed(d):
    return d - timedelta(days=1) if d.weekday() == 5 else d + timedelta(days=1) if d.weekday() == 6 else d


def federal_holidays(year):
    """US federal holidays (5 U.S.C. 6103), observed dates."""
    fixed = [date(year, 1, 1), date(year, 6, 19), date(year, 7, 4), date(year, 11, 11), date(year, 12, 25)]
    floating = [_nth_weekday(year, 1, 0, 3), _nth_weekday(year, 2, 0, 3), _last_weekday(year, 5, 0),
                _nth_weekday(year, 9, 0, 1), _nth_weekday(year, 10, 0, 2), _nth_weekday(year, 11, 3, 4)]
    return {_observed(d) for d in fixed} | set(floating)


def is_business_day(d):
    return d.weekday() < 5 and d not in federal_holidays(d.year)


def add_business_days(d, n):
    step = 1 if n >= 0 else -1
    while n:
        d += timedelta(days=step)
        if is_business_day(d):
            n -= step
    return d


# --- the register ------------------------------------------------------------------------------

def _date(v, where):
    try:
        return date.fromisoformat(v)
    except (TypeError, ValueError):
        _fail(f"{where} is not a YYYY-MM-DD date: {v!r}")


def validate(doc, where):
    if not isinstance(doc, dict) or doc.get("schema") != "agency-access/1" or not isinstance(doc.get("requests"), list):
        _fail(f"{where} is not an agency-access/1 document")
    seen = {}
    for r in doc["requests"]:
        rid = r.get("id") if isinstance(r, dict) else None
        if not isinstance(rid, str) or not ID_RE.match(rid) or rid in seen:
            _fail(f"{where}: request id {rid!r} is not a unique AAR-XXX")
        if set(r) - RECORD_KEYS:
            _fail(f"{rid}: unknown field(s) {sorted(set(r) - RECORD_KEYS)}")
        for k in ("agency", "channel"):
            if not isinstance(r.get(k), str) or not r[k].strip():
                _fail(f"{rid}: {k} must be a non-empty string")
        # No engagement (DEC-194): every entry is a simulated agency.
        if r.get("simulated") is not True or not r["agency"].rstrip().endswith(SIMULATED_SUFFIX):
            _fail(f"{rid}: every entry must be `simulated: true` for an agency named '... {SIMULATED_SUFFIX}'; "
                  f"no real agency request is taken ({_engagement.DECISION})")
        # The register records agencies and systems, never people.
        if any(isinstance(v, str) and EMAIL_RE.search(v) for v in r.values()):
            _fail(f"{rid}: carries an email address; the register names agencies and systems, not people")
        if r.get("kind") not in KINDS:
            _fail(f"{rid}: kind must be one of {list(KINDS)}")
        received = _date(r.get("received_on"), f"{rid} received_on")
        if r["kind"] == "withdrawal":
            if r.get("withdraws") not in seen or seen[r["withdraws"]].get("decision") != "granted":
                _fail(f"{rid}: withdraws must name an earlier granted request")
        if r.get("decision") is not None:
            if r["decision"] not in DECISIONS or r["kind"] != "access":
                _fail(f"{rid}: only an access request is decided, granted or denied")
            if _date(r.get("decided_on"), f"{rid} decided_on") < received:
                _fail(f"{rid}: decided before it was received")
            if not isinstance(r.get("decided_by"), str) or not r["decided_by"].strip():
                _fail(f"{rid}: a decision names who made it (decided_by)")
            if r["decision"] == "denied" and not (isinstance(r.get("reason"), str) and r["reason"].strip()):
                _fail(f"{rid}: a denial states its reason")
        if r.get("fedramp_notified_on") is not None:
            if r.get("decision") != "denied":
                _fail(f"{rid}: only a denial is notified to FedRAMP")
            if _date(r["fedramp_notified_on"], f"{rid} fedramp_notified_on") < date.fromisoformat(r["decided_on"]):
                _fail(f"{rid}: FedRAMP notified before the denial")
        seen[rid] = r
    return doc


def process(doc, today):
    reqs = sorted(doc["requests"], key=lambda r: (r["received_on"], r["id"]))
    withdrawn = {r["withdraws"]: r for r in reqs if r["kind"] == "withdrawal"}
    inventory, history, notices = [], [], []
    for r in reqs:
        history.append({"date": r["received_on"], "request": r["id"], "event": f"{r['kind']} received",
                        "agency": r["agency"], "system": r.get("system")})
        if r.get("decision"):
            history.append({"date": r["decided_on"], "request": r["id"], "event": r["decision"],
                            "agency": r["agency"], "system": r.get("system")})
        if r.get("decision") == "granted":
            w = withdrawn.get(r["id"])
            if w is None:
                inventory.append({"request": r["id"], "agency": r["agency"], "system": r.get("system"),
                                  "since": r["decided_on"]})
            else:
                history.append({"date": w["received_on"], "request": r["id"], "event": "access withdrawn",
                                "agency": r["agency"], "system": r.get("system")})
        if r.get("decision") == "denied":
            decided = date.fromisoformat(r["decided_on"])
            deadline = add_business_days(decided, NOTICE_DAYS)
            sent = r.get("fedramp_notified_on")
            if sent:
                state = "on time" if date.fromisoformat(sent) <= deadline else "late"
                history.append({"date": sent, "request": r["id"], "event": "denial notified to FedRAMP",
                                "agency": r["agency"], "system": r.get("system")})
            else:
                state = "pending" if today <= deadline else "overdue"
            notices.append({"request": r["id"], "agency": r["agency"], "denied_on": r["decided_on"],
                            "reason": r["reason"], "deadline": deadline.isoformat(), "notified_on": sent,
                            "state": state,
                            "rule": r.get("rule"),
                            "to": "FedRAMP (simulated recipient: nothing is sent; this entry is the notice)"})
    history.sort(key=lambda h: (h["date"], h["request"]))
    problems = [f"{n['request']}: FedRAMP denial notice {n['state']} (deadline {n['deadline']})"
                for n in notices if n["state"] in ("late", "overdue")]
    return {"as_of": today.isoformat(), "inventory": inventory, "history": history, "denial_notices": notices,
            "inventory_requests": [r["id"] for r in reqs if r["kind"] == "inventory-request"],
            "problems": problems}


def load(path):
    p = Path(path)
    try:
        return validate(json.loads(p.read_text()), str(p))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {p}: {exc}")


# --- the exercise ---------------------------------------------------------------------------------

def decide(request):
    """(decision, rule, reason) for an access request, by RULES; nobody decides by hand."""
    asks = f"{request.get('asks') or ''} {request.get('channel') or ''} {request.get('agency') or ''}"
    for rule, pattern, reason in RULES:
        if pattern.search(asks):
            return "denied", rule, reason
    return "granted", "R0-public", None


def notify(denied_on, delay, today):
    """The automated notifier: the date its log entry to the simulated FedRAMP is
    written, or None while it has not run (a simulated outage, or not yet due).
    `delay` is the business days the notifier's queue holds the notice; None is
    an outage that has not ended."""
    if delay is None:
        return None
    sent = add_business_days(denied_on, delay)
    return sent.isoformat() if sent <= today else None


def materialize(scenario, today):
    """Turn the scenario's business-day offsets (relative to today) into dates,
    decide each access request by the rules on the day it arrives, and run the
    notifier (with the scenario's simulated delays and outage) over the denials."""
    out = []
    for r in scenario["requests"]:
        r = dict(r)
        r["simulated"] = True
        r["received_on"] = add_business_days(today, r.pop("received_on_offset")).isoformat()
        delay = r.pop("notifier_delay_business_days", 0)
        if r["kind"] == "access":
            r["decision"], r["rule"], reason = decide(r)
            r["decided_on"], r["decided_by"] = r["received_on"], DECIDER
            if reason:
                r["reason"] = reason
                sent = notify(date.fromisoformat(r["decided_on"]), delay, today)
                if sent:
                    r["fedramp_notified_on"] = sent
        out.append(r)
    return {"schema": "agency-access/1", "requests": out}


def observe(result):
    obs = {f"{i['request']}": "in inventory" for i in result["inventory"]}
    for h in result["history"]:
        if h["event"] == "access withdrawn":
            obs[h["request"]] = "withdrawn"
    for n in result["denial_notices"]:
        obs[n["request"]] = f"denial notice {n['state']}"
    for rid in result["inventory_requests"]:
        obs[rid] = "inventory supplied"
    return obs


def exercise(scenario, today):
    doc = validate(materialize(scenario, today), "exercise scenario")
    result = process(doc, today)
    observed = observe(result)
    expected = scenario["expected"]
    mismatches = [f"{k}: expected {v!r}, observed {observed.get(k)!r}" for k, v in sorted(expected.items())
                  if observed.get(k) != v]
    mismatches += [f"{k}: observed {v!r} with no expectation" for k, v in sorted(observed.items())
                   if k not in expected]
    return doc, result, mismatches


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate")
    v.add_argument("--register", default=str(REGISTER))
    i = sub.add_parser("inventory")
    i.add_argument("--register", default=str(REGISTER))
    e = sub.add_parser("exercise")
    e.add_argument("--scenario", default=str(SCENARIO))
    e.add_argument("--output", default="agency-access-exercise.json")
    e.add_argument("--md-output", default="agency-access-exercise.md")
    for p in (v, i, e):
        p.add_argument("--today", default=None, help="YYYY-MM-DD (default: today, UTC)")
    a = ap.parse_args(argv)
    today = date.fromisoformat(a.today) if a.today else datetime.now(timezone.utc).date()

    if a.cmd in ("validate", "inventory"):
        result = process(load(a.register), today)
        if a.cmd == "inventory":
            print(json.dumps({"as_of": result["as_of"], "inventory": result["inventory"],
                              "history": result["history"]}, indent=2))
            return 0
        for p in result["problems"]:
            print(f"::error::{p}")
        if result["problems"]:
            _fail(f"{len(result['problems'])} denial notice(s) to FedRAMP late or overdue")
        print(f"agency access: {len(result['inventory'])} on record; {len(result['denial_notices'])} denial "
              f"notice(s), none late or overdue")
        return 0

    scenario = json.loads(Path(a.scenario).read_text())
    doc, result, mismatches = exercise(scenario, today)
    for m in mismatches:
        print(f"::error::agency access exercise: {m}")
    if mismatches:
        _fail("the exercise did not produce the expected outcomes")
    _engagement.require_none(scenario, "the agency access exercise scenario")
    log = {"log_type": "agency-access-exercise", "fedRampId": _offering.fedramp_id(), "simulated": True, "counterparty": "agency",
           "generated_at": datetime.now(timezone.utc).isoformat(), "as_of": today.isoformat(),
           "engagement": _engagement.STATEMENT,
           "disclaimer": scenario["disclaimer"], "procedure": "docs/procedures/agency-access.md",
           "rules": [{"rule": "R0-public", "decision": "granted", "reason": "Everything is public and read-only."}]
           + [{"rule": n, "decision": "denied", "reason": why} for n, _, why in RULES],
           "notice_window_business_days": NOTICE_DAYS,
           "outcome": "every expected outcome observed", "expected": scenario["expected"],
           "requests": doc["requests"], **{k: result[k] for k in ("inventory", "history", "denial_notices")}}
    Path(a.output).write_text(json.dumps(log, indent=2) + "\n")
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(log) + "\n")
    print(f"agency access exercise: {len(scenario['expected'])} expected outcomes observed")
    return 0


def render_markdown(log):
    out = ["# Agency access exercise (simulated)", "", f"> {log['engagement']}", "", f"_{log['disclaimer']}_", "",
           f"- **As of:** {log['as_of']} | **Generated:** {log['generated_at']}",
           f"- **Procedure:** `{log['procedure']}` | **Denial notice window:** "
           f"{log['notice_window_business_days']} business days", f"- **Outcome:** {log['outcome']}", "",
           "## Expected and observed", "", "| Request | Outcome |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in sorted(log["expected"].items())]
    out += ["", "## Inventory on record", "", "| Request | Agency | System | Since |", "|---|---|---|---|"]
    out += [f"| {i['request']} | {i['agency']} | {i.get('system') or '—'} | {i['since']} |" for i in log["inventory"]]
    out += ["", "## Decision rules (automated)", "", "| Rule | Decision | Reason |", "|---|---|---|"]
    out += [f"| {r['rule']} | {r['decision']} | {r['reason']} |" for r in log["rules"]]
    out += ["", "## Denial notices to FedRAMP (simulated; nothing is sent)", "",
            "| Request | Agency | Rule | Denied | Deadline | Notified | State |", "|---|---|---|---|---|---|---|"]
    out += [f"| {n['request']} | {n['agency']} | {n.get('rule') or '—'} | {n['denied_on']} | {n['deadline']} | "
            f"{n['notified_on'] or '—'} | {n['state']} |" for n in log["denial_notices"]]
    out += ["", "## History", "", "| Date | Request | Event | Agency |", "|---|---|---|---|"]
    out += [f"| {h['date']} | {h['request']} | {h['event']} | {h['agency']} |" for h in log["history"]]
    out += ["", "## Requests", "", "```json", json.dumps(log["requests"], indent=2), "```",
            "", "---", "_Source of truth: the signed `agency-access-exercise.json`._"]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
