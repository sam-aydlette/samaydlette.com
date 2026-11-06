#!/usr/bin/env python3
"""Hold the Annual Security Review, from package maintenance (KSI-PIY-RIS, KSI-PIY-RES, KSI-SVC-EIS, KSI-INR-RPI; PL-4).

Nobody convenes a review meeting (DEC-195). On its date the package
maintainer, at the deployed commit, generates the review from the system's own
data, and a simulated reviewer signs off each item:

  documents        every policy, procedure, plan and record in
                   data/non-machine-resources.json with its sha256, the result
                   of its machine checks (scripts/_nonmachine.py) and whether it
                   changed since the previous review. Any failing check fails.
  component types  the inventory's component types. A type added since the
                   previous review must be named in the threat model or the
                   ingress and DDoS sections of docs/architecture-decisions.md,
                   or the review fails (the fix is a doc change, not a meeting).
  operations       the last 12 months: decisions made, superseded and lapsed;
                   the VDR's open, accepted and process findings; incidents and
                   exercises by pattern. A real incident pattern seen twice
                   fails the review (KSI-INR-RPI): it needs a code or doc change.
  investment       recurring cost from data/recurring-costs.json (a source per
                   line) and pipeline minutes from the run history.
  rules of         the rules of behavior's sha256 is acknowledged by a simulated
  behavior         member of personnel each year and whenever it changes, on
                   every maintainer run; the deploy fails while the current
                   version has no acknowledgement.

A review that fails is not frozen: the run fails and the next run holds it
again, so the fix is shipped before the review is published. Writes
security-review-<due date>.json and .view.md (never rewritten) and the index
security-reviews.json (with the acknowledgements), every run.

  hold-security-review.py --ksi-signal ksi-signal.json --vdr vdr-report.json \
      [--runs runs.json] [--previous-index security-reviews.json] --out DIR --new-files FILE
"""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
import _decisions  # noqa: E402
import _nonmachine  # noqa: E402
import _offering  # noqa: E402
import _scheduled_review as sr  # noqa: E402

RV = sr.REVIEWS["security-review"]
ROB = "docs/rules-of-behavior.md"
COSTS = REPO / "data" / "recurring-costs.json"
THREAT_DOC = "docs/architecture-decisions.md"
# The sections of THREAT_DOC a new component type must be named in.
THREAT_SECTIONS = ("## Threat Modeling", "## Ingress and egress restriction", "## DDoS and unwanted-activity")
# What a component type is called in prose. A type not here is looked for by its own name.
TYPE_TERMS = {
    "api_gateway": ("API Gateway",), "audit_log_trail": ("CloudTrail", "trail"), "cdn_distribution": ("CloudFront",),
    "dns_zone": ("DNS", "Route 53"), "event_schedule": ("EventBridge", "schedule"), "external_service": ("Sigstore",
                                                                                                        "GitHub"),
    "function": ("Lambda",), "html_artifact": ("static site", "site content"), "iam_group": ("IAM",),
    "iam_policy": ("IAM",), "iam_role": ("role",), "identity_provider": ("Cognito",), "kms_key": ("KMS",),
    "kv_table": ("DynamoDB", "state lock"), "log_group": ("CloudWatch Logs", "log group"),
    "message_queue": ("SQS", "queue"), "metric_alarm": ("alarm",), "notification_topic": ("SNS",),
    "npm_package": ("npm", "dependenc"), "object_store": ("S3", "bucket"), "oidc_provider": ("OIDC",),
    "pypi_package": ("PyPI", "Python", "dependenc"), "tls_certificate": ("TLS", "ACM"),
}
COST_KEYS = {"id", "item", "source", "estimate_usd_per_year", "estimate", "basis"}
WINDOW_DAYS = 365
STATUS = "AI-drafted estimate; operator to correct"


def _fail(msg):
    raise SystemExit(f"::error::security review: {msg} (fail-closed)")


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --- the items -------------------------------------------------------------------------

def documents(nm, decisions, previous_review, repo=REPO):
    probs = _nonmachine.problems(nm, decisions, repo)
    before = {d["path"]: d["sha256"] for d in (previous_review or {}).get("documents") or []}
    rows = []
    for e in nm["resources"]:
        p = repo / e["path"]
        sha = sha256_file(p) if p.is_file() else None
        mine = [x for x in probs if x.startswith(e["id"] + ":")]
        rows.append({"id": e["id"], "path": e["path"], "kind": e["kind"], "sha256": sha,
                     "checks": "fail" if mine else "pass",
                     "changedSinceLastReview": None if not before else before.get(e["path"]) != sha})
    bad = [r["id"] for r in rows if r["checks"] == "fail"] + [x for x in probs if " has no entry " in x]
    check = {"id": "documents", "title": "Every policy, procedure, plan and record passes its machine checks",
             "result": "fail" if bad else "pass",
             "detail": (f"{len(rows)} document(s); "
                        + (f"failing: {', '.join(bad[:10])}" if bad else "all pass")
                        + (f"; {sum(1 for r in rows if r['changedSinceLastReview'])} changed since the last review"
                           if before else "; first review: every document is the baseline"))}
    return check, rows


def _section_text(text, heading):
    i = text.find(heading)
    if i < 0:
        return ""
    j = text.find("\n## ", i + 1)
    return text[i:j if j > 0 else None]


def component_types(signal, previous_review, threat_text):
    types = sorted({c.get("type") for c in signal.get("components") or [] if c.get("type")})
    if not types:
        _fail("the inventory lists no component types")
    sections = "\n".join(_section_text(threat_text, h) for h in THREAT_SECTIONS)
    prev = (previous_review or {}).get("componentTypes")
    new = sorted(set(types) - set(prev)) if isinstance(prev, list) else []

    def named(t):
        terms = TYPE_TERMS.get(t, (t.replace("_", " "),))
        return any(re.search(re.escape(term), sections, re.I) for term in terms)

    unnamed = [t for t in new if not named(t)]
    check = {"id": "component-types", "title": f"Every component type added since the last review is named in the "
                                               f"threat model ({THREAT_DOC})", "result": "fail" if unnamed else "pass",
             "detail": (f"{len(types)} type(s); " + (f"new since the last review: {', '.join(new)}" if new else
                                                     "none new since the last review" if isinstance(prev, list) else
                                                     "first review: the current types are the baseline")
                        + (f"; not named: {', '.join(unnamed)}" if unnamed else ""))}
    return check, types


def _day(v):
    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        return None


def operations(reg, incidents, vdr, today):
    since = today - timedelta(days=WINDOW_DAYS)
    recent = [r for r in reg["decisions"] if (_day(r.get("decided_on")) or date.min) >= since]
    lapsed = [r["id"] for r in _decisions.in_force(reg) if str(r.get("review_by", "")) < today.isoformat()]
    findings = vdr.get("findings") or []
    incs = [i for i in incidents.get("incidents") or [] if (_day(i.get("detected_at")) or date.min) >= since]
    real = [i for i in incs if not i.get("exercise")]
    patterns = Counter(i["evaluation"].get("basis") or "unclassified" for i in real)
    recurring = sorted(p for p, n in patterns.items() if n >= 2)
    summary = {
        "decisions": {"madeInLast12Months": len(recent),
                      "byDisposition": dict(sorted(Counter(r.get("disposition") for r in recent).items())),
                      "superseded": sum(1 for r in recent if r.get("disposition") == "superseded"),
                      "lapsed": lapsed},
        "findings": {"inVdr": len(findings), "process": sum(1 for f in findings if f.get("source") == "process"),
                     "riskAccepted": len(vdr.get("risk_accepted") or [])},
        "incidents": {"inLast12Months": len(real), "exercises": len(incs) - len(real),
                      "patterns": dict(sorted(patterns.items())), "recurring": recurring},
    }
    checks = [
        {"id": "decisions", "title": "No in-force decision is past its review date", "result": "fail" if lapsed else
         "pass", "detail": f"{len(recent)} decision(s) in the last 12 months; lapsed: {', '.join(lapsed) or 'none'}"},
        {"id": "incident-patterns", "title": "No incident pattern recurs (KSI-INR-RPI)",
         "result": "fail" if recurring else "pass",
         "detail": f"{len(real)} incident(s) and {len(incs) - len(real)} exercise(s) in the last 12 months"
                   + (f"; recurring: {', '.join(recurring)}" if recurring else "")},
    ]
    return checks, summary


def validate_costs(doc, repo=REPO):
    if not isinstance(doc, dict) or doc.get("schema") != "recurring-costs/1" or doc.get("status") != STATUS:
        _fail(f"data/recurring-costs.json is not a recurring-costs/1 document marked {STATUS!r}")
    lines = doc.get("lines")
    if not isinstance(lines, list) or not lines:
        _fail("data/recurring-costs.json has no lines")
    seen = set()
    for x in lines:
        if not isinstance(x, dict) or set(x) != COST_KEYS or x["id"] in seen:
            _fail(f"a cost line must have exactly {sorted(COST_KEYS)} and a unique id: {x!r}"[:200])
        seen.add(x["id"])
        src = str(x["source"])
        if not src.startswith("external:") and not (repo / src.split("#", 1)[0]).exists():
            _fail(f"{x['id']}: source {src!r} is neither a repository path nor external:<what>")
        est = x["estimate_usd_per_year"]
        if est is not None and (isinstance(est, bool) or not isinstance(est, (int, float)) or est < 0):
            _fail(f"{x['id']}: estimate_usd_per_year must be a non-negative number or null (unknown)")
        if est is None and x["estimate"] != "unknown":
            _fail(f"{x['id']}: a line with no figure must say 'unknown'")
    return doc


def investment(costs, runs, today):
    known = [x for x in costs["lines"] if x["estimate_usd_per_year"] is not None]
    since = (today - timedelta(days=WINDOW_DAYS)).isoformat()
    minutes = Counter()
    for r in runs or []:
        a, b = sr._ts(r.get("createdAt")), sr._ts(r.get("updatedAt"))
        if a and b and str(r.get("createdAt")) >= since:
            minutes[r.get("workflowName") or "unknown"] += max(0, round((b - a).total_seconds() / 60))
    summary = {"status": costs["status"], "estimatedUsdPerYear": round(sum(x["estimate_usd_per_year"] for x in known),
                                                                       2),
               "unknownLines": [x["id"] for x in costs["lines"] if x["estimate_usd_per_year"] is None],
               "lines": costs["lines"],
               "pipelineMinutes": {"byWorkflow": dict(sorted(minutes.items())), "total": sum(minutes.values()),
                                   "basis": "wall-clock minutes of the workflow runs GitHub lists (gh run list), "
                                            "created in the last 12 months; minutes on a public repository's "
                                            "standard runners are not billed"}}
    check = {"id": "investment", "title": "Recurring cost has a source for every line (data/recurring-costs.json) "
                                          "and the pipeline's run time is known",
             "result": "pass" if runs is not None else "fail",
             "detail": f"estimated ${summary['estimatedUsdPerYear']}/year over {len(known)} line(s), "
                       f"{len(summary['unknownLines'])} unknown ({STATUS}); "
                       + (f"{summary['pipelineMinutes']['total']} pipeline minute(s) from {len(runs)} run(s)"
                          if runs is not None else "no run history was read")}
    return check, summary


# --- the rules of behavior -------------------------------------------------------------

def acknowledgements(previous_index, rob_sha, today, held_now):
    acks = list(((previous_index or {}).get("rulesOfBehavior") or {}).get("acknowledgements") or [])
    known = {a.get("sha256") for a in acks}
    reason = ("annual acknowledgement with the security review" if held_now else
              None if rob_sha in known else
              "first acknowledgement" if not acks else "the rules of behavior changed")
    if reason:
        acks.append({"sha256": rob_sha, "acknowledgedOn": today.isoformat(), "by": sr.CAST["personnel"],
                     "reason": reason})
    return {"document": ROB, "currentSha256": rob_sha, "acknowledgedBy": sr.CAST["personnel"],
            "rule": "PL-4: acknowledged every year and whenever the document changes; the deploy fails while the "
                    "current version has no acknowledgement (scripts/check-scheduled-review.py).",
            "acknowledgements": acks}


def rob_acknowledged(index, rob_sha):
    acks = ((index or {}).get("rulesOfBehavior") or {}).get("acknowledgements") or []
    return any(a.get("sha256") == rob_sha for a in acks)


# --- the review ------------------------------------------------------------------------

def previous_review(previous_index, docs_dirs):
    """The last held review's document, read from the published copy (by its sha256)."""
    have = sr.held(RV, previous_index)
    if not have:
        return None
    last = have[max(have)]
    name = f"{RV.prefix}{last['dueDate']}.json"
    for d in docs_dirs:
        p = Path(d) / name
        if p.is_file():
            if hashlib.sha256(p.read_bytes()).hexdigest() != last["sha256"]:
                _fail(f"{name} does not match the sha256 the index records")
            return json.loads(p.read_text())
    _fail(f"the previous review {name} is not available")


def build(due, now, fedramp_id, signal, vdr, runs, reg, incidents, nm, costs, prev, threat_text, repo=REPO):
    today = now.date()
    doc_check, docs = documents(nm, reg, prev, repo)
    type_check, types = component_types(signal, prev, threat_text)
    op_checks, ops = operations(reg, incidents, vdr, today)
    inv_check, inv = investment(costs, runs, today)
    checks = [doc_check, type_check, *op_checks, inv_check]
    remarks = {"pass": "Reviewed. Looks good. I would have said so in a meeting, too, but this was faster.",
               "fail": "Not signed. Fix it in a pull request; I will be here, being simulated."}
    doc = sr.base_doc(RV, due, now, fedramp_id, f"Annual Security Review due {due} (generated; simulated sign-off)")
    doc.update({
        "rules": ["KSI-PIY-RIS", "KSI-PIY-RES", "KSI-SVC-EIS", "KSI-INR-RPI"],
        "controls": ["pl-2", "pl-4", "pm-3", "ra-3", "sa-11", "ir-4"],
        "method": "scripts/hold-security-review.py, run by package-maintenance.yml at the deployed commit on its due "
                  "date. Generated from the system's data; a failing item fails the run, and the fix is a code or "
                  "document change, not a meeting.",
        "reviewer": sr.CAST["reviewer"],
        "checks": checks, "result": sr.result_of(checks),
        "signOff": [{"check": c["id"], "by": sr.CAST["reviewer"], "result": c["result"], "remark": remarks[c["result"]]}
                    for c in checks],
        "documents": docs, "componentTypes": types, "operations": ops, "investment": inv,
        "previousReview": prev.get("dueDate") if prev else None,
    })
    return sr.finish(doc, "the security review")


def run(previous, out, now, fedramp_id, signal, vdr, runs, prev_dirs, repo=REPO, costs_path=COSTS):
    today = now.date()
    due = sr.due_now(RV, previous, today)
    entries, files = [], []
    if due:
        reg = _decisions.load(repo / "data" / "decisions.json")
        incidents = json.loads((repo / "data" / "incidents.json").read_text())
        nm = _nonmachine.load(repo / "data" / "non-machine-resources.json")
        costs = validate_costs(json.loads(Path(costs_path).read_text()), repo)
        threat_text = (repo / THREAT_DOC).read_text(encoding="utf-8")
        prev = previous_review(previous, prev_dirs)
        for d in due:
            doc = build(d, now, fedramp_id, signal, vdr, runs, reg, incidents, nm, costs, prev, threat_text, repo)
            if doc["result"] != "pass":
                for c in doc["checks"]:
                    if c["result"] != "pass":
                        print(f"::error::security review due {d}: {c['title']}: {c['detail']}")
                _fail(f"the review due {d} did not pass; it is held again on the next run once fixed")
            entry, written = sr.write(out, RV, d, doc)
            entries.append(entry)
            files += written
            prev = doc
    rob = acknowledgements(previous, sha256_file(repo / ROB), today, bool(entries))
    index = sr.index_doc(RV, previous, entries, now, fedramp_id, {"rulesOfBehavior": rob})
    sr.write_json(out, RV.index, index)
    return index, entries, files


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ksi-signal", required=True)
    ap.add_argument("--vdr", required=True)
    ap.add_argument("--runs", default=None, help="gh run list --json workflowName,createdAt,updatedAt output")
    ap.add_argument("--previous-index", default=None)
    ap.add_argument("--previous-dir", action="append", default=[], help="where the previous review's file is")
    ap.add_argument("--out", required=True)
    ap.add_argument("--new-files", default=None)
    ap.add_argument("--now", default=None, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    now = sr.now_utc(a.now)
    prev = Path(a.previous_index) if a.previous_index else None
    previous = json.loads(prev.read_text()) if prev and prev.is_file() else {}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    runs = json.loads(Path(a.runs).read_text()) if a.runs else None
    index, entries, files = run(previous, out, now, _offering.fedramp_id(), json.loads(Path(a.ksi_signal).read_text()),
                                json.loads(Path(a.vdr).read_text()), runs, a.previous_dir or [str(out)])
    if a.new_files:
        Path(a.new_files).write_text("".join(f + "\n" for f in files))
    for e in entries:
        print(f"security review due {e['dueDate']}: {e['result']}")
    print(f"security reviews: {len(index['reviews'])} held; next due {index['nextDueDate']}; rules of behavior "
          f"acknowledged at {index['rulesOfBehavior']['currentSha256'][:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
