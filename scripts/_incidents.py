"""The incident register: data/incidents.json (IEC-CSO-EFR/DPR/EFI/IIR/OIR/FIR).

Every incident the operator records lives here, once, with the evaluation the
FedRAMP Incident Evaluation and Communication rules ask for:

- evaluation   when it was evaluated, whether it is a FedRAMP Reportable
               Incident (IEC-CSO-EFR) and why; the basis is IEC-CSO-EFR, or
               VER-TFR-IRI / VER-TFR-NRI for a vulnerability treated as one
- estimates    Incident Rating records (IEC-CSO-EFI): rating, customer effect,
               one or several agencies, reason, when. Until the first one, a
               reportable incident is rated at the default (IEC-CSO-DPR)
- reports      the Initial, Ongoing and Final reports, each with when it was
               issued and what it set; a report restates everything set before
- resolved_at / recovery_complete_at, which start the Final report's clock

The clocks (when each report is due) come from FedRAMP's Class C timeframes
through scripts/_rules.py, never from this file. scripts/build-incident-report.py
renders the reports and the incident log from it; reconciliation checks the
findings an incident names against the VDR.

Fails closed, stdlib only (the deploy job installs no jsonschema), following
scripts/_decisions.py: a missing or invalid register stops the build. The JSON
schema beside it (infrastructure/schemas/incidents.schema.json) documents the
same shape and is checked in tests.
"""

import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _redact  # noqa: E402
import _rules  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PATH = REPO / "data" / "incidents.json"
SCHEMA_PATH = REPO / "infrastructure" / "schemas" / "incidents.schema.json"

ID_RE = re.compile(r"^INC-\d{4}-\d{3}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
# Addresses a published report may name: the system's own domain and FedRAMP's.
EMAIL_DOMAINS = ("samaydlette.com", "fedramp.gov", "gsa.gov")

BASES = ("IEC-CSO-EFR", "VER-TFR-IRI", "VER-TFR-NRI")
VULN_RULES = ("VER-TFR-IRI", "VER-TFR-NRI")
REPORT_TYPES = ("Initial", "Ongoing", "Final")
EFFECTS = ("minimal", "narrow", "disruptive", "debilitating")
AGENCY_SCOPES = ("single", "multiple")
# Delivery the pipeline performs. Only publication is built; sending to FedRAMP
# or an agency is the operator's decision and is not implemented.
NOTIFICATION_MODES = ("published-only",)

TOP_KEYS = {"$comment", "schema", "policy", "incidents"}
POLICY_KEYS = {"federal_incident_coordinator", "notification", "notification_text", "adopted_vulnerability_rules",
               "federal_customer_data", "decided_by", "decided_on", "review_by"}
INCIDENT_KEYS = {"id", "title", "exercise", "started_at", "detected_at", "detection_source", "evaluation",
                 "findings", "estimates", "reports", "resolved_at", "recovery_complete_at"}
EVALUATION_KEYS = {"evaluated_at", "reportable", "basis", "reason", "federal_customer_data_considered"}
ESTIMATE_KEYS = {"estimated_at", "rating", "customer_effect", "agencies", "reason"}
REPORT_KEYS = {"type", "at", "set"}
# What a report can set, by the field it fills in the FedRAMP incident report.
TEXT_FIELDS = {
    "description": "incidentDescription",
    "functional_impact": "functionalImpact",
    "recovery_plan": "recoveryPlan",
    "observed_activity": "observedActivity",
    "root_cause": "rootCause",
    "response_and_recovery_activities": "responseAndRecoveryActivities",
}
LIST_FIELDS = {
    "affected_agencies": "affectedAgencies",
    "indicators_of_compromise": "indicatorsOfCompromise",
    "related_cves": "relatedCveIds",
}
SET_KEYS = set(TEXT_FIELDS) | set(LIST_FIELDS) | {"milestones"}
MILESTONE_KEYS = {"at", "description"}


def _fail(msg):
    raise SystemExit(f"::error::incident register: {msg} (fail-closed)")


def parse_ts(value, where):
    """An aware datetime from an ISO 8601 timestamp with an offset, or fail."""
    if not isinstance(value, str) or not TS_RE.match(value):
        _fail(f"{where} must be an ISO 8601 timestamp with a UTC offset, got {value!r}")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail(f"{where} is not a valid timestamp: {value!r}")


def _text(value, where):
    if not isinstance(value, str) or not value.strip():
        _fail(f"{where} must be a non-empty string")
    return value


def _strings(value, where, pattern=None):
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        _fail(f"{where} must be a list of non-empty strings")
    if pattern is not None:
        for x in value:
            if not pattern.match(x):
                _fail(f"{where}: {x!r} does not match {pattern.pattern}")
    if len(set(value)) != len(value):
        _fail(f"{where} lists an entry twice")
    return value


def _published_text_ok(doc, where):
    """Everything in the register is published: no AWS account ID, and no email
    address outside the system's domain and FedRAMP's."""
    text = json.dumps(doc)
    if _redact.find(text):
        _fail(f"{where} contains an AWS account ID; the register is published")
    for m in EMAIL_RE.finditer(text):
        if not m.group(1).lower().endswith(EMAIL_DOMAINS):
            _fail(f"{where} names an email address outside {', '.join(EMAIL_DOMAINS)}; the register is published")


def _validate_policy(p, where):
    if not isinstance(p, dict) or set(p) - POLICY_KEYS or POLICY_KEYS - set(p):
        _fail(f"{where}.policy must have exactly {sorted(POLICY_KEYS)}")
    for k in ("federal_incident_coordinator", "notification_text", "decided_by"):
        _text(p[k], f"{where}.policy.{k}")
    for k in ("decided_on", "review_by"):
        if not isinstance(p[k], str) or not DATE_RE.match(p[k]):
            _fail(f"{where}.policy.{k} must be an ISO date")
    if p["notification"] not in NOTIFICATION_MODES:
        _fail(f"{where}.policy.notification {p['notification']!r} is not one of {list(NOTIFICATION_MODES)}; "
              f"no other delivery is built")
    adopted = _strings(p["adopted_vulnerability_rules"], f"{where}.policy.adopted_vulnerability_rules")
    if set(adopted) - set(VULN_RULES):
        _fail(f"{where}.policy.adopted_vulnerability_rules may name only {list(VULN_RULES)}")
    _text(p["federal_customer_data"], f"{where}.policy.federal_customer_data")


def _validate_estimate(e, where, rubric, floor):
    if not isinstance(e, dict) or set(e) != ESTIMATE_KEYS:
        _fail(f"{where} must have exactly {sorted(ESTIMATE_KEYS)}")
    at = parse_ts(e["estimated_at"], f"{where}.estimated_at")
    if at < floor:
        _fail(f"{where}.estimated_at is before the incident was detected")
    if e["customer_effect"] not in EFFECTS or e["agencies"] not in AGENCY_SCOPES:
        _fail(f"{where}: customer_effect must be one of {list(EFFECTS)} and agencies one of {list(AGENCY_SCOPES)}")
    want = rubric[(e["customer_effect"], e["agencies"])]
    if e["rating"] != want or isinstance(e["rating"], bool):
        _fail(f"{where}: a likely {e['customer_effect']} effect on {e['agencies']} agenc"
              f"{'y' if e['agencies'] == 'single' else 'ies'} is N{want} under IEC-CSO-EFI, not {e['rating']!r}")
    _text(e["reason"], f"{where}.reason")
    return at


def _validate_set(s, where):
    if not isinstance(s, dict) or not s or set(s) - SET_KEYS:
        _fail(f"{where}.set must be a non-empty object with only {sorted(SET_KEYS)}")
    for k in TEXT_FIELDS:
        if k in s:
            _text(s[k], f"{where}.set.{k}")
    for k in LIST_FIELDS:
        if k in s:
            _strings(s[k], f"{where}.set.{k}", CVE_RE if k == "related_cves" else None)
    milestones = s.get("milestones", [])
    if not isinstance(milestones, list):
        _fail(f"{where}.set.milestones must be a list")
    for i, m in enumerate(milestones):
        if not isinstance(m, dict) or set(m) != MILESTONE_KEYS:
            _fail(f"{where}.set.milestones[{i}] must have exactly {sorted(MILESTONE_KEYS)}")
        parse_ts(m["at"], f"{where}.set.milestones[{i}].at")
        _text(m["description"], f"{where}.set.milestones[{i}].description")


def _validate_incident(inc, where, policy, rubric, now):
    rid = inc.get("id") if isinstance(inc, dict) else None
    if not isinstance(rid, str) or not ID_RE.match(rid):
        _fail(f"{where}: incident id {rid!r} is not INC-YYYY-NNN")
    where = rid
    required = {"id", "title", "exercise", "started_at", "detected_at", "detection_source", "evaluation",
                "estimates", "reports"}
    if set(inc) - INCIDENT_KEYS or required - set(inc):
        _fail(f"{where}: unknown field(s) {sorted(set(inc) - INCIDENT_KEYS)}, missing {sorted(required - set(inc))}")
    _text(inc["title"], f"{where}.title")
    _text(inc["detection_source"], f"{where}.detection_source")
    if not isinstance(inc["exercise"], bool):
        _fail(f"{where}.exercise must be true or false")
    started = parse_ts(inc["started_at"], f"{where}.started_at")
    detected = parse_ts(inc["detected_at"], f"{where}.detected_at")
    if detected < started:
        _fail(f"{where}: detected before it started")

    ev = inc["evaluation"]
    if not isinstance(ev, dict) or set(ev) != EVALUATION_KEYS:
        _fail(f"{where}.evaluation must have exactly {sorted(EVALUATION_KEYS)} (IEC-CSO-EFR: when, the "
              f"determination, its basis and reason, and the federal customer data considered)")
    evaluated = parse_ts(ev["evaluated_at"], f"{where}.evaluation.evaluated_at")
    if evaluated < detected:
        _fail(f"{where}: evaluated before it was detected")
    if not isinstance(ev["reportable"], bool):
        _fail(f"{where}.evaluation.reportable must be true or false")
    _text(ev["reason"], f"{where}.evaluation.reason")
    _text(ev["federal_customer_data_considered"], f"{where}.evaluation.federal_customer_data_considered")
    if ev["basis"] not in BASES:
        _fail(f"{where}.evaluation.basis must be one of {list(BASES)}")
    findings = _strings(inc.get("findings", []), f"{where}.findings")
    if ev["basis"] in VULN_RULES:
        if ev["basis"] not in policy["adopted_vulnerability_rules"]:
            _fail(f"{where}: basis {ev['basis']} is not an adopted rule in policy.adopted_vulnerability_rules")
        if not ev["reportable"]:
            _fail(f"{where}: a vulnerability treated as a FedRAMP Reportable Incident under {ev['basis']} is reportable")
        if not findings:
            _fail(f"{where}: basis {ev['basis']} names no finding")

    if not isinstance(inc["estimates"], list) or not isinstance(inc["reports"], list):
        _fail(f"{where}: estimates and reports must be lists")
    if not ev["reportable"] and (inc["estimates"] or inc["reports"]):
        _fail(f"{where}: not a FedRAMP Reportable Incident, so it carries no rating or report")
    last = detected
    for i, e in enumerate(inc["estimates"]):
        at = _validate_estimate(e, f"{where}.estimates[{i}]", rubric, detected)
        if at < last:
            _fail(f"{where}.estimates are not in time order")
        last = at

    resolved = parse_ts(inc["resolved_at"], f"{where}.resolved_at") if "resolved_at" in inc else None
    recovered = (parse_ts(inc["recovery_complete_at"], f"{where}.recovery_complete_at")
                 if "recovery_complete_at" in inc else None)
    if recovered and not resolved:
        _fail(f"{where}: recovery is complete but the incident is not resolved")
    if resolved and resolved < detected or recovered and resolved and recovered < resolved:
        _fail(f"{where}: resolved_at / recovery_complete_at are out of order")

    reports = inc["reports"]
    prev = evaluated
    for i, r in enumerate(reports):
        w = f"{where}.reports[{i}]"
        if not isinstance(r, dict) or set(r) - REPORT_KEYS or {"type", "at"} - set(r):
            _fail(f"{w} must have type, at and optionally set")
        if r["type"] not in REPORT_TYPES:
            _fail(f"{w}.type must be one of {list(REPORT_TYPES)}")
        want = "Initial" if i == 0 else None
        if want and r["type"] != want:
            _fail(f"{where}: the first report is the Initial Incident Report (IEC-CSO-IIR)")
        if i > 0 and r["type"] == "Initial":
            _fail(f"{where}: only the first report is Initial")
        if r["type"] == "Final" and i != len(reports) - 1:
            _fail(f"{where}: nothing follows the Final Incident Report")
        at = parse_ts(r["at"], f"{w}.at")
        if at < prev:
            _fail(f"{w}.at is before the evaluation or the previous report")
        prev = at
        if "set" in r:
            _validate_set(r["set"], w)
        elif r["type"] == "Initial":
            _fail(f"{w}: the Initial report sets at least the description")
    if reports and "description" not in reports[0].get("set", {}):
        _fail(f"{where}: the Initial report must describe the incident (IEC-CSO-IIR)")
    if reports and reports[-1]["type"] == "Final":
        if not recovered:
            _fail(f"{where}: a Final Incident Report needs resolved_at and recovery_complete_at (IEC-CSO-FIR)")
        if parse_ts(reports[-1]["at"], "") < recovered:
            _fail(f"{where}: the Final report is dated before recovery completed")

    if now is not None:
        stamps = [started, detected, evaluated, resolved, recovered]
        stamps += [parse_ts(e["estimated_at"], "") for e in inc["estimates"]]
        stamps += [parse_ts(r["at"], "") for r in reports]
        if any(t and t > now for t in stamps):
            _fail(f"{where} records a time after now; a report cannot be issued in the future")


def validate(doc, where="data/incidents.json", now=None, rules_dir=_rules.RULES_DIR):
    """Structural and rule checks, enforced at build time without a jsonschema
    dependency. `now` (aware datetime), when given, also refuses future times."""
    if not isinstance(doc, dict) or doc.get("schema") != "incidents/1":
        _fail(f"{where} is not an incidents/1 document")
    if set(doc) - TOP_KEYS or {"schema", "policy", "incidents"} - set(doc):
        _fail(f"{where}: top-level fields must be {sorted(TOP_KEYS)}")
    _validate_policy(doc["policy"], where)
    if not isinstance(doc["incidents"], list):
        _fail(f"{where}: incidents must be a list")
    rubric = _rules.incident_rating_rubric(rules_dir)
    seen = set()
    for i, inc in enumerate(doc["incidents"]):
        _validate_incident(inc, f"{where} incidents[{i}]", doc["policy"], rubric, now)
        if inc["id"] in seen:
            _fail(f"{where}: duplicate id {inc['id']}")
        seen.add(inc["id"])
    _published_text_ok(doc, where)
    return doc


def load(path=None, now=None, rules_dir=_rules.RULES_DIR):
    p = Path(path) if path else DEFAULT_PATH
    if not p.is_file():
        _fail(f"{p} not found")
    try:
        doc = json.loads(p.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{p} is not valid JSON: {exc}")
    return validate(doc, str(p), now=now, rules_dir=rules_dir)


# ---- ratings and clocks -------------------------------------------------------

def add_clock(start, unit, n):
    """`start` plus n hours, or n business days. A business day here is Monday to
    Friday in UTC; federal holidays are counted as business days, which can only
    make a deadline earlier, never later."""
    if unit == "hours":
        return start + timedelta(hours=n)
    if unit == "bizdays":
        t, left = start.astimezone(timezone.utc), n
        while left:
            t += timedelta(days=1)
            if t.weekday() < 5:
                left -= 1
        return t
    _fail(f"unknown clock unit {unit!r}")


def rating_at(inc, t, default):
    """(N-rating, basis) in force at time t: the latest Incident Rating estimate
    made by then (IEC-CSO-EFI), else the default (IEC-CSO-DPR)."""
    best = None
    for e in inc["estimates"]:
        if parse_ts(e["estimated_at"], "") <= t:
            best = e
    if best is None:
        return default, "default (IEC-CSO-DPR)"
    return best["rating"], f"estimated (IEC-CSO-EFI) at {best['estimated_at']}"


def rating_history(inc, default, until=None):
    """[(when, rating, basis)] from evaluation through `until` (inclusive)."""
    out = [(inc["evaluation"]["evaluated_at"], default, "default (IEC-CSO-DPR)")]
    for e in inc["estimates"]:
        if until is None or parse_ts(e["estimated_at"], "") <= until:
            out.append((e["estimated_at"], e["rating"], f"estimated (IEC-CSO-EFI): {e['reason']}"))
    return out


def _obligation(kind, due, report, index, now):
    met_at = parse_ts(report["at"], "") if report else None
    return {"report": kind, "due_at": due.isoformat(), "report_index": index,
            "issued_at": report["at"] if report else None,
            "on_time": (met_at <= due) if report else None,
            "overdue": (report is None and now > due)}


def obligations(inc, timeframes, default, now):
    """Every report the Class C clocks call for, in order, and whether each was
    issued by its deadline. The last entry with report_index None is the one
    still due. Not reportable: no obligations."""
    if not inc["evaluation"]["reportable"]:
        return []
    reports = inc["reports"]
    resolved = parse_ts(inc["resolved_at"], "") if "resolved_at" in inc else None
    recovered = parse_ts(inc["recovery_complete_at"], "") if "recovery_complete_at" in inc else None
    evaluated = parse_ts(inc["evaluation"]["evaluated_at"], "")

    def due(kind, start):
        return add_clock(start, *timeframes[kind][rating_at(inc, start, default)[0]])

    out = [_obligation("Initial", due("iir", evaluated), reports[0] if reports else None, 0 if reports else None, now)]
    if not reports:
        return out
    i, prev = 1, parse_ts(reports[0]["at"], "")
    while True:
        oir_due = due("oir", prev)
        if resolved is not None and resolved <= oir_due:
            # Resolved before the next Ongoing report fell due: any further
            # Ongoing reports are voluntary, and the Final report's clock starts
            # when recovery completes (IEC-CSO-FIR).
            while i < len(reports) and reports[i]["type"] == "Ongoing":
                i += 1
            if recovered is not None:
                final = reports[i] if i < len(reports) else None
                out.append(_obligation("Final", due("fir", recovered), final, i if final else None, now))
            return out
        nxt = reports[i] if i < len(reports) and reports[i]["type"] == "Ongoing" else None
        out.append(_obligation("Ongoing", oir_due, nxt, i if nxt else None, now))
        if nxt is None:
            return out
        prev, i = parse_ts(nxt["at"], ""), i + 1


def status(inc):
    if not inc["evaluation"]["reportable"]:
        return "not-reportable"
    if inc["reports"] and inc["reports"][-1]["type"] == "Final":
        return "closed"
    if "resolved_at" in inc:
        return "resolved"
    return "open"


def open_findings(reg, include_exercises=False):
    """{finding or CVE: incident id} named by incidents that are not yet resolved."""
    out = {}
    for inc in reg["incidents"]:
        if inc["exercise"] and not include_exercises:
            continue
        if status(inc) == "open":
            for f in inc.get("findings", []):
                out[f] = inc["id"]
    return out
