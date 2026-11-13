"""The decision register: data/decisions.json (CR26; replaces the POA&M).

Every human decision about a finding lives here, once: a false positive, an
accepted risk, an operational requirement, a mitigation or a vendor dependency,
and the remediated items kept as history. Each record has a stable ID
(DEC-NNN), the decision fields (decided_by, decided_on, review_by), and what it
applies to: scanner check IDs (Checkov/tfsec), vulnerability IDs
(CVE/GHSA/scanner tracking ID), and the resources it names.

The VDR builder, the vulnerability gate, reconciliation and the trust center all
read it through this module, so they cannot disagree about what a decision
covers. Records carried over from the POA&M keep their old ID in `former_id`.

Fails closed: a missing or invalid register stops the build. A register that
silently read as empty would turn every handled finding into an open one, or
worse, a check that resolves to no decision into a passing one.
"""

import json
import re
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PATH = REPO / "data" / "decisions.json"
SCHEMA_PATH = REPO / "infrastructure" / "schemas" / "decisions.schema.json"

ID_RE = re.compile(r"^DEC-\d{3}$")
FORMER_RE = re.compile(r"^POAM-\d{3}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Dispositions of an in-force record. Config-scanner suppressions use
# risk-accepted / false-positive; vulnerabilities use the triage vocabulary.
IN_FORCE = ("false-positive", "risk-accepted", "accepted", "operational-requirement", "mitigated",
            "vendor-dependency", "under-investigation", "remediate")
CLOSED = ("remediated",)
DECISION_FIELDS = ("decided_by", "decided_on", "review_by")
# The fields infrastructure/schemas/decisions.schema.json allows. An unknown
# field is refused: a misspelt review_by would otherwise read as absent.
TOP_KEYS = {"$comment", "_note", "schema", "decisions"}
RECORD_KEYS = {"id", "former_id", "title", "status", "disposition", "justification", *DECISION_FIELDS, "accepted_by",
               "closed_on", "original_detection_date", "planned_completion", "remediation_plan",
               "vendor_dependency", "point_of_contact", "controls", "applies_to", "vuln_fields", "source"}
APPLIES_KEYS = {"check_ids", "vuln_ids", "resources"}


def _fail(msg):
    raise SystemExit(f"::error::decision register: {msg} (fail-closed)")


def validate(doc, where="data/decisions.json"):
    """Structural checks the schema states, enforced at build time without a
    jsonschema dependency (the deploy job installs none)."""
    if not isinstance(doc, dict) or doc.get("schema") != "decisions/1":
        _fail(f"{where} is not a decisions/1 document")
    if set(doc) - TOP_KEYS:
        _fail(f"{where}: unknown top-level field(s) {sorted(set(doc) - TOP_KEYS)}")
    recs = doc.get("decisions")
    if not isinstance(recs, list) or not recs:
        _fail(f"{where}: decisions must be a non-empty list")
    seen, former, claims = set(), set(), {}
    for r in recs:
        rid = r.get("id") if isinstance(r, dict) else None
        if not isinstance(rid, str) or not ID_RE.match(rid):
            _fail(f"{where}: record id {rid!r} is not DEC-NNN")
        if rid in seen:
            _fail(f"{where}: duplicate id {rid}")
        seen.add(rid)
        if set(r) - RECORD_KEYS:
            _fail(f"{rid}: unknown field(s) {sorted(set(r) - RECORD_KEYS)}")
        if r.get("former_id") is not None:
            if not FORMER_RE.match(str(r["former_id"])) or r["former_id"] in former:
                _fail(f"{rid}: former_id {r['former_id']!r} is not a unique POAM-NNN")
            former.add(r["former_id"])
        for k in ("title", "justification"):
            if not isinstance(r.get(k), str) or not r[k].strip():
                _fail(f"{rid}: {k} must be a non-empty string")
        status, disp = r.get("status"), r.get("disposition")
        if status == "in-force":
            if disp not in IN_FORCE:
                _fail(f"{rid}: in-force disposition {disp!r} is not one of {list(IN_FORCE)}")
            for k in DECISION_FIELDS:
                if not isinstance(r.get(k), str) or not r[k].strip():
                    _fail(f"{rid}: an in-force decision needs {k}")
            for k in ("decided_on", "review_by"):
                if not DATE_RE.match(r[k]):
                    _fail(f"{rid}: {k} must be an ISO date")
        elif status == "closed":
            if disp not in CLOSED:
                _fail(f"{rid}: a closed record's disposition must be one of {list(CLOSED)}")
            for k in ("closed_on", "decided_on", "review_by"):
                if k in r and not (isinstance(r[k], str) and DATE_RE.match(r[k])):
                    _fail(f"{rid}: {k} must be an ISO date")
        else:
            _fail(f"{rid}: status must be in-force or closed")
        applies = r.get("applies_to")
        if not isinstance(applies, dict) or set(applies) - APPLIES_KEYS:
            _fail(f"{rid}: applies_to must be an object with only {sorted(APPLIES_KEYS)}")
        for k in sorted(APPLIES_KEYS):
            v = applies.get(k, [])
            if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
                _fail(f"{rid}: applies_to.{k} must be a list of strings")
        if status == "in-force":
            # One check or vulnerability ID resolves to exactly one in-force decision.
            for k in ("check_ids", "vuln_ids"):
                for x in applies.get(k, []):
                    if x in claims:
                        _fail(f"{x!r} is claimed by both {claims[x]} and {rid}")
                    claims[x] = rid
    return doc


def load(path=None):
    p = Path(path) if path else DEFAULT_PATH
    if not p.is_file():
        _fail(f"{p} not found")
    try:
        doc = json.loads(p.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{p} is not valid JSON: {exc}")
    return validate(doc, str(p))


def records(reg):
    """{DEC id: record}."""
    return {r["id"]: r for r in reg["decisions"]}


def in_force(reg):
    return [r for r in reg["decisions"] if r["status"] == "in-force"]


def by_any_id(reg):
    """{DEC id or former POAM id: record}, for resolving a reference in text."""
    out = {}
    for r in reg["decisions"]:
        out[r["id"]] = r
        if r.get("former_id"):
            out[r["former_id"]] = r
    return out


def check_maps(reg):
    """({check_id: DEC id} for risk-accepted suppressions,
        {check_id: DEC id} for false-positive suppressions)."""
    accepted, false_pos = {}, {}
    for r in in_force(reg):
        target = {"risk-accepted": accepted, "false-positive": false_pos}.get(r["disposition"])
        if target is None:
            continue
        for c in r["applies_to"].get("check_ids", []):
            target[c] = r["id"]
    return accepted, false_pos


def false_positive_checks(reg):
    return set(check_maps(reg)[1])


def vuln_register(reg):
    """{vuln_id: entry} in the shape the triage policy and the vulnerability gate
    read: disposition, justification, decision_id, the decision fields, and any
    vulnerability-specific fields the record carries (e.g. mitigation)."""
    out = {}
    for r in in_force(reg):
        for v in r["applies_to"].get("vuln_ids", []):
            entry = {"disposition": r["disposition"], "justification": r["justification"],
                     "decision_id": r["id"], **{k: r[k] for k in DECISION_FIELDS}}
            entry.update(r.get("vuln_fields") or {})
            out[v] = entry
    return out


def decision_fields(reg):
    """{DEC id: {decided_by, decided_on, review_by}} for every in-force record."""
    return {r["id"]: {k: r[k] for k in DECISION_FIELDS} for r in in_force(reg)}


def detection_dates(reg):
    """{DEC id: ISO datetime} from each record's original detection date (REQ-SRC-1)."""
    out = {}
    for r in reg["decisions"]:
        d = r.get("original_detection_date")
        if isinstance(d, str) and DATE_RE.match(d):
            out[r["id"]] = f"{d}T00:00:00+00:00"
    return out


def review_due(reg, today=None):
    """In-force records whose review_by has passed."""
    today = today or date.today()
    return [r for r in in_force(reg) if date.fromisoformat(r["review_by"]) < today]
