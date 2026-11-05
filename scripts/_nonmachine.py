"""Non-machine information resources and their verification (VDR-TFR-NMV).

Providers MUST verify and validate the status of non-machine-based information
resources at least once every 3 months. data/non-machine-resources.json lists
them (policies, procedures, plans, the operator role, records and registers);
each entry's last_verified names the decision record in which the operator
attests that verification. People do the verifying; this module checks that
the attestation exists, is in force and is no older than the register's
max_age_days, that every listed file still exists, and that no policy or
runbook was added without an entry.

Fails closed: a missing or malformed register is an error, never an empty list.
"""

import json
import re
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PATH = REPO / "data" / "non-machine-resources.json"
TOP_KEYS = {"$schema", "$comment", "schema", "max_age_days", "resources"}
ENTRY_KEYS = {"id", "path", "kind", "title", "owner", "verifies", "last_verified"}
KINDS = {"policy", "procedure", "plan", "role", "record", "register"}
ID_RE = re.compile(r"^NMR-[A-Z0-9-]+$")
DEC_RE = re.compile(r"^DEC-\d{3}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# The rule's "at least once every 3 months": the longest three calendar months.
RULE_MAX_DAYS = 92
# Directories whose every Markdown file is a non-machine resource that must be listed.
MUST_LIST = (("docs/policies", {"README.md"}), ("docs/runbooks", set()))


def _fail(msg):
    raise SystemExit(f"::error::non-machine resources: {msg} (fail-closed)")


def validate(doc, where="data/non-machine-resources.json"):
    if not isinstance(doc, dict) or doc.get("schema") != "non-machine-resources/1":
        _fail(f"{where} is not a non-machine-resources/1 document")
    if set(doc) - TOP_KEYS:
        _fail(f"{where}: unknown field(s) {sorted(set(doc) - TOP_KEYS)}")
    m = doc.get("max_age_days")
    if not isinstance(m, int) or isinstance(m, bool) or not 1 <= m <= RULE_MAX_DAYS:
        _fail(f"{where}: max_age_days must be an integer from 1 to {RULE_MAX_DAYS}")
    res = doc.get("resources")
    if not isinstance(res, list) or not res:
        _fail(f"{where}: resources must be a non-empty list")
    seen = set()
    for e in res:
        rid = e.get("id") if isinstance(e, dict) else None
        if not isinstance(rid, str) or not ID_RE.match(rid) or rid in seen:
            _fail(f"{where}: entry id {rid!r} is not a unique NMR-...")
        seen.add(rid)
        if set(e) != ENTRY_KEYS:
            _fail(f"{rid}: fields must be exactly {sorted(ENTRY_KEYS)}")
        if e["kind"] not in KINDS:
            _fail(f"{rid}: kind {e['kind']!r} is not one of {sorted(KINDS)}")
        for k in ("path", "title", "owner", "verifies"):
            if not isinstance(e[k], str) or not e[k].strip():
                _fail(f"{rid}: {k} must be a non-empty string")
        lv = e["last_verified"]
        if (not isinstance(lv, dict) or set(lv) != {"on", "decision"}
                or not DATE_RE.match(str(lv.get("on"))) or not DEC_RE.match(str(lv.get("decision")))):
            _fail(f"{rid}: last_verified must be {{on: YYYY-MM-DD, decision: DEC-NNN}}")
    return doc


def load(path=None):
    p = Path(path) if path else DEFAULT_PATH
    if not p.is_file():
        _fail(f"{p} not found")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{p} is not valid JSON: {exc.__class__.__name__}")
    return validate(doc, str(p))


def problems(doc, decisions, today, repo=REPO):
    """Every reason the register does not show a current verification, as
    strings; empty when every resource was verified within max_age_days under
    an in-force decision. `decisions` is a loaded decisions/1 register."""
    recs = {r["id"]: r for r in decisions["decisions"]}
    out = []
    limit = doc["max_age_days"]
    listed = {e["path"] for e in doc["resources"]}
    for e in doc["resources"]:
        rid, lv = e["id"], e["last_verified"]
        if not (repo / e["path"]).is_file():
            out.append(f"{rid}: {e['path']} does not exist")
        on = date.fromisoformat(lv["on"])
        if on > today:
            out.append(f"{rid}: last verified {lv['on']}, after today")
        elif (today - on).days > limit:
            out.append(f"{rid}: last verified {lv['on']}, {(today - on).days} days ago (more than {limit})")
        d = recs.get(lv["decision"])
        if d is None:
            out.append(f"{rid}: {lv['decision']} is not in the decision register")
        elif d.get("status") != "in-force":
            out.append(f"{rid}: {lv['decision']} is not in force")
        elif d.get("review_by", "") < today.isoformat():
            out.append(f"{rid}: {lv['decision']} lapsed on {d['review_by']}")
        elif d.get("decided_on") != lv["on"]:
            out.append(f"{rid}: verified {lv['on']} but {lv['decision']} was decided {d.get('decided_on')}")
    for folder, skip in MUST_LIST:
        for p in sorted((repo / folder).glob("*.md")):
            rel = f"{folder}/{p.name}"
            if p.name not in skip and rel not in listed:
                out.append(f"{rel} has no entry in the register")
    return out


def status(doc, decisions, today, now=None):
    """The published status (/.well-known/vdr-non-machine-vv.json). verifiedAt is
    the OLDEST verification, so the freshness window lapses with the first
    resource that falls out of date."""
    now = now or datetime.now(timezone.utc)
    probs = problems(doc, decisions, today)
    oldest = min(date.fromisoformat(e["last_verified"]["on"]) for e in doc["resources"])
    return {
        "schema": "non-machine-vv/1",
        "rule": "VDR-TFR-NMV",
        "generatedAt": now.isoformat(),
        "verifiedAt": datetime.combine(oldest, time(0, tzinfo=timezone.utc)).isoformat(),
        "nextDueBy": (oldest + timedelta(days=doc["max_age_days"])).isoformat(),
        "maxAgeDays": doc["max_age_days"],
        "status": "ok" if not probs else "lapsed",
        "problems": probs,
        "source": "data/non-machine-resources.json",
        "resources": [{"id": e["id"], "kind": e["kind"], "title": e["title"], "path": e["path"],
                       "owner": e["owner"], "verifies": e["verifies"],
                       "lastVerified": e["last_verified"]["on"], "decision": e["last_verified"]["decision"]}
                      for e in doc["resources"]],
    }
