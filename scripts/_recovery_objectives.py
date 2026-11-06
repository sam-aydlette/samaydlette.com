"""The recovery objectives as data (KSI-RPL-RRO): data/recovery-objectives.json.

docs/recovery-plan.md states the recovery time objective (21 days) and the
recovery point objective (24 hours). The machines that test recovery read the
same numbers from here, so a drill cannot pass against an objective the plan
does not state: the Chaos Gremlin drill (scripts/hold-chaos-gremlin.py) and the
SDR's availability-rto method (scripts/_ksi_methods.py). Stdlib only,
fail-closed: a missing or malformed file stops the caller.
"""

import json
import re
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PATH = REPO / "data" / "recovery-objectives.json"
TOP_KEYS = {"$schema", "schema", "version", "description", "rto", "rpo", "source", "decided_by", "decided_on",
            "review_by", "rationale"}
SOURCE = "docs/recovery-plan.md"


def _fail(msg):
    raise SystemExit(f"::error::recovery objectives: {msg} (fail-closed)")


def _objective(doc, key):
    o = doc.get(key)
    if not isinstance(o, dict) or set(o) != {"hours", "stated"}:
        _fail(f"{key} must be {{hours, stated}}")
    h = o["hours"]
    if not isinstance(h, int) or isinstance(h, bool) or h < 1:
        _fail(f"{key}.hours must be a positive whole number of hours")
    if not isinstance(o["stated"], str) or not o["stated"].strip():
        _fail(f"{key}.stated must say how the recovery plan words it")
    return h


def validate(doc):
    if not isinstance(doc, dict) or doc.get("schema") != "recovery-objectives/1":
        _fail("not a recovery-objectives/1 document")
    if set(doc) - TOP_KEYS or TOP_KEYS - {"$schema"} - set(doc):
        _fail(f"fields must be {sorted(TOP_KEYS)}")
    for k in ("version", "description", "decided_by", "rationale"):
        if not isinstance(doc[k], str) or not doc[k].strip():
            _fail(f"{k} must be a non-empty string")
    if doc["source"] != SOURCE:
        _fail(f"source must be {SOURCE}")
    for k in ("decided_on", "review_by"):
        if not isinstance(doc[k], str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", doc[k]):
            _fail(f"{k} must be a YYYY-MM-DD date")
        date.fromisoformat(doc[k])
    rto, rpo = _objective(doc, "rto"), _objective(doc, "rpo")
    if rpo > rto:
        _fail("the recovery point objective is longer than the recovery time objective")
    return doc


def load(path=None):
    p = Path(path) if path else DEFAULT_PATH
    try:
        doc = json.loads(p.read_text())
    except FileNotFoundError:
        _fail(f"{p} not found")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{p} is not valid JSON: {exc}")
    return validate(doc)


def rto_hours(doc=None):
    return (doc or load())["rto"]["hours"]


def rpo_hours(doc=None):
    return (doc or load())["rpo"]["hours"]
