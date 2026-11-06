"""Key Security Indicators that do not apply: data/ksi-applicability.json.

A KSI's status is computed from its checks (scripts/build-sdr.py), except a KSI
that does not apply to this system at all. Such a scope cut is a record here:
why, who proposed it, and the operator's approval. Only the operator approves
(CLAUDE.md, proof-of-concept latitude): `approval.by` is his name, written on
his word.

A listed KSI is left out the way the impact filter leaves out a KSI of another
baseline: the inventory (scripts/build-ksi-signal.py) carries no result for it,
and the SDR (scripts/build-sdr.py) neither counts methods for it nor asks the
inventory for one, but publishes it with its reason and approval. The claim
check (scripts/_frr.py --claims) fails while a listed KSI is not approved.

Stdlib only, fail-closed.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _frr  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PATH = REPO / "data" / "ksi-applicability.json"
CATALOG_PATH = REPO / "infrastructure" / "schemas" / "ksi-catalog.json"
TOP_KEYS = {"$schema", "$comment", "schema", "ksis"}
ENTRY_KEYS = {"ksi_id", "status", "not_applicable", "proposal", "approval"}
KSI_RE = re.compile(r"^KSI-[A-Z]{3}-[A-Z]{3}$")


def _fail(msg):
    raise SystemExit(f"::error::KSI applicability: {msg} (fail-closed)")


def catalog_ids(path=CATALOG_PATH):
    cat = json.loads(Path(path).read_text())
    return {i["id"] for f in cat["KSI"].values() for i in f["indicators"]}


def validate(doc, known, where="data/ksi-applicability.json"):
    if not isinstance(doc, dict) or doc.get("schema") != "ksi-applicability/1":
        _fail(f"{where} is not a ksi-applicability/1 document")
    if set(doc) - TOP_KEYS:
        _fail(f"{where}: unknown top-level field(s) {sorted(set(doc) - TOP_KEYS)}")
    entries = doc.get("ksis")
    if not isinstance(entries, list):
        _fail(f"{where}: ksis must be a list")
    seen = set()
    for e in entries:
        kid = e.get("ksi_id") if isinstance(e, dict) else None
        if not isinstance(kid, str) or not KSI_RE.match(kid):
            _fail(f"{where}: an entry has no ksi_id")
        if kid in seen:
            _fail(f"duplicate entry for {kid}")
        seen.add(kid)
        if kid not in known:
            _fail(f"{kid} is not a KSI in the catalog")
        if set(e) - ENTRY_KEYS:
            _fail(f"{kid}: unknown field(s) {sorted(set(e) - ENTRY_KEYS)}")
        if e.get("status") != "Not Applicable":
            _fail(f"{kid}: status must be Not Applicable (every other KSI status is computed from its checks)")
        try:
            _frr._text(e, "not_applicable", kid)
            if "proposal" not in e:
                _fail(f"{kid}: proposal must be {{by, on}}")
            for k in ("proposal", "approval"):
                if k in e:
                    _frr._signoff_shape(e[k], f"{kid} {k}")
        except SystemExit as exc:
            _fail(str(exc).replace("::error::FRR records: ", "").replace(" (fail-closed)", ""))
        if e.get("approval") and e["approval"].get("by") != _frr.OPERATOR:
            _fail(f"{kid}: approval.by must be the operator ({_frr.OPERATOR}); anyone may propose, only the "
                  "operator approves")
    return doc


def load(path=None, catalog=None):
    p = Path(path) if path else DEFAULT_PATH
    if not p.is_file():
        _fail(f"{p} not found")
    try:
        doc = json.loads(p.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{p} is not valid JSON: {exc}")
    return validate(doc, catalog_ids(catalog or CATALOG_PATH), str(p))


def not_applicable(doc):
    """{KSI ID: entry} for every KSI recorded as not applying."""
    return {e["ksi_id"]: e for e in doc["ksis"]}


def claims(doc):
    """[(KSI ID, why)] for every scope cut the operator has not approved."""
    return [(e["ksi_id"], f"Not Applicable not approved by the operator ({_frr.OPERATOR})")
            for e in doc["ksis"] if not e.get("approval")]
