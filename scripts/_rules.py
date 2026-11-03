"""FedRAMP rules as data (REQ-RUL-1, REQ-RUL-2).

Timeframes are read from FedRAMP's machine-readable Consolidated Rules, vendored
at a pinned commit under infrastructure/schemas/fedramp-rules/, never typed into
code. The file's sha256 is checked against SOURCES.json on every load, and a
missing or malformed rule fails closed: a build with no deadlines is worse than
no build.
"""

import hashlib
import json
from functools import lru_cache
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent.parent / "infrastructure" / "schemas" / "fedramp-rules"
RULES_FILE = "fedramp-consolidated-rules.json"
CERT_CLASS = "c"

# FedRAMP's cell names → (likely exploitable, internet reachable). "nlev" applies
# whatever the reachability, so it fills both IRV and NIRV.
_CELLS = {"irv_lev": ((True, True),), "nirv_lev": ((True, False),), "nlev": ((False, True), (False, False))}


def _fail(msg):
    raise SystemExit(f"::error::FedRAMP rules: {msg} (fail-closed)")


@lru_cache(maxsize=8)
def _load(rules_dir):
    d = Path(rules_dir)
    try:
        sources = json.loads((d / "SOURCES.json").read_text())
        raw = (d / RULES_FILE).read_bytes()
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"cannot read the vendored rules in {d}: {exc}")
    for key in ("commit", "version", "sha256", "repository"):
        if not isinstance(sources.get(key), str) or not sources[key]:
            _fail(f"SOURCES.json lacks {key}")
    if len(sources["commit"]) != 40:
        _fail("the pin must be a full 40-character commit SHA")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != sources["sha256"]:
        _fail(f"{RULES_FILE} sha256 {digest} does not match the pinned {sources['sha256']}")
    try:
        rules = json.loads(raw)
    except json.JSONDecodeError as exc:
        _fail(f"{RULES_FILE} is not valid JSON: {exc}")
    return rules, sources


def load_rules(rules_dir=RULES_DIR):
    """(rules, sources) after the hash check."""
    return _load(str(rules_dir))


def pin(rules_dir=RULES_DIR):
    """What the report publishes about the rules it used."""
    _, s = load_rules(rules_dir)
    return {"source": s["repository"], "path": s.get("path", RULES_FILE),
            "commit": s["commit"], "version": s["version"], "sha256": s["sha256"]}


def _rule(rules, family, rule_id):
    try:
        return rules["FRR"][family]["data"]["all"]["TFR"][rule_id]
    except (KeyError, TypeError):
        _fail(f"{rule_id} not found at FRR/{family}/data/all/TFR")


def _days(cell, where):
    if not isinstance(cell, dict) or cell.get("timeframe_type") != "days" \
            or not isinstance(cell.get("timeframe_num"), int) or cell["timeframe_num"] <= 0:
        _fail(f"{where} is not a positive number of days")
    return cell["timeframe_num"]


def class_c_timeframes(rules_dir=RULES_DIR):
    """{(pain "N1".."N5", lev, irv): days} from VDR-TFR-PVR, Class C. N1 has no
    timeframe (mitigated during routine operations) and so no key."""
    rules, _ = load_rules(rules_dir)
    pvr = _rule(rules, "VDR", "VDR-TFR-PVR")
    try:
        table = pvr["varies_by_class"][CERT_CLASS]["pain_timeframes"]
    except (KeyError, TypeError):
        _fail(f"VDR-TFR-PVR has no Class {CERT_CLASS.upper()} pain_timeframes")
    out = {}
    for n in ("1", "2", "3", "4", "5"):
        if n not in table:
            _fail(f"VDR-TFR-PVR Class C has no N{n} row")
        row = table[n]
        if n == "1":
            if row:
                _fail("VDR-TFR-PVR Class C N1 unexpectedly carries timeframes; review before trusting")
            continue
        if set(row) != set(_CELLS):
            _fail(f"VDR-TFR-PVR Class C N{n} cells are {sorted(row)}, expected {sorted(_CELLS)}")
        for name, keys in _CELLS.items():
            days = _days(row[name], f"VDR-TFR-PVR Class C N{n} {name}")
            for lev, irv in keys:
                out[(f"N{n}", lev, irv)] = days
    return out


def _class_c_or_flat(rule, rule_id):
    cell = (rule.get("varies_by_class") or {}).get(CERT_CLASS, rule)
    return _days(cell, f"{rule_id} Class C")


def max_accepted_days(rules_dir=RULES_DIR):
    """VER-TFR-MAV: days from evaluation after which an unremediated vulnerability is accepted."""
    rules, _ = load_rules(rules_dir)
    return _class_c_or_flat(_rule(rules, "VER", "VER-TFR-MAV"), "VER-TFR-MAV")


def evaluation_days(rules_dir=RULES_DIR):
    """VER-TFR-EVU: days from detection within which every vulnerability is evaluated."""
    rules, _ = load_rules(rules_dir)
    return _class_c_or_flat(_rule(rules, "VER", "VER-TFR-EVU"), "VER-TFR-EVU")
