"""FedRAMP rules as data (REQ-RUL-1, REQ-RUL-2).

Timeframes are read from FedRAMP's machine-readable Consolidated Rules, vendored
at a pinned commit under infrastructure/schemas/fedramp-rules/, never typed into
code. The file's sha256 is checked against SOURCES.json on every load, and a
missing or malformed rule fails closed: a build with no deadlines is worse than
no build.
"""

import hashlib
import json
import re
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


def impact_levels(rules_dir=RULES_DIR):
    """The impact scale the rules define, lowest first ("N1".."N5"). A fully
    mitigated finding takes the first (REQ-PAI-1)."""
    rules, _ = load_rules(rules_dir)
    try:
        table = _rule(rules, "VDR", "VDR-TFR-PVR")["varies_by_class"][CERT_CLASS]["pain_timeframes"]
        levels = sorted(table, key=int)
    except (KeyError, TypeError, ValueError):
        _fail(f"VDR-TFR-PVR has no Class {CERT_CLASS.upper()} impact scale")
    if not levels:
        _fail("VDR-TFR-PVR Class C impact scale is empty")
    return [f"N{n}" for n in levels]


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


# The certification this system builds toward: FedRAMP 20x, Program path, Class C.
CERT_TYPE = "20x"
CERT_PATH = "Program"
_SCOPES = ("all", "20x")  # rule sections that can apply to a 20x certification


def _subset_applicability(family, scope, subset):
    """A subset's applicability block. Subsets of the 20x section are described
    in info["20x"].subsets where the family has one (CPO, FRC, IVV, SDR), and
    otherwise, like the cross-program section's, in info.subsets (VDR)."""
    info = family.get("info") or {}
    sections = [(info.get(scope) or {}).get("subsets")] if scope != "all" else []
    for where in [*sections, info.get("subsets")]:
        app = ((where or {}).get(subset) or {}).get("applicability")
        if isinstance(app, dict):
            return app
    return None


def applicable_provider_rules(rules_dir=RULES_DIR):
    """{rule ID: {"family", "name", "statement", "force"}} for every FedRAMP rule
    a provider must address for a 20x Program Class C certification (SDR-CSO-FRR).

    Applicability is read from the corpus's own subset metadata (types, paths,
    classes, affects), never from a list kept here, so a re-pinned corpus that
    adds or retires a rule changes the set. A subset in a 20x-relevant section
    with no applicability block fails closed: it can't be decided either way."""
    rules, _ = load_rules(rules_dir)
    frr = rules.get("FRR")
    if not isinstance(frr, dict) or not frr:
        _fail("no FRR section")
    out = {}
    for fam_id, family in sorted(frr.items()):
        for scope in _SCOPES:
            for subset, members in sorted(((family.get("data") or {}).get(scope) or {}).items()):
                app = _subset_applicability(family, scope, subset)
                if app is None:
                    _fail(f"FRR/{fam_id}/{scope}/{subset} has no applicability metadata")
                if not (CERT_TYPE in app.get("types", []) and CERT_PATH in app.get("paths", [])
                        and CERT_CLASS.upper() in app.get("classes", [])
                        and "Providers" in app.get("affects", [])):
                    continue
                for rid, rule in members.items():
                    if "Providers" not in (rule.get("affects") or []):
                        continue
                    cell = (rule.get("varies_by_class") or {}).get(CERT_CLASS, rule)
                    force, statement = cell.get("force"), cell.get("statement")
                    if not isinstance(force, str) or not isinstance(statement, str):
                        _fail(f"{rid} has no Class {CERT_CLASS.upper()} statement and force")
                    if rid in out:
                        _fail(f"{rid} appears twice in the corpus")
                    out[rid] = {"family": fam_id, "subset": subset, "name": rule.get("name", ""),
                                "statement": statement, "force": force}
    if not out:
        _fail("no provider rules apply; the applicability metadata has changed shape")
    return out


# ---- Incident Evaluation and Communication (IEC), Class C ---------------------
# The report clocks and the Incident Rating scale are FedRAMP's, read here from
# the pinned corpus like the remediation matrix above, never typed in.

INCIDENT_REPORTS = {"iir": "IEC-CSO-IIR", "oir": "IEC-CSO-OIR", "fir": "IEC-CSO-FIR"}
_CLOCK_UNITS = ("hours", "bizdays")


def _iec(rules, rule_id):
    try:
        return rules["FRR"]["IEC"]["data"]["all"]["CSO"][rule_id]
    except (KeyError, TypeError):
        _fail(f"{rule_id} not found at FRR/IEC/data/all/CSO")


def incident_report_timeframes(rules_dir=RULES_DIR):
    """{"iir"|"oir"|"fir": {1..5: (unit, n)}} for Class C, unit "hours" or
    "bizdays". Every impact level must carry every clock: a report with no
    deadline cannot be alarmed."""
    rules, _ = load_rules(rules_dir)
    out = {}
    for kind, rid in INCIDENT_REPORTS.items():
        try:
            table = _iec(rules, rid)["varies_by_class"][CERT_CLASS]["pain_timeframes"]
        except (KeyError, TypeError):
            _fail(f"{rid} has no Class {CERT_CLASS.upper()} pain_timeframes")
        clocks = {}
        for n in ("1", "2", "3", "4", "5"):
            cell = (table.get(n) or {}).get(kind)
            if not isinstance(cell, dict) or cell.get("timeframe_type") not in _CLOCK_UNITS \
                    or not isinstance(cell.get("timeframe_num"), int) or isinstance(cell["timeframe_num"], bool) \
                    or cell["timeframe_num"] <= 0:
                _fail(f"{rid} Class C N{n} {kind} is not a positive number of hours or business days")
            clocks[int(n)] = (cell["timeframe_type"], cell["timeframe_num"])
        out[kind] = clocks
    return out


_RATING_RE = re.compile(r"^\*\*N([1-5])\*\* for (.+)\.$")
_CLAUSE_RE = re.compile(r"likely (minimal|narrow|disruptive|debilitating) customer effect on "
                        r"(1 or more agencies|more than 1 agency|1 agency)")
_SCOPES_BY_TEXT = {"1 or more agencies": ("single", "multiple"), "1 agency": ("single",),
                   "more than 1 agency": ("multiple",)}


def incident_rating_rubric(rules_dir=RULES_DIR):
    """{(customer effect, "single"|"multiple" agencies): N-rating 1..5} from the
    IEC-CSO-EFI bullets. Every (effect, scope) pair must be rated exactly once,
    or the text has changed shape and the rubric is not trusted."""
    rules, _ = load_rules(rules_dir)
    bullets = _iec(rules, "IEC-CSO-EFI").get("following_information_bullets")
    if not isinstance(bullets, list) or not bullets:
        _fail("IEC-CSO-EFI has no rating bullets")
    out = {}
    for b in bullets:
        m = _RATING_RE.match(b) if isinstance(b, str) else None
        clauses = _CLAUSE_RE.findall(m.group(2)) if m else []
        if not clauses:
            _fail(f"IEC-CSO-EFI bullet {b!r} is not in the expected form")
        for effect, scope_text in clauses:
            for scope in _SCOPES_BY_TEXT[scope_text]:
                if (effect, scope) in out:
                    _fail(f"IEC-CSO-EFI rates {effect}/{scope} twice")
                out[(effect, scope)] = int(m.group(1))
    effects = ("minimal", "narrow", "disruptive", "debilitating")
    if set(out) != {(e, s) for e in effects for s in ("single", "multiple")}:
        _fail("IEC-CSO-EFI does not rate every customer effect for one and for several agencies")
    return out


def default_incident_rating(rules_dir=RULES_DIR):
    """IEC-CSO-DPR: the N-rating a FedRAMP Reportable Incident has until it is estimated."""
    rules, _ = load_rules(rules_dir)
    stmt = _iec(rules, "IEC-CSO-DPR").get("statement", "")
    m = re.search(r"\(PAIN\) of ([1-5])\b", stmt)
    if not m:
        _fail("IEC-CSO-DPR no longer states a default PAIN rating")
    return int(m.group(1))
