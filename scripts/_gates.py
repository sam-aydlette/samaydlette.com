#!/usr/bin/env python3
"""The governed gate-mode register (REQ-GAT-1, REQ-GAT-4, T53).

infrastructure/schemas/gate-modes.json records, for every check that implements
one of the method's gates G1-G7, the mode it runs in and the decision behind
that mode. Each gate script asks this module for its mode instead of carrying
one in code:

    block               a failure stops the build or the publication
    detect-and-recover  a failure is published, queued for a person and given a
                        recovery clock, and the run continues

The method's default for every gate is `block`. A different mode is a
deviation, so it needs a reason and a review date that has not passed. Every
entry, default or not, carries who decided it and when.

The loader fails closed. The build stops on a missing or unparseable file, an
entry without its decision fields, a non-default mode with no reason or a
lapsed review date, a check this module does not know, or a known check with no
entry. A mode cannot change without a decision record (T53), and a new check
cannot ship without a mode.

Stdlib only, imported the same way as _freshness:

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _gates
"""

import hashlib
import json
import os
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "infrastructure" / "schemas" / "gate-modes.json"

BLOCK = "block"
DETECT_AND_RECOVER = "detect-and-recover"
MODES = (BLOCK, DETECT_AND_RECOVER)
GATES = ("G1", "G2", "G3", "G4", "G5", "G6", "G7")

# Every check a gate script consults, with the gate it implements. A check here
# with no entry in the register, or an entry for a check not here, fails the load.
CHECKS = {
    "vdr.kev": "G1",
    "vdr.top-impact-lev-irv": "G2",
    "vdr.past-deadline": "G3",
    "vuln-gate.unhandled": "G3",
    "runtime-divergence.diverged": "G4",
    "reconcile.a": "G4",
    "reconcile.b": "G5",
    "reconcile.c": "G5",
    "reconcile.d": "G5",
    "reconcile.g": "G5",
    "reconcile.h": "G5",
    "reconcile.i": "G5",
    "reconcile.j": "G5",
    "reconcile.e": "G6",
    "reconcile.f": "G6",
    "reconcile.l": "G6",
    "reconcile.i.unreadable": "G7",
    "runtime-divergence.observer-fault": "G7",
    "detection.zap.missing": "G7",
    "detection.zap.stale": "G7",
    "detection.kev": "G7",
    "detection.epss": "G7",
    "detection.grype": "G7",
    "detection.dependabot": "G7",
    "detection.previous-vdr": "G7",
    "detection.checkov": "G7",
    "detection.tfsec": "G7",
}

TOP_KEYS = {"$schema", "version", "description", "method_reference", "checks"}
ENTRY_KEYS = {"check", "gate", "mode", "method_default", "reason", "decided_by", "decided_on", "review_by"}
REQUIRED_ENTRY_KEYS = ENTRY_KEYS - {"reason"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Set by the workflows. When present, every detect-and-recover event is appended
# here as one JSON line, and the nightly status beacon publishes them.
EVENTS_ENV = "GATE_EVENTS_FILE"

# An event's detail can carry scanner, AWS or signal text and is printed into a
# GitHub Actions log, which parses `::` commands: strip line breaks and `::`.
_SANITIZE = str.maketrans({"\r": " ", "\n": " ", "\x00": ""})


def _clean(text, limit=500):
    return str(text).translate(_SANITIZE).replace("::", ":")[:limit]


def _fail(where, msg):
    raise SystemExit(f"::error::gate-mode register {where}: {msg} (fail-closed; a gate's mode is a decision record, REQ-GAT-4)")


def _date(where, check, key, value):
    if not isinstance(value, str) or not DATE_RE.match(value):
        _fail(where, f"{check}: {key} must be an ISO date (YYYY-MM-DD), got {value!r}")
    try:
        return date.fromisoformat(value)
    except ValueError:
        _fail(where, f"{check}: {key} is not a real date: {value!r}")


def validate_gate_modes(cfg, where="(in memory)", today=None):
    today = today or datetime.now(timezone.utc).date()
    if not isinstance(cfg, dict):
        _fail(where, "not a JSON object")
    unknown = set(cfg) - TOP_KEYS
    if unknown:
        _fail(where, f"unknown keys {sorted(unknown)}")
    if not isinstance(cfg.get("version"), str) or not cfg["version"].strip():
        _fail(where, "version must be a non-empty string")
    entries = cfg.get("checks")
    if not isinstance(entries, list) or not entries:
        _fail(where, "checks must be a non-empty list")
    seen = {}
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            _fail(where, f"checks[{i}] is not an object")
        name = e.get("check", f"checks[{i}]")
        unknown, missing = set(e) - ENTRY_KEYS, REQUIRED_ENTRY_KEYS - set(e)
        if unknown or missing:
            _fail(where, f"{name}: unknown keys {sorted(unknown)}, missing keys {sorted(missing)}")
        if name not in CHECKS:
            _fail(where, f"{name} is not a check any gate implements")
        if name in seen:
            _fail(where, f"{name} is listed twice")
        if e["gate"] != CHECKS[name]:
            _fail(where, f"{name} implements {CHECKS[name]}, not {e['gate']!r}")
        for key in ("mode", "method_default"):
            if e[key] not in MODES:
                _fail(where, f"{name}: {key} must be one of {list(MODES)}, got {e[key]!r}")
        if e["method_default"] != BLOCK:
            _fail(where, f"{name}: the method's default for every gate is block")
        if not isinstance(e["decided_by"], str) or not e["decided_by"].strip():
            _fail(where, f"{name}: decided_by must name who decided the mode")
        _date(where, name, "decided_on", e["decided_on"])
        review_by = _date(where, name, "review_by", e["review_by"])
        if e["mode"] != e["method_default"]:
            if not isinstance(e.get("reason"), str) or not e["reason"].strip():
                _fail(where, f"{name}: mode {e['mode']} differs from the method default with no reason")
            if review_by < today:
                _fail(where, f"{name}: the decision to run in {e['mode']} lapsed on {e['review_by']}; "
                             "renew it or return the check to block")
        seen[name] = e
    absent = sorted(set(CHECKS) - set(seen))
    if absent:
        _fail(where, f"checks with no recorded mode: {absent}")
    return seen


def _override():
    """GATE_MODES_FILE points the loader at another register, for tests only. In
    CI the committed register is always used: a mode cannot be changed by an
    environment variable that bypasses the reviewed decision record."""
    p = os.environ.get("GATE_MODES_FILE")
    if p and os.environ.get("GITHUB_ACTIONS") == "true":
        _fail(p, "GATE_MODES_FILE is not honored in CI; edit infrastructure/schemas/gate-modes.json")
    return p


def load_gate_modes(path=None, today=None):
    """Load and validate the register. Returns {version, sha256, checks: {check: entry}}."""
    p = Path(path or _override() or DEFAULT_PATH)
    if not p.is_file():
        _fail(p, "not found")
    raw = p.read_bytes()
    try:
        cfg = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(p, f"not valid JSON: {exc}")
    checks = validate_gate_modes(cfg, p, today)
    return {"version": cfg["version"], "sha256": hashlib.sha256(raw).hexdigest(), "checks": checks}


def mode_of(register, check):
    if check not in register["checks"]:
        raise SystemExit(f"::error::gate-mode register has no entry for {check}")
    return register["checks"][check]["mode"]


def blocks(register, check):
    return mode_of(register, check) == BLOCK


def record_event(register, check, detail, now=None):
    """A detect-and-recover check failed: say so in the log and, when the
    workflow asks for it, append the event for the status beacon to publish."""
    entry = register["checks"][check]
    event = {"check": check, "gate": entry["gate"], "mode": entry["mode"],
             "detail": _clean(detail),
             "at": (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat()}
    print(f"::warning::{entry['gate']} {check} ({entry['mode']}): {event['detail']}", file=sys.stderr)
    path = os.environ.get(EVENTS_ENV)
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")
    return event


def published_view(register):
    """What an output records about the modes it ran under."""
    return {"version": register["version"], "sha256": register["sha256"],
            "checks": [{k: e[k] for k in ("check", "gate", "mode", "method_default", "review_by")}
                       for e in sorted(register["checks"].values(), key=lambda x: (x["gate"], x["check"]))]}


def read_events(path):
    """Events a run recorded, for the status beacon. Missing file: none."""
    p = Path(path)
    if not p.is_file():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            ev = json.loads(line)
            if isinstance(ev, dict) and ev.get("check") in CHECKS:
                out.append({"check": ev["check"], "gate": CHECKS[ev["check"]], "mode": _clean(ev.get("mode"), 40),
                            "detail": _clean(ev.get("detail", "")), "at": _clean(ev.get("at"), 40)})
    return out


if __name__ == "__main__":
    # `python3 scripts/_gates.py` validates the register; `... status FILE`
    # prints {gates, gate_events} for the nightly status beacon.
    reg = load_gate_modes()
    if len(sys.argv) >= 3 and sys.argv[1] == "status":
        print(json.dumps({"gates": {"version": reg["version"], "sha256": reg["sha256"]},
                          "gate_events": read_events(sys.argv[2])}))
    else:
        print(f"gate-mode register {reg['version']}: {len(reg['checks'])} checks, sha256 {reg['sha256'][:12]}")
