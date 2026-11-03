#!/usr/bin/env python3
"""The governed freshness windows (REQ-PUB-2, REQ-GOV-1).

infrastructure/schemas/freshness-config.json sets the maximum age of every
output published under /.well-known/. This loader is the one Python reader of
it: scripts/build-trust-center.py and scripts/check-evidence-freshness.py both
use it, and the watchdog (infrastructure/watchdog/logic.mjs) applies the same
rules in node. Terraform reads the file with jsondecode(), so a missing entry
fails the plan.

It fails closed. A missing, unparseable or invalid file stops the caller; there
is no built-in default to fall back to, which is what keeps the windows
governed. Stdlib only, so every caller stays standalone-runnable; the JSON
schema beside the config is enforced in tests, and the checks below are the
subset that matters at run time.

Imported the same way as _common:

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _freshness import load_freshness_config
"""

import hashlib
import json
import re
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "infrastructure" / "schemas" / "freshness-config.json"

# Artifacts a consumer reads a window for. Each must be listed, or the config is
# invalid: a reader that silently found no window would have nothing to enforce.
REQUIRED = (
    ".well-known/vdr-report.json",
    ".well-known/ksi-signal-runtime.json",
    ".well-known/vdr-status.json",
    ".well-known/boundary-corroboration.json",
)

TOP_KEYS = {"$schema", "version", "description", "decided_by", "decided_on", "review_by", "rationale", "artifacts"}
ARTIFACT_KEYS = {"path", "cadence", "max_age_hours", "timestamp", "signed", "signature", "note"}
CADENCES = {"nightly", "runtime", "deploy", "operator"}
PATH_RE = re.compile(r"^\.well-known/[A-Za-z0-9][A-Za-z0-9._-]*$")
FIELD_RE = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_WINDOW_HOURS = 8760


def _fail(where, msg):
    raise SystemExit(f"::error::freshness config {where}: {msg} (fail-closed; the windows are governed, never defaulted)")


def _check_artifact(where, i, a):
    if not isinstance(a, dict):
        _fail(where, f"artifacts[{i}] is not an object")
    unknown = set(a) - ARTIFACT_KEYS
    missing = {"path", "cadence", "max_age_hours", "timestamp", "signed"} - set(a)
    if unknown or missing:
        _fail(where, f"artifacts[{i}] unknown keys {sorted(unknown)}, missing keys {sorted(missing)}")
    path = a["path"]
    if not isinstance(path, str) or not PATH_RE.match(path) or ".." in path:
        _fail(where, f"artifacts[{i}].path must be one object directly under .well-known/, got {path!r}")
    if "signature" in a and (not isinstance(a["signature"], str) or not PATH_RE.match(a["signature"]) or ".." in a["signature"]):
        _fail(where, f"{path}: signature must be one object directly under .well-known/")
    if a["cadence"] not in CADENCES:
        _fail(where, f"{path}: cadence must be one of {sorted(CADENCES)}")
    w = a["max_age_hours"]
    if isinstance(w, bool) or not isinstance(w, (int, float)) or not 0 < w <= MAX_WINDOW_HOURS:
        _fail(where, f"{path}: max_age_hours must be a number in (0, {MAX_WINDOW_HOURS}], got {w!r}")
    if not isinstance(a["signed"], bool):
        _fail(where, f"{path}: signed must be true or false")
    ts = a["timestamp"]
    ok = isinstance(ts, dict) and (
        (ts.get("source") == "last_modified" and set(ts) == {"source"})
        or (ts.get("source") == "json" and set(ts) == {"source", "field"}
            and isinstance(ts.get("field"), str) and FIELD_RE.match(ts["field"])))
    if not ok:
        _fail(where, f"{path}: timestamp must be {{source: json, field: a.b}} or {{source: last_modified}}, got {ts!r}")


def validate_freshness_config(cfg, where="(in memory)"):
    if not isinstance(cfg, dict):
        _fail(where, "not a JSON object")
    unknown = set(cfg) - TOP_KEYS
    if unknown:
        _fail(where, f"unknown keys {sorted(unknown)}")
    for key in ("version", "decided_by", "rationale"):
        if not isinstance(cfg.get(key), str) or not cfg[key].strip():
            _fail(where, f"{key} must be a non-empty string")
    for key in ("decided_on", "review_by"):
        if not isinstance(cfg.get(key), str) or not DATE_RE.match(cfg[key]):
            _fail(where, f"{key} must be an ISO date (YYYY-MM-DD)")
    arts = cfg.get("artifacts")
    if not isinstance(arts, list) or not arts:
        _fail(where, "artifacts must be a non-empty list")
    seen = set()
    for i, a in enumerate(arts):
        _check_artifact(where, i, a)
        if a["path"] in seen:
            _fail(where, f"{a['path']} is listed twice")
        seen.add(a["path"])
    absent = [p for p in REQUIRED if p not in seen]
    if absent:
        _fail(where, f"required artifacts not listed: {absent}")


def load_freshness_config(path=None):
    """Load and validate the governed config. Returns the parsed config plus
    `sha256` (of the file's bytes, for recording which version an output used)
    and `windows` ({path: max_age_hours})."""
    p = Path(path) if path else DEFAULT_PATH
    if not p.is_file():
        _fail(p, "not found")
    raw = p.read_bytes()
    try:
        cfg = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(p, f"not valid JSON: {exc}")
    validate_freshness_config(cfg, p)
    cfg["sha256"] = hashlib.sha256(raw).hexdigest()
    cfg["windows"] = {a["path"]: a["max_age_hours"] for a in cfg["artifacts"]}
    return cfg


def artifact_for(cfg, name):
    """The listed artifact whose object name is `name` (a key, URL or file path
    ending in it), or None."""
    base = str(name).rstrip("/").rsplit("/", 1)[-1]
    return next((a for a in cfg["artifacts"] if a["path"] == f".well-known/{base}"), None)


def timestamp_of(artifact, raw, last_modified=None):
    """The ISO timestamp an artifact's age is measured from: the configured JSON
    field, or the object's last-modified time. None when it is absent."""
    ts = artifact["timestamp"]
    if ts["source"] == "last_modified":
        return last_modified
    node = json.loads(raw)
    for part in ts["field"].split("."):
        node = node.get(part) if isinstance(node, dict) else None
    return node if isinstance(node, str) and node else None
