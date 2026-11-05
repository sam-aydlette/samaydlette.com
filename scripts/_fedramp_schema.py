"""Validate CR26 reports against FedRAMP's 2026-06-24 JSON schemas (FRC-CSO-JSN).

The nine schemas are vendored verbatim in infrastructure/schemas/fedramp-2026-06-24/
with their sha256s in SOURCES.json. Every builder of a CR26 report calls
write_validated(), which validates the document, stamps nothing, and writes it
only if it passes. A report that does not validate is never written, so it can
never be signed or published.

Why not the jsonschema package: the deploy job installs no Python packages; its
builders run on the runner's own interpreter. This module implements the subset
of JSON Schema draft 2020-12 these schemas use, and fails closed on any keyword
it does not implement, so a new schema version that uses one cannot be
half-checked. tests/test_fedramp_schema.py checks it against jsonschema (a dev
dependency) on good and known-bad documents.

Formats are asserted, not merely annotated: date, date-time, email and uri. That
is stricter than jsonschema's default and matches what storycheck checks.
"""

import hashlib
import json
import re
import sys
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO / "infrastructure" / "schemas" / "fedramp-2026-06-24"
BASES = ("https://fedramp.gov/schemas/", "https://www.fedramp.gov/schemas/")

# The report types this repo publishes, by FedRAMP schema file.
SCHEMAS = {
    "cpo": "fedramp-certification-package-overview-schema-2026-06-24.json",
    "sdr": "fedramp-security-decision-record-schema-2026-06-24.json",
    "vdt": "fedramp-vulnerability-detail-report-schema-2026-06-24.json",
    "avi": "fedramp-accepted-vulnerability-info-schema-2026-06-24.json",
    "mrh": "fedramp-historical-ver-activity-schema-2026-06-24.json",
    "ocr": "fedramp-ongoing-certification-report-schema-2026-06-24.json",
    "scn": "fedramp-significant-change-notifications-schema-2026-06-24.json",
    "incident": "fedramp-incident-report-schema-2026-06-24.json",
}

# Every report except the CPO carries this; it is the one join the schemas define.
CPO_URI = "https://samaydlette.com/.well-known/certification-package-overview.json"

ANNOTATIONS = {"$schema", "$id", "$schemaVersion", "$defs", "$comment", "title", "description",
               "examples", "default"}
ASSERTIONS = {"type", "required", "properties", "items", "enum", "const", "$ref", "pattern",
              "format", "minItems", "maxItems", "contains", "allOf", "if", "then"}
FORMATS = {"date", "date-time", "email", "uri"}

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class SchemaError(Exception):
    """The vendored schema set is unusable: tampered, unlisted, or uses a keyword
    this validator does not implement."""


def _fail(msg):
    raise SystemExit(f"::error::CR26 schema: {msg} (fail-closed)")


def _walk_keywords(node, where):
    if isinstance(node, dict):
        for k, v in node.items():
            if k not in ANNOTATIONS | ASSERTIONS:
                raise SchemaError(f"{where}: keyword {k!r} is not implemented")
            if k == "format" and v not in FORMATS:
                raise SchemaError(f"{where}: format {v!r} is not implemented")
            if k == "properties":
                for name, sub in v.items():
                    _walk_keywords(sub, f"{where}/properties/{name}")
            elif k == "$defs":
                for name, sub in v.items():
                    _walk_keywords(sub, f"{where}/$defs/{name}")
            elif k in ("items", "contains", "if", "then"):
                _walk_keywords(v, f"{where}/{k}")
            elif k == "allOf":
                for i, sub in enumerate(v):
                    _walk_keywords(sub, f"{where}/allOf/{i}")


def load_registry(schema_dir=SCHEMA_DIR):
    """{schema $id: schema} for every vendored file, after checking each against
    SOURCES.json. A changed, missing or unlisted file refuses the whole set."""
    schema_dir = Path(schema_dir)
    try:
        sources = json.loads((schema_dir / "SOURCES.json").read_text())["files"]
    except (OSError, ValueError, KeyError) as exc:
        raise SchemaError(f"{schema_dir}/SOURCES.json unreadable: {exc}") from exc
    present = {p.name for p in schema_dir.glob("*.json")} - {"SOURCES.json"}
    if present != set(sources):
        raise SchemaError(f"schema files {sorted(present ^ set(sources))} are not exactly the set in SOURCES.json")
    registry = {}
    for name, meta in sources.items():
        raw = (schema_dir / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != meta.get("sha256"):
            raise SchemaError(f"{name}: sha256 differs from SOURCES.json")
        doc = json.loads(raw)
        if doc.get("$id") != meta.get("$id") or not doc["$id"].endswith("/" + name):
            raise SchemaError(f"{name}: $id {doc.get('$id')!r} does not match SOURCES.json")
        _walk_keywords(doc, name)
        for base in BASES:
            registry[base + name] = doc
    return registry


def _resolve(ref, current, registry):
    """Return (target schema, the document it lives in)."""
    uri, _, frag = ref.partition("#")
    doc = registry.get(uri) if uri else current
    if doc is None:
        raise SchemaError(f"$ref {ref!r} is outside the vendored set")
    node = doc
    for part in [p for p in frag.split("/") if p]:
        try:
            node = node[part]
        except (KeyError, TypeError) as exc:
            raise SchemaError(f"$ref {ref!r} does not resolve") from exc
    return node, doc


def _type_ok(value, t):
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "string":
        return isinstance(value, str)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "null":
        return value is None
    raise SchemaError(f"type {t!r} is not implemented")


def _format_ok(value, fmt):
    if fmt == "date":
        if not _DATE_RE.match(value):
            return False
        try:
            date.fromisoformat(value)
        except ValueError:
            return False
        return True
    if fmt == "date-time":
        if not _DATETIME_RE.match(value):
            return False
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00").replace("t", "T"))
        except ValueError:
            return False
        return True
    if fmt == "email":
        return bool(_EMAIL_RE.match(value))
    if fmt == "uri":
        parts = urlsplit(value)
        return bool(parts.scheme) and bool(parts.netloc or parts.path) and " " not in value
    raise SchemaError(f"format {fmt!r} is not implemented")


def _equal(a, b):
    # JSON equality: true is not 1.
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return a == b


def _check(value, schema, doc, registry, path, errors):
    if "$ref" in schema:
        target, target_doc = _resolve(schema["$ref"], doc, registry)
        _check(value, target, target_doc, registry, path, errors)
    t = schema.get("type")
    if t is not None and not _type_ok(value, t):
        errors.append(f"{path or '/'}: expected {t}")
        return
    if "enum" in schema and not any(_equal(value, e) for e in schema["enum"]):
        errors.append(f"{path or '/'}: {value!r} is not one of {schema['enum']}")
    if "const" in schema and not _equal(value, schema["const"]):
        errors.append(f"{path or '/'}: must be {schema['const']!r}")
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path or '/'}: {value!r} does not match {schema['pattern']}")
        if "format" in schema and not _format_ok(value, schema["format"]):
            errors.append(f"{path or '/'}: {value!r} is not a valid {schema['format']}")
    if isinstance(value, dict):
        for req in schema.get("required", []):
            if req not in value:
                errors.append(f"{path or '/'}: missing required {req!r}")
        for name, sub in schema.get("properties", {}).items():
            if name in value:
                _check(value[name], sub, doc, registry, f"{path}/{name}", errors)
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path or '/'}: fewer than {schema['minItems']} item(s)")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path or '/'}: more than {schema['maxItems']} item(s)")
        if "items" in schema:
            for i, item in enumerate(value):
                _check(item, schema["items"], doc, registry, f"{path}/{i}", errors)
        if "contains" in schema and not any(
                not _errors_of(item, schema["contains"], doc, registry) for item in value):
            errors.append(f"{path or '/'}: no item matches the required 'contains' schema")
    for sub in schema.get("allOf", []):
        _check(value, sub, doc, registry, path, errors)
    if "if" in schema and not _errors_of(value, schema["if"], doc, registry) and "then" in schema:
        _check(value, schema["then"], doc, registry, path, errors)


def _errors_of(value, schema, doc, registry):
    errs = []
    _check(value, schema, doc, registry, "", errs)
    return errs


def validate(document, kind, registry=None):
    """Errors (a list of strings; empty means valid) for `document` as a `kind`
    report. Also requires `$schema` to name that report's FedRAMP schema
    (storycheck FMT-4) and, except for the CPO, the CPO link."""
    registry = registry if registry is not None else load_registry()
    name = SCHEMAS[kind]
    schema = registry[BASES[0] + name]
    errors = []
    if not isinstance(document, dict) or document.get("$schema") != BASES[0] + name:
        errors.append(f"/$schema: must be {BASES[0] + name}")
    _check(document, schema, schema, registry, "", errors)
    if kind != "cpo" and isinstance(document, dict) and document.get("certificationPackageOverviewUri") != CPO_URI:
        errors.append(f"/certificationPackageOverviewUri: must be {CPO_URI}")
    return errors


def write_validated(document, kind, path, registry=None):
    """Validate, then write. Nothing is written if the document fails."""
    try:
        errors = validate(document, kind, registry)
    except SchemaError as exc:
        _fail(str(exc))
    if errors:
        for e in errors[:25]:
            print(f"::error::{Path(path).name}: {e}", file=sys.stderr)
        _fail(f"{Path(path).name} does not validate against {SCHEMAS[kind]} ({len(errors)} error(s)); not written")
    Path(path).write_text(json.dumps(document, indent=2) + "\n")


def stamp(kind):
    """The `$schema` value a `kind` report carries."""
    return BASES[0] + SCHEMAS[kind]
