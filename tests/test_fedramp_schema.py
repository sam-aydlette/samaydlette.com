"""The CR26 schema validator (scripts/_fedramp_schema.py) and the vendored schemas.

Pins:
- the vendored set is exactly FedRAMP's 2026-06-24 files, by sha256; a changed,
  missing or unlisted file refuses the set;
- the validator refuses a schema that uses a keyword it does not implement;
- on valid documents it agrees with jsonschema, and it is never weaker: every
  document jsonschema rejects, it rejects too (good fixtures, known-bad fixtures,
  and systematic mutations of each good fixture);
- `$schema` must name the report's FedRAMP schema (FMT-4), and every report but
  the CPO links the CPO;
- write_validated writes nothing when a document fails.
"""
import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _fedramp_schema as fs  # noqa: E402

FIX = REPO / "tests" / "fixtures" / "cr26"
GOOD = {k: json.loads((FIX / "good" / f"{k}.json").read_text()) for k in ("cpo", "sdr", "ocr", "scn", "incident")}
BAD = {
    "vdt-missing-required.json": ("vdt", "missing required 'vulnerabilities'"),
    "vdt-wrong-schema.json": ("vdt", "/$schema"),
    "vdt-overdue-without-explanation.json": ("vdt", "missing required 'explanation'"),
    "cpo-no-sales-contact.json": ("cpo", "contains"),
    "incident-final-without-resolved.json": ("incident", "missing required 'resolvedAt'"),
}


def _js_registry():
    res = []
    for f in fs.SCHEMA_DIR.glob("fedramp-*.json"):
        r = Resource.from_contents(json.loads(f.read_text()))
        res += [(base + f.name, r) for base in fs.BASES]
    return Registry().with_resources(res)


JS_REG = _js_registry()
REG = fs.load_registry()


def _js_errors(doc, kind):
    schema = json.loads((fs.SCHEMA_DIR / fs.SCHEMAS[kind]).read_text())
    return list(Draft202012Validator(schema, registry=JS_REG, format_checker=FormatChecker()).iter_errors(doc))


# --- the vendored set ------------------------------------------------------------

def test_the_vendored_set_is_fedramps_nine_schemas_by_hash():
    src = json.loads((fs.SCHEMA_DIR / "SOURCES.json").read_text())["files"]
    assert len(src) == 9
    for name, meta in src.items():
        assert hashlib.sha256((fs.SCHEMA_DIR / name).read_bytes()).hexdigest() == meta["sha256"]
        assert meta["$id"] == "https://fedramp.gov/schemas/" + name
    assert set(fs.SCHEMAS.values()) <= set(src)


def _copy_set(tmp_path):
    d = tmp_path / "schemas"
    shutil.copytree(fs.SCHEMA_DIR, d)
    return d


def test_a_changed_schema_refuses_the_set(tmp_path):
    d = _copy_set(tmp_path)
    f = d / fs.SCHEMAS["vdt"]
    f.write_text(f.read_text().replace('"vulnerabilities"]', '"reportPeriod"]'))
    with pytest.raises(fs.SchemaError, match="sha256"):
        fs.load_registry(d)


def test_an_unlisted_or_missing_schema_refuses_the_set(tmp_path):
    d = _copy_set(tmp_path)
    (d / "extra.json").write_text("{}")
    with pytest.raises(fs.SchemaError, match="not exactly the set"):
        fs.load_registry(d)
    (d / "extra.json").unlink()
    (d / fs.SCHEMAS["avi"]).unlink()
    with pytest.raises(fs.SchemaError, match="not exactly the set"):
        fs.load_registry(d)


def test_a_keyword_the_validator_does_not_implement_refuses_the_set(tmp_path):
    d = _copy_set(tmp_path)
    name = fs.SCHEMAS["scn"]
    doc = json.loads((d / name).read_text())
    doc["additionalProperties"] = False
    raw = json.dumps(doc).encode()
    (d / name).write_bytes(raw)
    src = json.loads((d / "SOURCES.json").read_text())
    src["files"][name]["sha256"] = hashlib.sha256(raw).hexdigest()
    (d / "SOURCES.json").write_text(json.dumps(src))
    with pytest.raises(fs.SchemaError, match="additionalProperties"):
        fs.load_registry(d)


# --- agreement with jsonschema ---------------------------------------------------

@pytest.mark.parametrize("kind", sorted(GOOD))
def test_good_documents_pass_both_validators(kind):
    assert fs.validate(GOOD[kind], kind, REG) == []
    assert _js_errors(GOOD[kind], kind) == []


@pytest.mark.parametrize("name", sorted(BAD))
def test_each_known_bad_document_fails_for_its_reason(name):
    kind, reason = BAD[name]
    doc = json.loads((FIX / "bad" / name).read_text())
    errors = fs.validate(doc, kind, REG)
    assert any(reason in e for e in errors), errors
    if "$schema" not in reason:
        assert _js_errors(doc, kind), "jsonschema should reject it too"


def _mutations(doc):
    """Drop each key, null each value, and put a wrong-typed or out-of-vocabulary
    value at each leaf, anywhere in the document."""
    def paths(node, prefix=()):
        if isinstance(node, dict):
            for k, v in node.items():
                yield prefix + (k,)
                yield from paths(v, prefix + (k,))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield prefix + (i,)
                yield from paths(v, prefix + (i,))

    def at(node, path):
        for p in path[:-1]:
            node = node[p]
        return node

    for path in list(paths(doc)):
        for op in ("drop", "null", "int", "str", "date"):
            m = copy.deepcopy(doc)
            parent, key = at(m, path), path[-1]
            if op == "drop":
                if isinstance(parent, list):
                    parent.pop(key)
                else:
                    del parent[key]
            elif op == "null":
                parent[key] = None
            elif op == "int":
                parent[key] = 7
            elif op == "str":
                parent[key] = "not-a-valid-value"
            else:
                parent[key] = "2026-13-45"
            yield path, op, m


@pytest.mark.parametrize("kind", sorted(GOOD))
def test_the_validator_is_never_weaker_than_jsonschema(kind):
    checked = 0
    for path, op, m in _mutations(GOOD[kind]):
        if path == ("$schema",):
            continue
        if _js_errors(m, kind):
            assert fs.validate(m, kind, REG), f"{kind}: {op} at {path} passed here but jsonschema rejects it"
            checked += 1
    assert checked > 10


# --- envelope rules ----------------------------------------------------------------

def test_every_report_but_the_cpo_must_link_the_cpo():
    doc = copy.deepcopy(GOOD["ocr"])
    doc["certificationPackageOverviewUri"] = "https://example.com/other-cpo.json"
    assert any("certificationPackageOverviewUri" in e for e in fs.validate(doc, "ocr", REG))
    assert fs.validate(GOOD["cpo"], "cpo", REG) == []


def test_formats_are_asserted():
    doc = copy.deepcopy(GOOD["ocr"])
    doc["reportPeriod"]["to"] = "31/10/2026"
    assert any("valid date" in e for e in fs.validate(doc, "ocr", REG))
    doc = copy.deepcopy(GOOD["cpo"])
    doc["contactInformation"][0]["contactEmail"] = "not an email"
    assert any("valid email" in e for e in fs.validate(doc, "cpo", REG))


def test_write_validated_writes_nothing_for_a_failing_document(tmp_path):
    doc = json.loads((FIX / "bad" / "vdt-missing-required.json").read_text())
    out = tmp_path / "vdt.json"
    with pytest.raises(SystemExit, match="not written"):
        fs.write_validated(doc, "vdt", out, REG)
    assert not out.exists()
    fs.write_validated(GOOD["ocr"], "ocr", out, REG)
    assert json.loads(out.read_text()) == GOOD["ocr"]
