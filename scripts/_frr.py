"""The FedRAMP rule records: data/frr-records.json (SDR-CSO-FRR).

One record per FedRAMP rule that applies to this system's certification (20x,
Program path, Class C), saying whether the rule is implemented, how, what shows
it, and, when it isn't, what is missing and which piece of work closes it. The
Security Decision Record publishes these records; nothing else may say a rule
is met.

The register is only allowed to claim what the repository can show:

- The applicable rule set comes from the pinned corpus (_rules.applicable_provider_rules).
  A missing or extra record fails, so a re-pinned corpus that adds a rule
  cannot be published past.
- "Implemented" needs at least one piece of evidence, and every piece of
  evidence on any record must resolve:
    test      tests/<file>.py::<test>[::<method>]  a test function that exists
    step      <workflow>.yml#<step name>          a step in .github/workflows/
    artifact  .well-known/<name>                  a published, freshness-governed artifact
    decision  DEC-NNN                             an in-force decision record
- Anything short of implemented states its gap and what closes it: a
  workstream (W2..W10), "sam" (an act only the operator can perform, such as an
  application, a registration or engaging an assessor), or "optional" (a MAY
  rule not exercised; refused for any other force).
- Every MAY rule says why it was or wasn't exercised (may_rationale); no
  other rule carries one.
- No record text may carry an AWS account ID, or an email address outside the
  system's domain and FedRAMP's (the SDR is published).

Fails closed, stdlib only (the deploy job installs no jsonschema); the JSON
schema beside it documents the same shape and is checked in tests.
"""

import ast
import json
import re
import sys
from collections import Counter
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _decisions  # noqa: E402
import _freshness  # noqa: E402
import _redact  # noqa: E402
import _rules  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PATH = REPO / "data" / "frr-records.json"
SCHEMA_PATH = REPO / "infrastructure" / "schemas" / "frr-records.schema.json"
WORKFLOWS = REPO / ".github" / "workflows"
TESTS = REPO / "tests"

STATUSES = ("Implemented", "Partially Implemented", "Not Implemented")
WORKSTREAMS = tuple(f"W{n}" for n in range(2, 11))
CLOSERS = (*WORKSTREAMS, "sam", "optional")
EVIDENCE_KINDS = ("test", "step", "artifact", "decision")

TOP_KEYS = {"$comment", "schema", "basis", "records"}
RECORD_KEYS = {"frr_id", "status", "implementation", "evidence", "gap", "closes_with", "may_rationale"}
EVIDENCE_KEYS = {"kind", "ref"}

TEST_RE = re.compile(r"^(tests/[A-Za-z0-9_/]+\.py)::([A-Za-z_][A-Za-z0-9_]*)(?:::([A-Za-z_][A-Za-z0-9_]*))?(?:\[[^\]]*\])?$")
STEP_RE = re.compile(r"^([A-Za-z0-9_.-]+\.ya?ml)#(.+)$")
STEP_LINE_RE = re.compile(r"^\s*-\s+name:\s*(.+?)\s*$")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
# Addresses a record may name: the system's own domain and FedRAMP's senders
# (AFC-CSO-TFG). Anything else, a personal mailbox above all, stays out of the SDR.
EMAIL_DOMAINS = ("samaydlette.com", "fedramp.gov", "gsa.gov")


def _fail(msg):
    raise SystemExit(f"::error::FRR records: {msg} (fail-closed)")


# --- evidence resolution ----------------------------------------------------------

@lru_cache(maxsize=None)
def _test_names(path):
    """{function name} and {(class, method)} defined in a test module."""
    tree = ast.parse(Path(path).read_text(), filename=str(path))
    funcs, methods = set(), set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.add(node.name)
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.add((node.name, sub.name))
    return funcs, methods


@lru_cache(maxsize=None)
def _step_names(path):
    names = set()
    for line in Path(path).read_text().splitlines():
        m = STEP_LINE_RE.match(line)
        if m:
            names.add(m.group(1).strip().strip("'\""))
    return names


def _resolve_test(ref, repo):
    m = TEST_RE.match(ref)
    if not m:
        return "is not tests/<file>.py::<test>"
    rel, first, second = m.groups()
    path = repo / rel
    if ".." in rel or not path.is_file():
        return f"{rel} does not exist"
    funcs, methods = _test_names(str(path))
    if second is None:
        ok = first in funcs and first.startswith("test")
    else:
        ok = (first, second) in methods and second.startswith("test")
    return None if ok else "names no test function in that file"


def _resolve_step(ref, repo):
    m = STEP_RE.match(ref)
    if not m:
        return "is not <workflow>.yml#<step name>"
    wf, step = m.groups()
    path = repo / ".github" / "workflows" / wf
    if not path.is_file():
        return f"workflow {wf} does not exist"
    return None if step in _step_names(str(path)) else f"no step named {step!r} in {wf}"


def resolver(repo=REPO, freshness_path=None, decisions_path=None):
    """A function evidence -> None when it resolves, else the reason it doesn't."""
    repo = Path(repo)
    published = {a["path"] for a in _freshness.load_freshness_config(
        freshness_path or repo / "infrastructure" / "schemas" / "freshness-config.json")["artifacts"]}
    in_force = {r["id"] for r in _decisions.in_force(_decisions.load(decisions_path or repo / "data" / "decisions.json"))}

    def resolve(ev):
        kind, ref = ev["kind"], ev["ref"]
        if kind == "test":
            return _resolve_test(ref, repo)
        if kind == "step":
            return _resolve_step(ref, repo)
        if kind == "artifact":
            return None if ref in published else "is not a freshness-governed published artifact"
        if kind == "decision":
            return None if ref in in_force else "is not an in-force decision record"
        return f"unknown evidence kind {kind!r}"
    return resolve


# --- validation -------------------------------------------------------------------

def _text(rec, key, rid, required=True):
    v = rec.get(key)
    if v is None and not required:
        return None
    if not isinstance(v, str) or not v.strip():
        _fail(f"{rid}: {key} must be a non-empty string")
    if _redact.find(v):
        _fail(f"{rid}: {key} carries an AWS account ID")
    for m in EMAIL_RE.finditer(v):
        if m.group(1).lower() not in EMAIL_DOMAINS:
            _fail(f"{rid}: {key} names an email address outside {list(EMAIL_DOMAINS)}")
    return v


def validate(doc, applicable, resolve, where="data/frr-records.json"):
    """Structural and honesty checks. `applicable` is {rule ID: rule} from the
    corpus; `resolve` maps evidence to None or a failure reason."""
    if not isinstance(doc, dict) or doc.get("schema") != "frr-records/1":
        _fail(f"{where} is not an frr-records/1 document")
    if set(doc) - TOP_KEYS:
        _fail(f"{where}: unknown top-level field(s) {sorted(set(doc) - TOP_KEYS)}")
    _text(doc, "basis", "basis")
    recs = doc.get("records")
    if not isinstance(recs, list):
        _fail(f"{where}: records must be a list")
    seen = set()
    for rec in recs:
        rid = rec.get("frr_id") if isinstance(rec, dict) else None
        if not isinstance(rid, str) or not rid:
            _fail(f"{where}: a record has no frr_id")
        if rid in seen:
            _fail(f"duplicate record for {rid}")
        seen.add(rid)
        if rid not in applicable:
            _fail(f"{rid} is not a rule that applies to a 20x Class C provider (extra record)")
        if set(rec) - RECORD_KEYS:
            _fail(f"{rid}: unknown field(s) {sorted(set(rec) - RECORD_KEYS)}")
        status = rec.get("status")
        if status not in STATUSES:
            _fail(f"{rid}: status {status!r} is not one of {list(STATUSES)}")
        _text(rec, "implementation", rid)
        if applicable[rid]["force"] == "MAY":
            _text(rec, "may_rationale", rid)
        elif "may_rationale" in rec:
            _fail(f"{rid}: may_rationale is for MAY rules only (Class C force is {applicable[rid]['force']})")
        evidence = rec.get("evidence", [])
        if not isinstance(evidence, list):
            _fail(f"{rid}: evidence must be a list")
        for ev in evidence:
            if not isinstance(ev, dict) or set(ev) != EVIDENCE_KEYS or ev.get("kind") not in EVIDENCE_KINDS \
                    or not isinstance(ev.get("ref"), str) or not ev["ref"]:
                _fail(f"{rid}: evidence {ev!r} must be {{kind: one of {list(EVIDENCE_KINDS)}, ref}}")
            why = resolve(ev)
            if why:
                _fail(f"{rid}: {ev['kind']} evidence {ev['ref']!r} does not resolve: {why}")
        closes = rec.get("closes_with")
        if status == "Implemented":
            if not evidence:
                _fail(f"{rid}: Implemented needs evidence that resolves")
            if rec.get("gap") is not None or closes is not None:
                _fail(f"{rid}: an Implemented record has no gap and nothing closing it")
            continue
        _text(rec, "gap", rid)
        if not isinstance(closes, list) or not closes or len(set(closes)) != len(closes) \
                or any(c not in CLOSERS for c in closes):
            _fail(f"{rid}: closes_with must be a non-empty list drawn from {list(CLOSERS)}")
        if "optional" in closes:
            if applicable[rid]["force"] != "MAY":
                _fail(f"{rid}: only a MAY rule can be left as optional (Class C force is {applicable[rid]['force']})")
            if len(closes) != 1:
                _fail(f"{rid}: an optional rule is closed by nothing else")
    missing = sorted(set(applicable) - seen)
    if missing:
        _fail(f"no record for {len(missing)} applicable rule(s): {', '.join(missing)}")
    return doc


def load(path=None, rules_dir=None, repo=REPO, freshness_path=None, decisions_path=None):
    p = Path(path) if path else DEFAULT_PATH
    if not p.is_file():
        _fail(f"{p} not found")
    try:
        doc = json.loads(p.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{p} is not valid JSON: {exc}")
    applicable = _rules.applicable_provider_rules(rules_dir or _rules.RULES_DIR)
    return validate(doc, applicable, resolver(repo, freshness_path, decisions_path), str(p))


def summary(doc, applicable):
    """Counts the trust center and the SDR can show: by status, and by status
    within each force (MUST, SHOULD, ...)."""
    by_status = Counter(r["status"] for r in doc["records"])
    by_force = {}
    for r in doc["records"]:
        f = applicable[r["frr_id"]]["force"]
        by_force.setdefault(f, Counter())[r["status"]] += 1
    optional = sum(1 for r in doc["records"] if r.get("closes_with") == ["optional"])
    return {"rules": len(doc["records"]),
            "by_status": {s: by_status.get(s, 0) for s in STATUSES},
            "by_force": {f: {s: c.get(s, 0) for s in STATUSES} for f, c in sorted(by_force.items())},
            "optional_not_exercised": optional}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Validate data/frr-records.json against the pinned FedRAMP rules.")
    ap.add_argument("--records", default=str(DEFAULT_PATH))
    args = ap.parse_args(argv)
    doc = load(args.records)
    print(json.dumps(summary(doc, _rules.applicable_provider_rules()), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
