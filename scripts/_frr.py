"""The FedRAMP rule records: data/frr-records.json (SDR-CSO-FRR).

One record per FedRAMP rule that applies to this system (20x, Program path,
Class C), with one of four statuses (CLAUDE.md, proof-of-concept latitude):

  Implemented       a real mechanism ran on real inputs, and evidence exists;
  Not Demonstrated  buildable and not built yet; `not_demonstrated` says what
                    is missing and `planned` what Implemented will look like;
  Impractical       one engineer with cheap AWS cannot meet it; `impractical`
                    names the reasons (one-person, no-budget with its cost,
                    no-outside-party), why, and what was built anyway;
  Not Applicable    the rule's trigger cannot happen here; `not_applicable`
                    names the missing trigger.

Facts here, decision in Rego (the ScubaGoggles pattern):

- `load` holds the register to its shape, fail-closed, stdlib only: the record
  set equals the applicable rules in the pinned corpus (a re-pinned corpus that
  adds a rule cannot be published past), fields belong to their status, and no
  text carries an AWS account ID or an outside email address (the SDR is
  published). `make check` runs it through the tests.
- `facts` adds what Python can observe: whether each piece of evidence
  resolves in this repository.
    test      tests/<file>.py::<test>[::<method>]  a test function that exists
    step      <workflow>.yml#<step name>          a step in .github/workflows/
    artifact  .well-known/<name>                  a freshness-governed artifact
    decision  DEC-NNN                             an in-force decision record
- `claims` asks policies/compliance/claims.rego which records claim more than
  their fields support. The deploy gate (`--claims`) fails on any.
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
import _triage  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PATH = REPO / "data" / "frr-records.json"
SCHEMA_PATH = REPO / "infrastructure" / "schemas" / "frr-records.schema.json"
POLICY = REPO / "policies" / "compliance" / "claims.rego"

STATUSES = ("Implemented", "Not Demonstrated", "Impractical", "Not Applicable")
OPERATOR = "Sam Aydlette"
EVIDENCE_KINDS = ("test", "step", "artifact", "decision")
SIGNOFF_KEYS = {"by", "on"}
IMPRACTICAL_KEYS = {"reasons", "why", "cost", "built"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

TOP_KEYS = {"$schema", "$comment", "schema", "basis", "records"}
RECORD_KEYS = {"frr_id", "status", "implementation", "planned", "evidence", "may_rationale", "not_applicable",
               "not_demonstrated", "impractical", "proposal", "approval"}
# The field each status explains itself with; a field for another status is refused.
STATUS_FIELD = {"Implemented": "implementation", "Not Demonstrated": "not_demonstrated",
                "Impractical": "impractical", "Not Applicable": "not_applicable"}
EVIDENCE_KEYS = {"kind", "ref"}

TEST_RE = re.compile(r"^(tests/[A-Za-z0-9_/]+\.py)::([A-Za-z_][A-Za-z0-9_]*)(?:::([A-Za-z_][A-Za-z0-9_]*))?$")
STEP_RE = re.compile(r"^([A-Za-z0-9_.-]+\.ya?ml)#(.+)$")
STEP_LINE_RE = re.compile(r"^\s*-\s+name:\s*(.+?)\s*$")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
# Addresses a record may name: the system's own domain and FedRAMP's senders.
EMAIL_DOMAINS = ("samaydlette.com", "fedramp.gov", "gsa.gov")


def _fail(msg):
    raise SystemExit(f"::error::FRR records: {msg} (fail-closed)")


# --- evidence resolution (facts) -----------------------------------------------

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
    ok = (first in funcs and first.startswith("test")) if second is None \
        else ((first, second) in methods and second.startswith("test"))
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


# --- shape ---------------------------------------------------------------------

def _text(rec, key, where, required=True):
    v = rec.get(key)
    if v is None and not required:
        return None
    if not isinstance(v, str) or not v.strip():
        _fail(f"{where}: {key} must be a non-empty string")
    if _redact.find(v):
        _fail(f"{where}: {key} carries an AWS account ID")
    for m in EMAIL_RE.finditer(v):
        if m.group(1).lower() not in EMAIL_DOMAINS:
            _fail(f"{where}: {key} names an email address outside {list(EMAIL_DOMAINS)}")
    return v


def _signoff(v, where):
    if not isinstance(v, dict) or set(v) != SIGNOFF_KEYS:
        _fail(f"{where} must be {{by, on}}")
    _text(v, "by", where)
    if not isinstance(v.get("on"), str) or not DATE_RE.match(v["on"]):
        _fail(f"{where}.on must be a date (YYYY-MM-DD)")


def _impractical(v, rid):
    """Shape only. Whether the reasons are enough is the claim check's decision."""
    if not isinstance(v, dict) or set(v) - IMPRACTICAL_KEYS:
        _fail(f"{rid}: impractical must be {{reasons, why, cost, built}}")
    if not isinstance(v.get("reasons", []), list) or not all(isinstance(x, str) for x in v.get("reasons", [])):
        _fail(f"{rid}: impractical.reasons must be a list of strings")
    for k in ("why", "cost", "built"):
        _text(v, k, f"{rid} impractical", required=False)


def validate(doc, applicable, where="data/frr-records.json"):
    """Structural checks. `applicable` is {rule ID: rule} from the corpus."""
    if not isinstance(doc, dict) or doc.get("schema") != "frr-records/2":
        _fail(f"{where} is not an frr-records/2 document")
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
        for st, field in STATUS_FIELD.items():
            if field in rec and st != status:
                _fail(f"{rid}: {field} is for {st} records only")
        if status == "Implemented":
            _text(rec, "implementation", rid)
        _text(rec, "planned", rid, required=False)
        for k in ("not_demonstrated", "not_applicable"):
            _text(rec, k, rid, required=False)
        if "impractical" in rec:
            _impractical(rec["impractical"], rid)
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
        for k in ("proposal", "approval"):
            if k in rec:
                _signoff(rec[k], f"{rid} {k}")
    missing = sorted(set(applicable) - seen)
    if missing:
        _fail(f"no record for {len(missing)} applicable rule(s): {', '.join(missing)}")
    return doc


def load(path=None, rules_dir=None):
    p = Path(path) if path else DEFAULT_PATH
    if not p.is_file():
        _fail(f"{p} not found")
    try:
        doc = json.loads(p.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{p} is not valid JSON: {exc}")
    return validate(doc, _rules.applicable_provider_rules(rules_dir or _rules.RULES_DIR), str(p))


# --- facts and the claim decision ------------------------------------------------

def facts(doc, resolve, ksi_short=None):
    """The claim policy's input: each record with its evidence resolved."""
    records = []
    for r in doc["records"]:
        rec = {k: v for k, v in r.items() if k != "evidence"}
        rec["evidence"] = []
        for ev in r.get("evidence", []):
            why = resolve(ev)
            rec["evidence"].append({**ev, "resolves": why is None, "why": why or ""})
        records.append(rec)
    out = {"operator": OPERATOR, "records": records}
    if ksi_short is not None:
        out["ksi_short"] = sorted(ksi_short)
    return out


def claims(doc, resolve, ksi_short=None, policy=POLICY):
    """[(rule ID, why)] for every record whose fields do not support its status,
    as decided by policies/compliance/claims.rego. `ksi_short` is the KSIs with
    fewer than two automated methods (the deploy supplies it; without it, an
    Implemented FRC-CSX-VVK is an unsupported claim)."""
    deny = _triage.evaluate("data.compliance.claims.deny", facts(doc, resolve, ksi_short), policy=policy)
    if not isinstance(deny, list):
        _fail("the claim policy returned no decision")
    return sorted((d["frr_id"], d["why"]) for d in deny)


def summary(doc, applicable):
    """Counts the trust center and the SDR show: by status, and by status
    within each force (MUST, SHOULD, ...)."""
    by_status = Counter(r["status"] for r in doc["records"])
    by_force = {}
    for r in doc["records"]:
        by_force.setdefault(applicable[r["frr_id"]]["force"], Counter())[r["status"]] += 1
    reasons = Counter(x for r in doc["records"] if r["status"] == "Impractical"
                      for x in r.get("impractical", {}).get("reasons", []))
    unapproved = sum(1 for r in doc["records"]
                     if r["status"] in ("Impractical", "Not Applicable") and not r.get("approval"))
    return {"rules": len(doc["records"]),
            "by_status": {s: by_status.get(s, 0) for s in STATUSES},
            "impractical_reasons": {k: reasons[k] for k in sorted(reasons)},
            "awaiting_approval": unapproved,
            "by_force": {f: {s: c.get(s, 0) for s in STATUSES} for f, c in sorted(by_force.items())}}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Validate data/frr-records.json against the pinned FedRAMP rules.")
    ap.add_argument("--records", default=str(DEFAULT_PATH))
    ap.add_argument("--claims", action="store_true",
                    help="also fail on any record whose fields do not support its status (the deploy gate)")
    ap.add_argument("--ksi-short", default=None,
                    help="JSON list of KSIs with fewer than two automated methods (from the SDR build)")
    args = ap.parse_args(argv)
    doc = load(args.records)
    print(json.dumps(summary(doc, _rules.applicable_provider_rules()), indent=2))
    if args.claims:
        short = json.loads(Path(args.ksi_short).read_text()) if args.ksi_short else None
        bad = claims(doc, resolver(), short)
        if bad:
            for rid, why in bad:
                print(f"::error::{rid}: {why}")
            print(f"{len({rid for rid, _ in bad})} of {len(doc['records'])} record(s) claim more than their fields "
                  "support; the deploy does not proceed.", file=sys.stderr)
            return 1
        print("Every record's status is supported by its fields.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
