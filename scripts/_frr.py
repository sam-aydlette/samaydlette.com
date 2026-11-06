"""The FedRAMP rule records: data/frr-records.json (SDR-CSO-FRR).

One record per FedRAMP rule that applies to this system's certification (20x,
Program path, Class C), saying which of four statuses the rule has, how, what
shows it, and who proposed and approved any stand-in or scope cut. The Security
Decision Record publishes these records; nothing else may say a rule is met.

The four statuses (the operator's proof-of-concept latitude, CLAUDE.md):

  Implemented       a real mechanism ran on real inputs, and evidence exists;
  Simulated         a real mechanism ran on a labelled stand-in input;
  Not Demonstrated  not built, or nothing runs; the record says why;
  Not Applicable    the rule does not apply; the record says why.

The register is only allowed to claim what the repository can show:

- The applicable rule set comes from the pinned corpus (_rules.applicable_provider_rules).
  A missing or extra record fails, so a re-pinned corpus that adds a rule
  cannot be published past.
- Every piece of evidence on any record must resolve:
    test      tests/<file>.py::<test>[::<method>]  a test function that exists
    step      <workflow>.yml#<step name>          a step in .github/workflows/
    artifact  .well-known/<name>                  a published, freshness-governed artifact
    decision  DEC-NNN                             an in-force decision record
- Every MAY rule says why it was or wasn't exercised (may_rationale); no
  other rule carries one.
- No record text may carry an AWS account ID, or an email address outside the
  system's domain and FedRAMP's (the SDR is published).

Loading (`load`, every consumer and `make check`) holds the register to its
shape. The claim check (`--claims`, the deploy gate "FedRAMP rule claims
supported by evidence", and `claims()`) holds each record to what its status
claims, and fails on any record whose fields do not support it:

  Implemented       resolving evidence, and no `simulated` block (a stand-in
                    input makes the record Simulated);
  Simulated         `simulated` {counterparty, how, real, stand_in}: what is
                    real and what stands in (an outside party, the people,
                    or infrastructure deliberately not built); `stand_in_proof`
                    {bad_input: a test that feeds a bad stand-in and asserts a
                    different outcome; replaceable: {statement: how a real
                    input would replace the stand-in and what would have to
                    change, test: one that shows it, where one exists}}, each
                    cited test resolving; and deploy-time evidence (a workflow
                    step or a published artifact). A guard that refuses real
                    agencies or FedRAMP (DEC-194) is policy, not logic;
  Not Demonstrated  `not_demonstrated` (why: not built, or nothing runs), and
                    no evidence claimed;
  Not Applicable    `not_applicable` (why).

Simulated, Not Demonstrated and Not Applicable records also carry `proposal`
{by, on} and `approval` {by, on}. The approver is the operator: an agent may
propose a stand-in or a scope cut and never approve one, so `approval.by` is
the operator's name and is written only on his word. The claim check never
fails on an honestly stated status; it fails only on a claim its fields do not
support, which includes a stand-in or scope cut nobody approved.

Each record describes the state after a successful deploy of the commit that
contains it. Fails closed, stdlib only (the deploy job installs no
jsonschema); the JSON schema beside it documents the same shape and is
checked in tests.
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

STATUSES = ("Implemented", "Simulated", "Not Demonstrated", "Not Applicable")
# The statuses that rest on a stand-in or a scope cut: proposed by anyone,
# approved only by the operator.
NEEDS_APPROVAL = ("Simulated", "Not Demonstrated", "Not Applicable")
OPERATOR = "Sam Aydlette"
EVIDENCE_KINDS = ("test", "step", "artifact", "decision")
# Outside parties this proof of concept stands in for (DEC-194: no engagement):
# the mechanism is real and runs on every deploy or on its schedule; the party
# is not. `personnel` is the people a people-run process needs (Quarterly
# Review attendees, a trainee), so that no process waits on a person.
SIMULATED_COUNTERPARTIES = ("assessor", "fedramp", "agency", "incident-recipient", "mail", "sam-gov", "personnel")
SIMULATED_KEYS = {"counterparty", "how"}
# What a Simulated record must say beyond the counterparty: what is real and
# what is the stand-in (checked by the claim check).
SIMULATED_CLAIM_KEYS = {"real", "stand_in"}
STAND_IN_PROOF_KEYS = {"bad_input", "replaceable"}
# replaceable: how a real input would replace the stand-in and what would have
# to change (required), with a test that shows it where one exists (optional).
REPLACEABLE_KEYS = {"statement", "test"}
SIGNOFF_KEYS = {"by", "on"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

TOP_KEYS = {"$comment", "schema", "basis", "records"}
RECORD_KEYS = {"frr_id", "status", "implementation", "evidence", "may_rationale", "not_applicable",
               "not_demonstrated", "simulated", "stand_in_proof", "proposal", "approval"}
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


def _signoff_shape(v, where):
    if not isinstance(v, dict) or set(v) != SIGNOFF_KEYS:
        _fail(f"{where} must be {{by, on}}")
    _text(v, "by", where)
    if not isinstance(v.get("on"), str) or not DATE_RE.match(v["on"]):
        _fail(f"{where}.on must be a date (YYYY-MM-DD)")


def _stand_in_proof_shape(v, rid):
    if not isinstance(v, dict) or set(v) != STAND_IN_PROOF_KEYS \
            or not isinstance(v.get("bad_input"), str) or not v["bad_input"] \
            or not isinstance(v.get("replaceable"), dict) or "statement" not in v["replaceable"] \
            or set(v["replaceable"]) - REPLACEABLE_KEYS \
            or ("test" in v["replaceable"]
                and (not isinstance(v["replaceable"]["test"], str) or not v["replaceable"]["test"])):
        _fail(f"{rid}: stand_in_proof must be {{bad_input: <test>, replaceable: {{statement, test (optional)}}}}")
    _text(v["replaceable"], "statement", f"{rid} stand_in_proof.replaceable")


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
        if "simulated" in rec:
            sim = rec["simulated"]
            if not isinstance(sim, dict) or not SIMULATED_KEYS <= set(sim) \
                    or set(sim) - SIMULATED_KEYS - SIMULATED_CLAIM_KEYS \
                    or sim.get("counterparty") not in SIMULATED_COUNTERPARTIES:
                _fail(f"{rid}: simulated must be {{counterparty: one of {list(SIMULATED_COUNTERPARTIES)}, how, "
                      f"real, stand_in}}")
            for k in ("how", *sorted(SIMULATED_CLAIM_KEYS)):
                _text(sim, k, f"{rid} simulated", required=k == "how")
            if status not in ("Implemented", "Simulated"):
                _fail(f"{rid}: simulated is for Simulated records only")
            if not any(ev["kind"] in ("step", "artifact") for ev in evidence):
                _fail(f"{rid}: a simulated counterparty needs deploy-time evidence (a workflow step or a "
                      f"published artifact): the simulation runs on every deploy")
        if "stand_in_proof" in rec:
            if status != "Simulated":
                _fail(f"{rid}: stand_in_proof is for Simulated records only")
            _stand_in_proof_shape(rec["stand_in_proof"], rid)
        for k in ("proposal", "approval"):
            if k in rec:
                if status not in NEEDS_APPROVAL:
                    _fail(f"{rid}: {k} is for {', '.join(NEEDS_APPROVAL)} records only")
                _signoff_shape(rec[k], f"{rid} {k}")
        if rec.get("approval") and rec["approval"].get("by") != OPERATOR:
            _fail(f"{rid}: approval.by must be the operator ({OPERATOR}); anyone may propose, only the operator "
                  "approves")
        if "not_applicable" in rec and status != "Not Applicable":
            _fail(f"{rid}: not_applicable is for Not Applicable records only")
        if "not_demonstrated" in rec and status != "Not Demonstrated":
            _fail(f"{rid}: not_demonstrated is for Not Demonstrated records only")
        if status == "Implemented" and not evidence:
            _fail(f"{rid}: Implemented needs evidence that resolves")
        if status == "Simulated" and not evidence:
            _fail(f"{rid}: Simulated needs evidence that resolves")
        if status == "Not Applicable":
            _text(rec, "not_applicable", rid)
        if status == "Not Demonstrated":
            _text(rec, "not_demonstrated", rid)
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


def claims(doc, resolve):
    """[(rule ID, why)] for every record whose fields do not support the status
    it claims (the deploy gate). An honest status never appears here; an
    unsupported claim, including a stand-in or a scope cut the operator has not
    approved, always does."""
    out = []
    for r in doc["records"]:
        rid, status = r["frr_id"], r["status"]
        evidence = r.get("evidence") or []
        if status == "Implemented" and "simulated" in r:
            out.append((rid, "Implemented with a simulated block: a mechanism run on a stand-in input is "
                             "Simulated, not Implemented"))
        if status == "Simulated":
            missing = sorted(SIMULATED_CLAIM_KEYS - set(r.get("simulated") or {}))
            if "simulated" not in r:
                out.append((rid, "Simulated without a simulated block saying what stands in"))
            elif missing:
                out.append((rid, f"Simulated without saying {' and '.join(missing)} (what is real and what is "
                                 "the stand-in)"))
            proof = r.get("stand_in_proof")
            if not proof:
                out.append((rid, "Simulated without stand_in_proof (a test that a bad stand-in changes the "
                                 "result, and a statement of how a real input would replace the stand-in)"))
            else:
                refs = [("bad_input", proof["bad_input"])]
                if proof["replaceable"].get("test"):
                    refs.append(("replaceable", proof["replaceable"]["test"]))
                for label, ref in refs:
                    why = resolve({"kind": "test", "ref": ref})
                    if why:
                        out.append((rid, f"stand_in_proof {label} test {ref!r} does not resolve: {why}"))
        if status == "Not Demonstrated" and evidence:
            out.append((rid, "Not Demonstrated but cites evidence: a record that claims evidence is not "
                             "'not built'"))
        if status in NEEDS_APPROVAL:
            if not r.get("proposal"):
                out.append((rid, f"{status} without a proposal (who proposed it, when)"))
            if not r.get("approval"):
                out.append((rid, f"{status} not approved by the operator ({OPERATOR})"))
    return out


def summary(doc, applicable):
    """Counts the trust center and the SDR can show: by status, and by status
    within each force (MUST, SHOULD, ...)."""
    by_status = Counter(r["status"] for r in doc["records"])
    by_force = {}
    for r in doc["records"]:
        f = applicable[r["frr_id"]]["force"]
        by_force.setdefault(f, Counter())[r["status"]] += 1
    simulated = Counter(r["simulated"]["counterparty"] for r in doc["records"] if "simulated" in r)
    unapproved = sum(1 for r in doc["records"] if r["status"] in NEEDS_APPROVAL and not r.get("approval"))
    return {"rules": len(doc["records"]),
            "by_status": {s: by_status.get(s, 0) for s in STATUSES},
            "awaiting_approval": unapproved,
            "simulated": {c: simulated[c] for c in sorted(simulated)},
            "by_force": {f: {s: c.get(s, 0) for s in STATUSES} for f, c in sorted(by_force.items())}}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Validate data/frr-records.json against the pinned FedRAMP rules.")
    ap.add_argument("--records", default=str(DEFAULT_PATH))
    ap.add_argument("--ksi-applicability", default=None,
                    help="the KSI scope cuts (default data/ksi-applicability.json), held to the same approval rule")
    ap.add_argument("--claims", action="store_true",
                    help="also fail on any record whose fields do not support its status (the deploy gate)")
    args = ap.parse_args(argv)
    doc = load(args.records)
    print(json.dumps(summary(doc, _rules.applicable_provider_rules()), indent=2))
    if args.claims:
        import _ksi_applicability  # imports this module; loaded here to keep the import one-way
        bad = claims(doc, resolver()) + _ksi_applicability.claims(_ksi_applicability.load(args.ksi_applicability))
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
