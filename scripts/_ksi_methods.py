"""The mechanisms that count as automated methods for a KSI (FRC-CSX-VVK):
infrastructure/schemas/ksi-methods.json.

A method counts for a KSI only when it genuinely tests that KSI's measures (the
strict count, operator's decision of 2026-11-06). Two kinds of method exist:

- An OPA rule counts through its own annotations: `custom.ksi_ids` names the
  KSIs it tests and `custom.resource_types` the Terraform types it evaluates
  (`["*"]` any; `custom.runtime_only` when it runs only against live
  configuration). The plan gate counts for a KSI when a rule annotated with it
  evaluated a resource of one of its types in this plan; the runtime
  re-validation, when it did so against live configuration. Family-level links
  in the inventory never count (`rule_methods`).
- Every other mechanism is an entry in the governed table, with a measure
  sentence and the verifier its result must pass before it counts:
    published           a published record, signed by a workflow scripts/_signers.py
                        allows for that file, inside its freshness-config window,
                        and passing the named check;
    vdr-feed            a detection feed of this build's VDR report (bound to this
                        inventory, Sigstore-signed, inside its window) with every
                        named feed present and passing the detection gate;
    runtime-divergence  the verified, fresh runtime signal reports `converged`;
    plan-gate           the signed KSI signal of this deploy carries its plan-gate run;
    training            scripts/_training.py's currency and completion checks.

A mechanism counts once per KSI however many records it publishes. A
mechanism whose input is a stand-in carries `stand_in_proof` (CLAUDE.md,
proof-of-concept latitude): `bad_input`, a test that feeds it a bad stand-in
and asserts a different result, and `replaceable` {statement: how a real input
would replace the stand-in and what would have to change, test: one that shows
it, where one exists}; each test named must exist. Stdlib only, fail-closed.
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _freshness  # noqa: E402
import _frr  # noqa: E402
import _scheduled_review as _sched  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PATH = REPO / "infrastructure" / "schemas" / "ksi-methods.json"
CATALOG_PATH = REPO / "infrastructure" / "schemas" / "ksi-catalog.json"
TOP_KEYS = {"$schema", "schema", "version", "description", "rationale", "methods"}
METHOD_KEYS = {"key", "mechanism", "measure", "ksis", "input", "verifier"}
OPTIONAL_METHOD_KEYS = {"stand_in_proof"}
REPLACEABLE_KEYS = {"statement", "test"}
INPUTS = ("real", "stand-in")
FEEDS = ("grype", "dependabot", "checkov", "tfsec", "codeql", "zap-api")
SIMPLE_KINDS = ("runtime-divergence", "plan-gate", "training")
KEY_RE = re.compile(r"^[a-z][a-z0-9-]*$")
NOT_EVALUATED = (False, "not evaluated in this build")


def _fail(msg):
    raise SystemExit(f"::error::KSI methods: {msg} (fail-closed)")


def _ts(v):
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


# --- the checks a published record must pass ---------------------------------------------

def _check_audit_log(doc, now):
    return _sched.method_status("audit-log-review", doc, now)


def _check_recovery(doc, now):
    return _sched.method_status("recovery-exercise", doc, now)


def _check_reconcile(doc, now):
    if not isinstance(doc, dict) or doc.get("schema") != "reconcile-report/1" or doc.get("result") != "pass":
        return False, "the record is not a passing reconcile-report/1"
    a = next((i for i in doc.get("invariants") or [] if isinstance(i, dict) and i.get("id") == "a"), None)
    if not a or a.get("status") != "held":
        return False, "invariant (a) was not checked against live state (deferred or absent)"
    return True, None


def _check_security_settings(doc, now):
    settings = doc.get("settings") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or doc.get("schema") != "security-settings/1" or not isinstance(settings, list) \
            or not settings:
        return False, "the record is not a security-settings/1 export with settings"
    bad = [s for s in settings if not isinstance(s, dict) or s.get("result") in ("deviation", "not-read")]
    if bad:
        return False, f"{len(bad)} setting(s) deviate or were not read"
    return True, None


def _check_conformance(doc, now):
    if not isinstance(doc, dict) or doc.get("schema") != "conformance-results/1" or not doc.get("tests"):
        return False, "the record is not a conformance-results/1 document with tests"
    failed = [t.get("id") for t in doc["tests"] if not isinstance(t, dict) or t.get("result") == "failed"]
    if failed:
        return False, f"{len(failed)} conformance test(s) failed"
    return True, None


def _check_inbox(doc, now):
    if not isinstance(doc, dict) or doc.get("report_type") != "fedramp-inbox-simulation" \
            or doc.get("simulation") is not True or not doc.get("cases"):
        return False, "the record is not a labelled inbox simulation with cases"
    if doc.get("result") != "pass":
        return False, "the simulation did not pass"
    return True, None


def _check_availability(doc, now):
    if not isinstance(doc, dict) or doc.get("feed_type") != "availability" or not doc.get("measured_at") \
            or not doc.get("daily"):
        return False, "the record carries no availability measurement"
    return True, None


def _check_scn_evaluations(doc, now):
    entries = doc.get("entries") if isinstance(doc, dict) else None
    if not isinstance(entries, list) or not entries or not isinstance(doc.get("unrecorded"), int):
        return False, "the record is not an SCN evaluation log with entries"
    problems = [e for e in entries if not isinstance(e, dict) or e.get("problem")]
    if problems or doc["unrecorded"]:
        return False, (f"{max(len(problems), doc['unrecorded'])} merged change(s) carry no valid significant-change "
                       "evaluation")
    return True, None


def _scheduled(key):
    def chk(doc, now):
        return _sched.method_status(key, doc, now)
    chk.__name__ = f"_check_{key.replace('-', '_')}"
    return chk


def _incident_log(section):
    def chk(doc, now):
        if not isinstance(doc, dict) or doc.get("schema") != "incident-reports/1":
            return False, "the record is not an incident-reports/1 log"
        sec = doc.get(section)
        if not isinstance(sec, dict):
            return False, f"the incident log carries no {section} check"
        if not (sec.get("planted") or {}).get("caught"):
            return False, f"the {section} check's planted case was not caught"
        if sec.get("result") != "pass":
            return False, f"the {section} check did not pass"
        return True, None
    chk.__name__ = f"_check_incident_{section}"
    return chk


def _check_security_txt(doc, now):
    st = doc.get("securityTxt") if isinstance(doc, dict) else None
    if not isinstance(st, dict) or not st.get("checks"):
        return False, "the security settings record carries no security.txt check"
    if st.get("result") != "pass":
        return False, "security.txt is not valid: " + "; ".join(c["id"] for c in st["checks"] if not c.get("ok"))
    return True, None


CHECKS = {"audit-log-review": _check_audit_log, "recovery-exercise": _check_recovery,
          "reconcile": _check_reconcile, "security-settings": _check_security_settings,
          "conformance": _check_conformance, "inbox-simulation": _check_inbox,
          "availability": _check_availability, "scn-evaluations": _check_scn_evaluations,
          "security-review": _scheduled("security-review"), "board-meeting": _scheduled("board-meeting"),
          "cfo-review": _scheduled("cfo-review"), "tabletop": _scheduled("tabletop"),
          "disclosure-drill": _scheduled("disclosure-drill"), "phishing-drill": _scheduled("phishing-drill"),
          "incident-lessons": _incident_log("lessons_learned"), "incident-patterns": _incident_log("patterns"),
          "security-txt": _check_security_txt}


# --- the table ------------------------------------------------------------------------------

def _catalog_ids(path=CATALOG_PATH):
    cat = json.loads(Path(path).read_text())
    return {i["id"] for f in cat["KSI"].values() for i in f["indicators"]}


def _text(v, where):
    if not isinstance(v, str) or not v.strip():
        _fail(f"{where} must be a non-empty string")


def _stand_in_proof(m, key, repo):
    proof = m.get("stand_in_proof")
    if m["input"] != "stand-in":
        if proof is not None:
            _fail(f"{key}: stand_in_proof is for a method whose input is a stand-in")
        return
    if not isinstance(proof, dict) or set(proof) != {"bad_input", "replaceable"} \
            or not isinstance(proof.get("replaceable"), dict) or "statement" not in proof["replaceable"] \
            or set(proof["replaceable"]) - REPLACEABLE_KEYS:
        _fail(f"{key}: a stand-in method needs stand_in_proof {{bad_input, replaceable: {{statement, test?}}}}")
    _text(proof["replaceable"]["statement"], f"{key}: stand_in_proof.replaceable.statement")
    for ref in (proof["bad_input"], proof["replaceable"].get("test")):
        if ref is None:
            continue
        why = _frr._resolve_test(ref, repo) if isinstance(ref, str) else "is not a test node id"
        if why:
            _fail(f"{key}: stand_in_proof test {ref!r} {why}")


def validate(doc, known, published, where="infrastructure/schemas/ksi-methods.json", repo=REPO):
    """`known` is the catalog's KSI IDs; `published` the freshness-governed paths."""
    if not isinstance(doc, dict) or doc.get("schema") != "ksi-methods/1":
        _fail(f"{where} is not a ksi-methods/1 document")
    if set(doc) - TOP_KEYS:
        _fail(f"{where}: unknown top-level field(s) {sorted(set(doc) - TOP_KEYS)}")
    for k in ("version", "description", "rationale"):
        _text(doc.get(k), k)
    methods = doc.get("methods")
    if not isinstance(methods, list) or not methods:
        _fail(f"{where}: methods must be a non-empty list")
    seen = set()
    for m in methods:
        key = m.get("key") if isinstance(m, dict) else None
        if not isinstance(key, str) or not KEY_RE.match(key):
            _fail(f"{where}: a method has no key")
        if key in seen:
            _fail(f"duplicate method {key}")
        seen.add(key)
        if set(m) - OPTIONAL_METHOD_KEYS != METHOD_KEYS:
            _fail(f"{key}: fields must be exactly {sorted(METHOD_KEYS)}, and stand_in_proof for a stand-in")
        _text(m["mechanism"], f"{key}: mechanism")
        _text(m["measure"], f"{key}: measure")
        ksis = m["ksis"]
        if not isinstance(ksis, list) or not ksis or len(set(ksis)) != len(ksis):
            _fail(f"{key}: ksis must be a non-empty list without repeats")
        unknown = sorted(set(ksis) - known)
        if unknown:
            _fail(f"{key}: {', '.join(unknown)} not in the KSI catalog")
        if m["input"] not in INPUTS:
            _fail(f"{key}: input must be one of {list(INPUTS)}")
        _stand_in_proof(m, key, Path(repo))
        v = m["verifier"]
        kind = v.get("kind") if isinstance(v, dict) else None
        if kind == "published":
            if set(v) != {"kind", "artifact", "check"}:
                _fail(f"{key}: a published verifier is {{kind, artifact, check}}")
            if v["artifact"] not in published:
                _fail(f"{key}: {v['artifact']} is not a freshness-governed published artifact")
            if v["check"] not in CHECKS:
                _fail(f"{key}: check {v['check']!r} is not one of {sorted(CHECKS)}")
        elif kind == "vdr-feed":
            feeds = v.get("feeds")
            if set(v) != {"kind", "feeds"} or not isinstance(feeds, list) or not feeds \
                    or any(f not in FEEDS for f in feeds):
                _fail(f"{key}: a vdr-feed verifier is {{kind, feeds: drawn from {list(FEEDS)}}}")
        elif kind in SIMPLE_KINDS:
            if set(v) != {"kind"}:
                _fail(f"{key}: a {kind} verifier takes no other field")
        else:
            _fail(f"{key}: verifier kind {kind!r} is not one of {['published', 'vdr-feed', *SIMPLE_KINDS]}")
    return doc


def load(path=None, catalog=None, freshness=None):
    p = Path(path) if path else DEFAULT_PATH
    if not p.is_file():
        _fail(f"{p} not found")
    try:
        doc = json.loads(p.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{p} is not valid JSON: {exc}")
    cfg = _freshness.load_freshness_config(freshness)
    return validate(doc, _catalog_ids(catalog or CATALOG_PATH), {a["path"] for a in cfg["artifacts"]}, str(p))


def by_key(doc):
    return {m["key"]: m for m in doc["methods"]}


def published_keys(doc):
    """{key: artifact file name} for the methods whose result is a published record."""
    return {m["key"]: m["verifier"]["artifact"].split("/", 1)[1] for m in doc["methods"]
            if m["verifier"]["kind"] == "published"}


# --- verifiers ------------------------------------------------------------------------------

def verify_published(method, path, bundle, now, cfg, verify_signature, identities):
    """(ok, reason) for one published record: signature by an allowed
    publisher, inside its freshness window, and passing its check."""
    v = method["verifier"]
    name = v["artifact"].split("/", 1)[1]
    if not Path(path).is_file() or not Path(bundle).is_file():
        return False, f"{name} or its signature is not available to this build"
    try:
        ok = verify_signature(path, bundle, identities)
    except OSError as exc:
        return False, f"the signature of {name} could not be checked ({type(exc).__name__})"
    if not ok:
        return False, f"the signature of {name} does not verify against its publisher"
    try:
        raw = Path(path).read_bytes()
        doc = json.loads(raw)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return False, f"{name} is unreadable"
    art = _freshness.artifact_for(cfg, name)
    at = _ts(_freshness.timestamp_of(art, raw)) if art else None
    if art is None or at is None:
        return False, f"{name} carries no timestamp its freshness window can be measured from"
    if not 0 <= (now - at).total_seconds() <= art["max_age_hours"] * 3600:
        return False, f"{name} is outside its {art['max_age_hours']}-hour window"
    return CHECKS[v["check"]](doc, now)


def verify_vdr_feeds(method, vdr_usable, vdr):
    """(ok, reason) for a detection-feed method: `vdr_usable` is (ok, reason)
    for the VDR report itself (bound, signed, fresh)."""
    if not vdr_usable[0]:
        return False, vdr_usable[1]
    feeds = ((vdr.get("methodology") or {}).get("detection") or {}).get("feeds") or []
    for name in method["verifier"]["feeds"]:
        rows = [f for f in feeds if isinstance(f, dict) and f.get("feed") == name]
        if not rows:
            return False, f"the VDR's detection record lists no {name} feed"
        if any(f.get("status") != "ok" for f in rows):
            return False, f"the {name} feed failed the detection gate"
    return True, None
