"""Runs the VDR triage policy (policies/triage.rego; T7, G17).

The builder collects facts; the policy decides. One `opa eval` per report, with
every finding batched into a single input. The FedRAMP rules reach the policy as
data.rules only after scripts/_rules.py has checked their pinned sha256.

Fails closed: no `opa`, an evaluation error, an undefined result, a decision
count that does not match the input, or any entry in data.vdr.triage.errors
stops the build. A report with decisions missing is worse than no report.
"""

import atexit
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import _rules

POLICY = Path(__file__).resolve().parent.parent / "policies" / "triage.rego"
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_TIMEOUT_S = 300


def _fail(msg):
    raise SystemExit(f"::error::triage policy: {msg} (fail-closed)")


def opa_binary():
    exe = shutil.which("opa")
    if not exe:
        _fail("'opa' is not on PATH; install the version pinned in .github/workflows/deploy-with-opa.yml "
              "(OPA_VERSION / OPA_SHA256)")
    return exe


@lru_cache(maxsize=4)
def _rules_data_file(rules_dir):
    """The hash-checked rules, written once per process as {"rules": ...}."""
    rules, _ = _rules.load_rules(rules_dir)
    d = Path(tempfile.mkdtemp(prefix="vdr-triage-"))
    atexit.register(shutil.rmtree, d, True)
    p = d / "rules.json"
    p.write_text(json.dumps({"rules": rules}))
    return str(p)


def evaluate(query, input_doc, rules_dir=_rules.RULES_DIR, policy=POLICY):
    """The value of `query` against the policy, the rules and `input_doc`."""
    data_file = _rules_data_file(str(rules_dir))
    with tempfile.TemporaryDirectory(prefix="vdr-triage-in-") as td:
        inp = Path(td) / "input.json"
        inp.write_text(json.dumps(input_doc))
        try:
            proc = subprocess.run(
                [opa_binary(), "eval", "--format", "json", "-d", str(policy), "-d", data_file,
                 "-i", str(inp), query],
                capture_output=True, text=True, timeout=_TIMEOUT_S, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            _fail(f"opa eval did not run: {exc}")
    if proc.returncode != 0:
        _fail(f"opa eval exited {proc.returncode}: {proc.stderr.strip()[:2000]}")
    try:
        result = json.loads(proc.stdout).get("result") or []
        return result[0]["expressions"][0]["value"]
    except (json.JSONDecodeError, IndexError, KeyError, TypeError):
        _fail(f"{query} is undefined")


def decide(items, *, now, epss_threshold, margin_days, lev_overrides, rules_dir=_rules.RULES_DIR,
           evaluation_days=None):
    """One decision per item, in order. evaluation_days: VER-TFR-EVU, read from
    the rules by the caller (_rules.evaluation_days); None skips the check."""
    doc = {"now_ns": to_ns(now), "today": now.date().isoformat(), "epss_threshold": epss_threshold,
           "margin_days": margin_days, "lev_overrides": lev_overrides or {}, "items": items,
           **({"evaluation_days": evaluation_days} if evaluation_days is not None else {})}
    out = evaluate('{"decisions": data.vdr.triage.decisions, "errors": data.vdr.triage.errors}',
                   doc, rules_dir)
    if out.get("errors"):
        _fail("; ".join(sorted(out["errors"])))
    decisions = out.get("decisions")
    if not isinstance(decisions, list) or len(decisions) != len(items):
        _fail(f"{len(decisions or [])} decisions for {len(items)} findings")
    for item, d in zip(items, decisions, strict=True):
        if d.get("id") != item["id"]:
            _fail(f"decision for {d.get('id')!r} returned in the place of {item['id']!r}")
    return decisions


def vocabulary(rules_dir=_rules.RULES_DIR):
    """{"dispositions", "pass", "closing"} as sets, from the policy."""
    v = evaluate("data.vdr.triage.vocabulary", {"items": []}, rules_dir)
    return {k: set(v[k]) for k in ("dispositions", "pass", "closing")}


def to_ns(dt):
    """Exact integer nanoseconds since the epoch (microsecond precision)."""
    return ((dt - EPOCH) // timedelta(microseconds=1)) * 1000


def from_ns(ns, tz=timezone.utc):
    """ISO 8601 in `tz`, the inverse of to_ns."""
    return (EPOCH + timedelta(microseconds=ns // 1000)).astimezone(tz).isoformat()
