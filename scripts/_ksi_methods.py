"""Facts for the KSI method count (FRC-CSX-VVK); the decision is
policies/compliance/ksi.rego.

What this module observes, and nothing more:

- the OPA rules' annotations (custom.ksi_ids, custom.resource_types,
  custom.runtime_only), read with `opa inspect`;
- observations: each resource the OPA gate evaluated, by stage and Terraform
  type, with the rule IDs that reported a violation on it. `plan` comes from
  this deploy's KSI signal; `live` from the runtime signal, counted only while
  it is inside its freshness window;
- checks (data/ksi-methods.json): whether each mechanism ran at each of its
  stages and passed. `deploy` reads this build's VDR detection record and KSI
  signal; `nightly` the evidence-nightly beacon (vdr-status.json); `live` the
  runtime signal. A stale beacon or runtime signal means the mechanism did not
  run there;
- the KSI scope cuts (data/ksi-applicability.json): approved only when the
  operator signed them.

Stdlib only, fail-closed.
"""

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _freshness  # noqa: E402
import _triage  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
METHODS_PATH = REPO / "data" / "ksi-methods.json"
APPLICABILITY_PATH = REPO / "data" / "ksi-applicability.json"
CATALOG_PATH = REPO / "infrastructure" / "schemas" / "ksi-catalog.json"
OPA_POLICY_DIR = REPO / "infrastructure" / "policy"
POLICY = REPO / "policies" / "compliance" / "ksi.rego"
OPERATOR = "Sam Aydlette"
GATE_POLICY_ID = "terraform.compliance"
OBSERVE_KINDS = ("detection-feed", "runtime-divergence", "beacon", "plan-gate")
STAGES = ("plan", "live", "deploy", "nightly")


def _fail(msg):
    raise SystemExit(f"::error::KSI methods: {msg} (fail-closed)")


def _json(path, what):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{what} {path} is unreadable: {exc}")


# --- registers ------------------------------------------------------------------

def catalog_ksis(path=CATALOG_PATH):
    cat = _json(path, "KSI catalog")
    return sorted(i["id"] for fam in (cat.get("KSI") or {}).values() for i in fam.get("indicators", []) or [])


def load_methods(path=METHODS_PATH, known=None):
    doc = _json(path, "methods register")
    if doc.get("schema") != "ksi-methods/2" or not isinstance(doc.get("methods"), list):
        _fail(f"{path} is not a ksi-methods/2 document")
    known = set(known if known is not None else catalog_ksis())
    keys = set()
    for m in doc["methods"]:
        key = m.get("key") if isinstance(m, dict) else None
        if not isinstance(key, str) or key in keys:
            _fail(f"{path}: a method has no key, or a duplicate one ({key!r})")
        keys.add(key)
        if set(m) != {"key", "ksis", "observe", "stages", "measure"}:
            _fail(f"{key}: fields must be key, ksis, observe, stages, measure")
        if not m["ksis"] or set(m["ksis"]) - known:
            _fail(f"{key}: ksis must be KSIs in the catalog ({sorted(set(m['ksis']) - known)})")
        if not m["stages"] or set(m["stages"]) - set(STAGES):
            _fail(f"{key}: stages must be drawn from {list(STAGES)}")
        obs = m["observe"]
        if not isinstance(obs, dict) or obs.get("kind") not in OBSERVE_KINDS:
            _fail(f"{key}: observe.kind must be one of {list(OBSERVE_KINDS)}")
        if obs["kind"] == "detection-feed" and not (isinstance(obs.get("feeds"), list) and obs["feeds"]):
            _fail(f"{key}: a detection-feed method names its feeds")
        if obs["kind"] == "beacon" and not isinstance(obs.get("field"), str):
            _fail(f"{key}: a beacon method names its field")
        if not isinstance(m["measure"], str) or not m["measure"].strip():
            _fail(f"{key}: measure must say what the mechanism tests")
    return doc["methods"]


def load_applicability(path=APPLICABILITY_PATH, known=None):
    doc = _json(path, "KSI applicability")
    if doc.get("schema") != "ksi-applicability/2" or not isinstance(doc.get("ksis"), list):
        _fail(f"{path} is not a ksi-applicability/2 document")
    known = set(known if known is not None else catalog_ksis())
    out = []
    for k in doc["ksis"]:
        kid = k.get("ksi_id")
        if kid not in known or k.get("status") != "Not Applicable" \
                or not isinstance(k.get("not_applicable"), str) or not k["not_applicable"].strip():
            _fail(f"{path}: {kid!r} must be a catalog KSI with status Not Applicable and its missing trigger")
        out.append({"ksi_id": kid, "not_applicable": k["not_applicable"],
                    "approved": (k.get("approval") or {}).get("by") == OPERATOR})
    return out


def rule_annotations(policy_dir=OPA_POLICY_DIR):
    try:
        proc = subprocess.run([_triage.opa_binary(), "inspect", "-a", str(policy_dir), "--format", "json"],
                              capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        _fail(f"opa inspect did not run: {exc}")
    if proc.returncode != 0:
        _fail(f"opa inspect exited {proc.returncode}: {proc.stderr.strip()[:500]}")
    rules = {}
    for entry in json.loads(proc.stdout).get("annotations") or []:
        ann = entry.get("annotations") or {}
        c = ann.get("custom") or {}
        if ann.get("scope") != "rule" or not c.get("ksi_ids"):
            continue
        r = rules.setdefault(c["id"], {"id": c["id"], "ksi_ids": [], "resource_types": [], "runtime_only": False})
        r["ksi_ids"] = sorted(set(r["ksi_ids"]) | set(c["ksi_ids"]))
        r["resource_types"] = sorted(set(r["resource_types"]) | set(c.get("resource_types") or []))
        r["runtime_only"] = r["runtime_only"] or bool(c.get("runtime_only"))
    if not rules:
        _fail(f"no rule in {policy_dir} declares ksi_ids")
    return [rules[k] for k in sorted(rules)]


# --- observations -----------------------------------------------------------------

def _fresh(doc, name, now, cfg):
    """True when `doc` (a published artifact) is inside its freshness window."""
    if not isinstance(doc, dict):
        return False
    art = _freshness.artifact_for(cfg, name)
    if art is None:
        _fail(f"{name} has no freshness window")
    ts = _freshness.timestamp_of(art, json.dumps(doc))
    try:
        t = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return False
    return timedelta(0) <= now - t <= timedelta(hours=art["max_age_hours"])


def gate_observations(signal, stage):
    """[{stage, tf_type, violation_ids}] for each resource the OPA gate evaluated."""
    if not isinstance(signal, dict):
        return []
    tf = {c["component_id"]: (c.get("attributes") or {}).get("tf_type") for c in signal.get("components") or []}
    out = []
    for v in signal.get("validations") or []:
        if (v.get("policy") or {}).get("id") != GATE_POLICY_ID:
            continue
        ids = sorted({x.get("id") for x in v.get("violations") or [] if isinstance(x, dict) and x.get("id")})
        for ref in v.get("component_refs") or []:
            if tf.get(ref):
                out.append({"stage": stage, "tf_type": tf[ref], "violation_ids": ids})
    return out


def _feeds(detection, names):
    """(ran, passed) for named detection feeds."""
    rows = [f for f in ((detection or {}).get("feeds") or []) if isinstance(f, dict) and f.get("feed") in names]
    ran = all(any(f.get("feed") == n for f in rows) for n in names)
    return ran, ran and all(f.get("status") == "ok" for f in rows)


def check_runs(methods, *, deploy_signal, vdr, beacon, runtime_signal, beacon_fresh, runtime_fresh):
    out = []
    plan = gate_observations(deploy_signal, "plan")
    for m in methods:
        obs = m["observe"]
        for stage in m["stages"]:
            ran = passed = False
            why = ""
            if stage == "nightly" and not beacon_fresh:
                why = "the nightly beacon is missing or outside its freshness window"
            elif stage == "live" and not runtime_fresh:
                why = "the runtime signal is missing, unverified or outside its freshness window"
            elif obs["kind"] == "detection-feed":
                detection = ((vdr or {}).get("methodology") or {}).get("detection") if stage == "deploy" \
                    else (beacon or {}).get("detection")
                ran, passed = _feeds(detection, obs["feeds"])
                why = "" if ran else f"the detection record lists no {'/'.join(obs['feeds'])} feed"
            elif obs["kind"] == "beacon":
                ran = obs["field"] in (beacon or {})
                passed = ran and beacon[obs["field"]] == "success"
                why = "" if ran else f"the nightly beacon has no {obs['field']} result"
            elif obs["kind"] == "runtime-divergence":
                status = ((runtime_signal or {}).get("divergence") or {}).get("status")
                ran, passed = status is not None, status == "converged"
                why = "" if ran else "the runtime signal reports no divergence result"
            elif obs["kind"] == "plan-gate":
                ran, passed = bool(plan), bool(plan) and not any(o["violation_ids"] for o in plan)
                why = "" if ran else "this deploy's signal carries no gate results"
            out.append({"key": m["key"], "ksis": m["ksis"], "stage": stage, "ran": ran, "passed": passed, "why": why})
    return out


def facts(*, deploy_signal, vdr, beacon, runtime_signal, now=None, cfg=None, methods=None,
          applicability=None, rules=None, ksis=None):
    now = now or datetime.now(timezone.utc)
    cfg = cfg or _freshness.load_freshness_config()
    beacon_fresh = _fresh(beacon, "vdr-status.json", now, cfg)
    runtime_fresh = _fresh(runtime_signal, "ksi-signal-runtime.json", now, cfg)
    known = ksis if ksis is not None else catalog_ksis()
    return {
        "ksis": known,
        "rules": rules if rules is not None else rule_annotations(),
        "observations": gate_observations(deploy_signal, "plan")
        + (gate_observations(runtime_signal, "live") if runtime_fresh else []),
        "checks": check_runs(methods if methods is not None else load_methods(known=known),
                             deploy_signal=deploy_signal, vdr=vdr, beacon=beacon, runtime_signal=runtime_signal,
                             beacon_fresh=beacon_fresh, runtime_fresh=runtime_fresh),
        "not_applicable": applicability if applicability is not None else load_applicability(known=known),
        "inputs": {"beacon_fresh": beacon_fresh, "runtime_fresh": runtime_fresh},
    }


def decide(fact_doc, policy=POLICY):
    """{"ksis": {id: {status, methods, passing, failing}}, "short": [...], "findings": [...]}."""
    out = _triage.evaluate("data.compliance.ksi.result", fact_doc, policy=policy)
    if not isinstance(out, dict) or set(out.get("ksis") or {}) != set(fact_doc["ksis"]):
        _fail("the KSI policy did not return a status for every KSI")
    return out
