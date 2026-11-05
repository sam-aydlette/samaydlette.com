#!/usr/bin/env python3
# =============================================================================
# VDR REPORT AGGREGATOR (FedRAMP 20x Vulnerability Detection and Response)
# =============================================================================
# Aggregates vulnerability findings across the system's SAST/SCA tools, applies
# the FedRAMP 20x VDR evaluation framework (PAIN N1-N5, IRV, LEV, KEV), and
# emits a single VDR report. The build itself is the report (per VER-RPT-PER
# and VER-TFR-MHR — at least monthly cadence is satisfied by per-deploy
# emission).
#
# The script blocks the build (exit 1) if any finding exceeds the Class C
# remediation timeframes for its PAIN/IRV/LEV combination per VDR-TFR-PVR.
# Class C is the "Moderate" equivalent class targeted by this system.
#
# Inputs (all optional — script handles missing/empty inputs gracefully):
#   --opa PATH                Output of scripts/terraform-plan.sh (OPA results)
#   --dependabot PATH         Dependabot alerts in GitHub API JSON form
#   --grype PATH              Grype SCA scan output (`grype -o json`); the
#                             Software Composition Analysis source for the Silk
#                             Reeling app's Python (Lambda) and JS (SPA)
#                             dependency trees that Dependabot does not watch.
#   --checkov PATH            Checkov SARIF or JSON output
#   --tfsec PATH              tfsec JSON output
#   --kev PATH                CISA KEV catalog JSON (cisa.gov format)
#   --checkov-yaml PATH       Path to .checkov.yaml; the skip-check list is
#                             read and each entry becomes a risk-accepted entry
#                             with decision cross-references (VER-RPT-AVI fields
#                             populated).
#   --previous-vdr PATH       Path to the previous VDR report; used as the
#                             first-detected ledger so SLA clocks (Class C
#                             remediation timeframes from VDR-TFR-PVR) carry
#                             across builds. Without this the script treats
#                             every finding as newly-detected.
#   --output PATH             Output VDR report path (default: vdr-report.json)
#
# Exit codes:
#   0 — no findings exceed Class C remediation timeframes
#   1 — at least one finding is past its SLA, or any KEV is unmitigated
#   2 — script error (bad input, etc.)
# =============================================================================

import argparse
from collections import Counter
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

# Shared helpers live next to this script; keep it runnable from any cwd.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _offering  # noqa: E402
import _codeql  # noqa: E402
import _decisions  # noqa: E402
import _evaluation  # noqa: E402
import _gates  # noqa: E402
import _redact  # noqa: E402
import _rules  # noqa: E402
import _triage  # noqa: E402
import _zap_api  # noqa: E402


# =============================================================================
# GOVERNED PAIN CLASSIFIER CONFIG (see infrastructure/schemas/vdr-pain-config.json)
# =============================================================================
# The deterministic CVSS-Environmental PAIN method has exactly two classes of
# tunable knob — the word thresholds and the EPSS likely-exploitable threshold —
# plus the impact/requirement weight tables and the tag-to-requirement maps.
# The memo (s14) requires these to live in GOVERNED CONFIGURATION, not as in-band
# ad-hoc constants, so they are loaded from a versioned, schema-backed JSON file
# and never silently defaulted. The FedRAMP VDR-TFR-PVR remediation-day matrix is
# NOT a knob here either: it is FedRAMP's, read at build time from the pinned
# machine-readable rules (scripts/_rules.py), never typed into code.
#
# The config is loaded, validated fail-closed, recorded in the report's
# methodology block, and consumed by assign_pain's CVSS-Environmental
# derivation. The severity proxy remains only as the fallback for findings that
# carry no CVSS vector.
DEFAULT_PAIN_CONFIG = (Path(__file__).resolve().parent.parent
                       / "infrastructure" / "schemas" / "vdr-pain-config.json")


def _validate_pain_config(cfg, where):
    """Fail-closed structural validation of the governed PAIN config. A malformed
    or incomplete config is an error, never a silent fallback to built-in
    defaults — that is what keeps the governed knobs from being bypassed."""
    required = ["version", "pain_word_thresholds", "epss_threshold",
                "epss_threshold_rationale", "isc_cap",
                "cvss_impact_weights", "requirement_weights",
                "data_sensitivity_to_requirement", "mission_criticality_to_requirement",
                "multi_agency_default", "likely_overdue_margin_days",
                "likely_overdue_margin_rationale"]
    missing = [k for k in required if k not in cfg]
    if missing:
        raise SystemExit(f"::error::PAIN config {where} missing required keys: {missing}")
    t = cfg["pain_word_thresholds"]
    th = [t.get("minimal_to_narrow"), t.get("narrow_to_disruptive"),
          t.get("disruptive_to_debilitating")]
    if any(not isinstance(x, (int, float)) for x in th):
        raise SystemExit(f"::error::PAIN config {where}: word thresholds must be numbers")
    if not (0 <= th[0] < th[1] < th[2] <= 1):
        raise SystemExit(f"::error::PAIN config {where}: word thresholds must be strictly "
                         f"ascending in [0,1], got {th}")
    if not (0 <= cfg["epss_threshold"] <= 1):
        raise SystemExit(f"::error::PAIN config {where}: epss_threshold must be in [0,1]")
    # The threshold is a risk-tolerance decision; it is not published without its reason.
    rationale = cfg["epss_threshold_rationale"]
    if not isinstance(rationale, str) or not rationale.strip():
        raise SystemExit(f"::error::PAIN config {where}: epss_threshold_rationale must be a non-empty string")
    if not (0 < cfg["isc_cap"] <= 1):
        raise SystemExit(f"::error::PAIN config {where}: isc_cap must be in (0,1]")
    if not isinstance(cfg["likely_overdue_margin_days"], int) or cfg["likely_overdue_margin_days"] < 1:
        raise SystemExit(f"::error::PAIN config {where}: likely_overdue_margin_days must be a positive integer")
    if not str(cfg["likely_overdue_margin_rationale"]).strip():
        raise SystemExit(f"::error::PAIN config {where}: likely_overdue_margin_rationale must be non-empty")
    if cfg["multi_agency_default"] not in (0, 1):
        raise SystemExit(f"::error::PAIN config {where}: multi_agency_default must be 0 or 1")


def load_pain_config(path=None):
    """Load + validate the governed PAIN classifier config. Returns
    (config_dict, sha256_hex). Fails closed on a missing/malformed file so the
    governed calibration is always present and auditable (memo s14)."""
    cfg_path = Path(path) if path else DEFAULT_PAIN_CONFIG
    if not cfg_path.exists():
        raise SystemExit(f"::error::PAIN config not found at {cfg_path}; the governed "
                         f"classifier config is required (fail-closed).")
    raw = cfg_path.read_bytes()
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"::error::PAIN config at {cfg_path} is not valid JSON: {exc}") from exc
    _validate_pain_config(cfg, cfg_path)
    return cfg, hashlib.sha256(raw).hexdigest()


# =============================================================================
# CHECKOV/TFSEC CHECK ID → DECISION (data/decisions.json)
# =============================================================================
# Every suppressed configuration check resolves to one in-force record in the
# decision register (CR26; it replaced the POA&M): risk-accepted (a real
# weakness, accepted) or false-positive (the scanner is wrong). A suppression
# with no record surfaces with decision_id null, and reconciliation fails on it.
# Loaded once, fail-closed: an unreadable register stops the build.
DECISIONS_PATH = _decisions.DEFAULT_PATH
DECISIONS = _decisions.load(DECISIONS_PATH)
RISK_ACCEPTED_BY_CHECK_ID, FALSE_POSITIVE_BY_CHECK_ID = _decisions.check_maps(DECISIONS)


def use_decisions(path):
    """Rebind the register (main's --decisions)."""
    global DECISIONS_PATH, DECISIONS, RISK_ACCEPTED_BY_CHECK_ID, FALSE_POSITIVE_BY_CHECK_ID
    DECISIONS_PATH = Path(path)
    DECISIONS = _decisions.load(DECISIONS_PATH)
    RISK_ACCEPTED_BY_CHECK_ID, FALSE_POSITIVE_BY_CHECK_ID = _decisions.check_maps(DECISIONS)


# tfsec (Aqua AVD-*) rule IDs → their Checkov equivalent, so a tfsec finding for
# the same condition routes to the same decision as the Checkov check. Without this
# tfsec findings have no suppression path and surface as orphaned-open (the
# AVD-AWS-0089 / AVD-AWS-0132 log-bucket findings in the audit).
TFSEC_TO_CHECKOV = {
    "AVD-AWS-0089": "CKV_AWS_18",   # S3 server access logging enabled
    "AVD-AWS-0132": "CKV_AWS_145",  # S3 encryption uses a customer-managed key
    "AVD-AWS-0015": "CKV_AWS_35",   # CloudTrail log files use a customer-managed key
    "AVD-AWS-0162": "CKV2_AWS_10",  # CloudTrail CloudWatch Logs integration
}


def normalize_check_id(tool_id):
    """Map a tfsec AVD id to its Checkov equivalent; pass other ids through."""
    return TFSEC_TO_CHECKOV.get(tool_id, tool_id)


def classify_finding(tool_id):
    """Return (disposition, decision_id) for a config-scanner finding.

    disposition is "risk-accepted" or "false-positive" for a documented
    suppression, else (None, None) for a genuinely-open finding that must be
    remediated or given a decision record (the reconciliation gate fails closed
    on any VDR finding left without a decision_id)."""
    cid = normalize_check_id(tool_id or "")
    if cid in RISK_ACCEPTED_BY_CHECK_ID:
        return ("risk-accepted", RISK_ACCEPTED_BY_CHECK_ID[cid])
    if cid in FALSE_POSITIVE_BY_CHECK_ID:
        return ("false-positive", FALSE_POSITIVE_BY_CHECK_ID[cid])
    return (None, None)


# =============================================================================
# VULNERABILITY DECISIONS (data/decisions.json, applies_to.vuln_ids)
# =============================================================================
# A vulnerability from an SCA or DAST scanner (Grype/Dependabot/ZAP) has no
# check ID; it is decided by a record in the decision register that names it in
# applies_to.vuln_ids. The vulnerability gate reads the same register through
# scripts/_decisions.py, and resolves a finding's key exactly as
# register_vuln_id() does (cve, else tracking_id, else tool_id), so the two
# gates cannot disagree about which decision a finding resolves to. Whether a
# record is in force, and whether its disposition passes, is the triage
# policy's decision (policies/triage.rego).

# Scanner sources whose findings are vulnerabilities (governed by the register)
# rather than configuration findings (governed by .checkov.yaml + the maps
# above). Mirrors vuln-gate.py's VULN_SOURCES.
VULN_SOURCES = {"grype", "zap", "dependabot", "codeql"}

# The disposition vocabulary (REQ-DSP-3), the dispositions that pass the
# vulnerability gate, and those that close a finding for the deadline gate are
# defined in policies/triage.rego (vocabulary), which decides with them:
#   false-positive          the reason it is not exploitable lives inside the
#                           scanned artifact and it never was (REQ-DSP-4)
#   mitigated               a named control, verified by a named check, protects it
#   vendor-dependency       known, exploitable, no fix exists yet; the clock runs
#   under-investigation     not yet known whether it applies; the clock runs
#   operational-requirement Rev5 term for a deliberate acceptance, kept until the
#                           Rev5 term kept for existing records; equivalent to accepted
#   accepted                will not fix; carries the acceptance explanation
#   remediate               a fix is planned; the clock runs


def triage_vocabulary():
    """{"dispositions", "pass", "closing"} from the triage policy."""
    return _triage.vocabulary()


NOT_RECORDED = "not recorded"
_DECISION_FIELDS = ("decided_by", "decided_on", "review_by")


def _decision_fields(entry):
    """REQ-DSP-1: every decision field published; an unrecorded one says so."""
    return {k: (entry or {}).get(k) or NOT_RECORDED for k in _DECISION_FIELDS}


def load_disposition_register(path=None):
    """{vuln_id: entry} from the decision register (default: the one loaded).
    Fails closed on a missing or invalid register (scripts/_decisions.py)."""
    reg = _decisions.load(path) if path else DECISIONS
    return _decisions.vuln_register(reg)


def register_vuln_id(finding):
    """The register key for a finding, resolved exactly as vuln-gate.py does."""
    return finding.get("cve") or finding.get("tracking_id") or finding.get("tool_id")


def register_entry(finding, register):
    """(key, entry) from the register for an SCA/DAST finding, or None. Whether
    the entry is in force is the triage policy's decision."""
    if finding.get("source") not in VULN_SOURCES:
        return None
    key = register_vuln_id(finding)
    entry = register.get(key)
    return (key, entry) if entry else None


def classify_vulnerability(finding, register, today=None, mitigation=None):
    """(disposition, decision_id) the triage policy gives an SCA/DAST finding from the
    register, or (None, None). Only a record in force, with a passing disposition
    and a decision reference, confers anything; an entry with no decision_id leaves the
    finding open so invariant (h) fails rather than publish handled-but-untracked."""
    reg = register_entry(finding, register)
    if not reg:
        return (None, None)
    d = _decide_one(finding, register={"key": reg[0], "entry": reg[1]}, mitigation=mitigation,
                    today=today, kind="finding")
    return (d["disposition"], d["decision_id"]) if d["decision_id"] else (None, None)


# =============================================================================
# MITIGATIONS (data/mitigations.json) AND THE LIVE READ (rule 1)
# =============================================================================
# A mitigation names a control by inventory component ID, the control's
# fingerprint when the decision was made, and a verifying check. It is void when
# the control's fingerprint changes (T24), when the check stops passing or has no
# result (T25), when the control leaves the inventory, or past review_by. A void
# mitigation takes its clock reset with it (clock_facts).
#
# effect:
#   full                     fully mitigated: NLEV, lowest impact level. Rule 1:
#                            only when the verifying check reads live state, i.e.
#                            the signed runtime signal, verified and fresh.
#   not-reachable            the finding is NIRV
#   not-likely-exploitable   the finding is NLEV (never for a KEV)
MITIGATIONS_PATH = Path(__file__).resolve().parent.parent / "data" / "mitigations.json"
RUNTIME_PUBKEY_PATH = (Path(__file__).resolve().parent.parent / "infrastructure" / "keys"
                       / "runtime-signing-key.json")
MITIGATION_EFFECTS = {"full", "not-reachable", "not-likely-exploitable"}
VERIFYING_SIGNALS = {"runtime", "deploy"}
# The runtime emitter runs daily; two days allows one missed run. Moves to the
# governed freshness config with the other windows.
RUNTIME_SIGNAL_MAX_AGE_HOURS = 48
RUNTIME_SIGNAL_URI = "https://samaydlette.com/.well-known/ksi-signal-runtime.json"


def component_fingerprint(component):
    """sha256 over the component's canonical JSON. Any change to the control's
    declared configuration changes it and voids the mitigations that name it."""
    canon = json.dumps(component, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


def load_mitigations(path=None):
    """{id: record} from the governed mitigations file. Missing file: none. A
    malformed record fails the build: a mitigation that silently fails to load
    would put a finding back on an expired clock without saying why, and one
    that loads half-formed could clear a finding it should not."""
    p = Path(path) if path else MITIGATIONS_PATH
    if not p.exists():
        return {}
    try:
        doc = json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"::error::mitigations at {p} are not valid JSON: {exc}") from exc
    out = {}
    for mid, m in (doc.get("mitigations") or {}).items():
        where = f"mitigation {mid} in {p}"
        if not isinstance(m, dict):
            raise SystemExit(f"::error::{where} is not an object")
        ctl, vc = m.get("control") or {}, m.get("verifying_check") or {}
        missing = [k for k in ("finding", "justification", "decided_by", "decided_on", "review_by")
                   if not m.get(k)]
        missing += [f"control.{k}" for k in ("component_id", "fingerprint") if not ctl.get(k)]
        missing += [f"verifying_check.{k}" for k in ("signal", "policy") if not vc.get(k)]
        if missing:
            raise SystemExit(f"::error::{where} is missing {', '.join(missing)}")
        if m.get("effect") not in MITIGATION_EFFECTS:
            raise SystemExit(f"::error::{where} effect {m.get('effect')!r} is not one of {sorted(MITIGATION_EFFECTS)}")
        if vc["signal"] not in VERIFYING_SIGNALS:
            raise SystemExit(f"::error::{where} verifying_check.signal {vc['signal']!r} is not one of {sorted(VERIFYING_SIGNALS)}")
        for k in ("decided_on", "review_by"):
            try:
                date.fromisoformat(str(m[k]))
            except ValueError as exc:
                raise SystemExit(f"::error::{where} {k} {m[k]!r} is not a date") from exc
        out[mid] = m
    return out


def load_runtime_signal(path, pubkey_path=None, now=None, max_age_hours=RUNTIME_SIGNAL_MAX_AGE_HOURS):
    """The signed runtime signal: the only live read a mitigation can cite.

    Verified against the committed P-256 key (infrastructure/keys/
    runtime-signing-key.json) with the signer's canonical form
    (sorted keys, compact, provenance.attestation removed). Anything short of a
    verified, fresh signal yields no validations a full mitigation can use."""
    now = now or datetime.now(timezone.utc)
    out = {"verified": False, "fresh": False, "reason": None, "validations": [], "emitted_at": None}
    p = Path(path) if path else None
    if not p or not p.exists():
        out["reason"] = "no runtime signal supplied"
        return out
    try:
        sig = json.loads(p.read_text())
    except json.JSONDecodeError:
        out["reason"] = "runtime signal is not valid JSON"
        return out
    try:
        import base64
        import copy
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        out["reason"] = "cryptography is not installed; the runtime signal cannot be verified"
        return out
    try:
        key_doc = json.loads(Path(pubkey_path or RUNTIME_PUBKEY_PATH).read_text())
        pem = key_doc["public_key_pem"].encode("ascii")
        if hashlib.sha256(pem).hexdigest() != key_doc.get("public_key_sha256"):
            raise ValueError("pinned key does not match its recorded sha256")
        key = serialization.load_pem_public_key(pem)
        raw = base64.b64decode(sig["provenance"]["attestation"]["signature"])
        body = copy.deepcopy(sig)
        body["provenance"].pop("attestation", None)
        canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        key.verify(raw, canon, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, KeyError, TypeError, ValueError, OSError, AttributeError) as exc:
        out["reason"] = f"runtime signal signature does not verify ({type(exc).__name__})"
        return out
    out["verified"] = True
    out["emitted_at"] = sig.get("emitted_at")
    out["signal_id"] = sig.get("signal_id")
    out["divergence"] = (sig.get("divergence") or {}).get("status")
    emitted = _ts(sig.get("emitted_at"), None) if sig.get("emitted_at") else None
    out["fresh"] = bool(emitted and timedelta(0) <= now - emitted <= timedelta(hours=max_age_hours))
    if not out["fresh"]:
        out["reason"] = f"runtime signal emitted {sig.get('emitted_at')} is outside {max_age_hours}h"
    out["validations"] = sig.get("validations") or []
    # VER-RPT-PER: the emitter's bounded run history, inside the signed payload.
    out["run_history"] = [r for r in sig.get("run_history") or [] if isinstance(r, dict) and r.get("emitted_at")]
    return out


def runtime_verification_summary(runtime):
    """The runtime V&V run this report read (VER-RPT-PER): when it ran, whether
    its signature verified, how many validations it ran and how many failed.
    Counts are published only from a verified signal."""
    runtime = runtime or {}
    out = {"uri": RUNTIME_SIGNAL_URI, "verified": bool(runtime.get("verified")),
           "fresh": bool(runtime.get("fresh")), "reason": runtime.get("reason"),
           "emitted_at": runtime.get("emitted_at"), "signal_id": runtime.get("signal_id"),
           "validations": None, "failed": None, "divergence": None}
    if out["verified"]:
        vals = [v for v in runtime.get("validations") or [] if isinstance(v, dict)]
        out["validations"] = len(vals)
        out["failed"] = sum(1 for v in vals if v.get("result") != "pass")
        out["divergence"] = runtime.get("divergence")
        # Every run the emitter retained (signed with the signal), so a period
        # report counts the runs a later run replaced (VER-RPT-PER).
        out["run_history"] = [{k: r.get(k) for k in ("signal_id", "emitted_at", "validations", "failed",
                                                     "unassessed", "divergence")}
                              for r in runtime.get("run_history") or []]
    return out


def dast_summary(zap_path):
    """The DAST scan this report ingested: when ZAP generated it and how many
    alert types it reported. None when no ZAP report was given."""
    if not zap_path:
        return None
    p = Path(zap_path)
    if not p.is_file():
        return {"scanner": "zap", "status": "missing", "generated_at": None, "alerts": None}
    try:
        doc = json.loads(p.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"scanner": "zap", "status": "unreadable", "generated_at": None, "alerts": None}
    if not isinstance(doc, dict):
        return {"scanner": "zap", "status": "unreadable", "generated_at": None, "alerts": None}
    # ZAP writes nanoseconds; datetime parses at most microseconds.
    raw = re.sub(r"(\.\d{6})\d+", r"\1", doc["created"]) if isinstance(doc.get("created"), str) else None
    created = _ts(raw, None) if raw else None
    gen = created.astimezone(timezone.utc).isoformat() if created and created.tzinfo else None
    alerts = sum(len(site.get("alerts") or []) for site in doc.get("site") or [] if isinstance(site, dict))
    return {"scanner": "zap", "status": "ok", "generated_at": gen, "alerts": alerts}


def mitigation_state(finding, mitigations, inventory, runtime, today):
    """The mitigation covering this finding, evaluated, or None. When several
    name the finding, the first valid one (by ID) is used, else the first; a
    void record never hides a valid one. `matched` lists every ID that named it."""
    keys = {register_vuln_id(finding), finding.get("tracking_id"),
            normalize_check_id(finding.get("tool_id") or "")}
    states = [_mitigation_state_one(mid, m, inventory, runtime, today)
              for mid, m in sorted(mitigations.items()) if m["finding"] in keys]
    if not states:
        return None
    chosen = next((st for st in states if st["valid"]), states[0])
    return {**chosen, "matched": [st["id"] for st in states]}


def _mitigation_state_one(mid, m, inventory, runtime, today):
    ctl, vc = m["control"], m["verifying_check"]
    cid = ctl["component_id"]
    out = {"id": mid, "effect": m["effect"], "valid": False, "void_reason": None,
           "control": {"component_id": cid, "setting": ctl.get("setting")},
           "verifying_check": {"signal": vc["signal"], "policy": vc["policy"]},
           "justification": m["justification"],
           "verified_on": f"{m['decided_on']}T00:00:00+00:00",
           **_decision_fields(m)}

    def void(reason):
        out["void_reason"] = reason
        return out

    if date.fromisoformat(str(m["review_by"])) < today:
        return void(f"review_by {m['review_by']} has passed")
    comp = (inventory.get("components") or {}).get(cid)
    if comp is None:
        return void(f"control {cid} is not in the inventory")
    if component_fingerprint(comp) != ctl["fingerprint"]:
        return void(f"control {cid} changed since the decision (fingerprint differs)")
    if m["effect"] == "full" and vc["signal"] != "runtime":
        return void("a full mitigation needs a verifying check that reads live state")
    if vc["signal"] == "runtime":
        rt = runtime or {}
        if not rt.get("verified"):
            return void(f"no live read: {rt.get('reason') or 'runtime signal not verified'}")
        if not rt.get("fresh"):
            return void(f"no live read: {rt.get('reason') or 'runtime signal stale'}")
        results = rt.get("validations") or []
    else:
        results = inventory.get("validations") or []
    hits = [v for v in results
            if (v.get("policy") or {}).get("id") == vc["policy"] and cid in (v.get("component_refs") or [])]
    if not hits:
        return void(f"verifying check {vc['policy']} has no result for {cid}")
    if any(v.get("result") != "pass" for v in hits):
        return void(f"verifying check {vc['policy']} does not pass for {cid}")
    out["valid"] = True
    return out

# Per-suppression PAIN fallbacks.
# Only the PAIN fallback is kept here, for a suppression whose check has no
# governed vector in force. IRV comes from the inventory (a central suppression
# names no resource, so it is unresolved and IRV) and LEV from Figure 7.
SUPPRESSION_EVALUATION = {
    "CKV_AWS_68":  {"pain": "N2"},
    "CKV_AWS_86":  {"pain": "N1"},
    "CKV_AWS_310": {"pain": "N1"},
    "CKV_AWS_117": {"pain": "N1"},
    "CKV_AWS_35":  {"pain": "N1"},
    "CKV2_AWS_10": {"pain": "N1"},
    "CKV_AWS_252": {"pain": "N1"},
}

# Rationale per suppressed check, mirrored from .checkov.yaml comments and the
# corresponding decision records. Used to populate VER-RPT-AVI explanation field.
SUPPRESSION_RATIONALE = {
    "CKV_AWS_68":  "Cost trade-off (~$120/year). Static personal site has no forms, no auth endpoints; AWS Shield Standard is the baseline DDoS protection at zero marginal cost.",
    "CKV_AWS_86":  "Single S3 origin. No secondary origin to fail over to; multi-origin would require multi-region storage.",
    "CKV_AWS_310": "The two origins serve distinct path patterns (static S3 site vs the Silk Reeling API), not a redundant failover pair; an origin group would require multi-region storage.",
    "CKV_AWS_117": "Lambda has no internet egress, no sensitive data, no private endpoint targets. NAT Gateway adds cost without commensurate isolation benefit.",
    "CKV_AWS_35":  "CloudTrail log files use SSE-S3, consistent with the DEC-029 decision family: service-written control-plane records about this account's own infrastructure; a CMK adds key sprawl and a decrypt dependency for every consumer without a confidentiality benefit.",
    "CKV2_AWS_10": "CloudWatch Logs integration declined: it duplicates every management event into paid log-group storage to enable metric filters this single-operator system reviews quarterly instead (KSI-MLA-RVL). Log-file validation plus the TLS-only versioned bucket carry the integrity requirement.",
    "CKV_AWS_252": "SNS delivery notifications declined: no consumer exists for a per-delivery notification; the quarterly review reads the bucket directly.",
}

# Read .checkov.yaml as YAML if PyYAML is available; fall back to a forgiving
# regex parser that pulls `- CKV_AWS_NNN` entries from the skip-check list.
def _read_checkov_skip_list(yaml_path):
    text = Path(yaml_path).read_text()
    try:
        import yaml  # type: ignore
        doc = yaml.safe_load(text) or {}
        return list(doc.get("skip-check", []) or [])
    except ImportError:
        # Stdlib-only fallback. Matches lines under skip-check that look like
        # `  - CKV_AWS_NNN` (optionally with a trailing comment).
        in_skip = False
        ids = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("skip-check:"):
                in_skip = True
                continue
            if in_skip:
                if stripped.startswith("- ") or stripped.startswith("-\t"):
                    val = stripped[1:].strip().split("#", 1)[0].strip()
                    if val:
                        ids.append(val)
                elif stripped and not (stripped.startswith("- ") or stripped.startswith("#")):
                    in_skip = False
        return ids


# =============================================================================
# Class C remediation timeframes from VDR-TFR-PVR (FedRAMP CR26)
# =============================================================================
# Days from evaluation, keyed (pain_n, lev, irv). Read from FedRAMP's pinned
# machine-readable rules (infrastructure/schemas/fedramp-rules/), not typed in
# (REQ-RUL-1). N1 has no timeframe (mitigate during routine operations). A
# missing or altered rules file fails the build.


def rules_pin():
    """The FedRAMP rules version this report used (REQ-RUL-2)."""
    return _rules.pin()


# Severity → PAIN FALLBACK. Used only for findings with no CVSS impact vector
# (IaC/config/DAST findings, which are not CVE-scored): there is no C/I/A vector
# to re-weight, so the qualitative severity is the best available proxy. CVE
# findings that carry a CVSS vector are scored by the deterministic
# CVSS-Environmental method instead (see assign_pain / pain_from_environmental).
SEVERITY_TO_PAIN = {
    "CRITICAL": "N4",
    "HIGH":     "N3",
    "MEDIUM":   "N2",
    "LOW":      "N1",
    "INFO":     "N1",
    "INFORMATIONAL": "N1",
    "WARNING":  "N2",
    "ERROR":    "N3",
}

# Treats this system's components as not internet-reachable by default. The
# internet-facing surfaces are (1) CloudFront serving static content and (2) the
# public Silk Reeling API Gateway HTTP API fronting its app Lambda. The internal
# compliance Lambda is NOT internet-reachable (only invokable via EventBridge).
# Findings tied to CloudFront / S3 / static content or the Silk Reeling public
# app are upgraded to IRV true; Grype SCA findings additionally carry an explicit
# internet_reachable=True (see ingest_grype) since they ride that public Lambda.


# =============================================================================
# INGESTION
# =============================================================================


def ingest_opa(path):
    """Load OPA gate output (validations.json from terraform-plan.sh)."""
    if not path or not Path(path).exists():
        return []
    try:
        doc = json.loads(Path(path).read_text())
    except json.JSONDecodeError:
        print(f"warning: {path} is not valid JSON", file=sys.stderr)
        return []
    findings = []
    for result in doc.get("results") or []:
        if result.get("compliant"):
            continue
        for v in result.get("violations") or []:
            findings.append({
                "source": "opa",
                "tool_id": result.get("kind", "opa"),
                "tracking_id": f"opa-{result.get('resource_type','x')}-{result.get('resource_name','x')}-{v.get('type','x')}",
                "title": v.get("type", "policy-violation"),
                "description": v.get("message", ""),
                "severity": (v.get("severity") or "MEDIUM").upper(),
                "resource": v.get("resource") or result.get("resource_name") or "",
            })
    return findings


_TF_RESOURCE_LINE = re.compile(r'^resource\s+"([A-Za-z0-9_-]+)"\s+"([A-Za-z0-9_-]+)"')
_REPO_ROOT = Path(__file__).resolve().parent.parent


def _tf_address_from_snippet(text):
    """'type.name' from the first line of a Checkov snippet, if it opens a resource block."""
    for raw in (text or "").splitlines()[:1]:
        m = _TF_RESOURCE_LINE.match(raw.strip())
        if m:
            return f"{m.group(1)}.{m.group(2)}"
    return None


def _tf_stack(path):
    """The root module a scanned file belongs to ("infrastructure/bootstrap"), or
    None for the main stack (infrastructure/) or a path outside it. A Terraform
    address is unique only within its root module."""
    parts = Path(str(path or "")).parts
    if "infrastructure" not in parts:
        return None
    dirs = parts[parts.index("infrastructure"):-1]
    return "/".join(dirs) if len(dirs) > 1 else None


def _scoped(address, path):
    """A finding's identity: the address, qualified by its root module unless it
    is the main stack (whose identities predate this and must not move)."""
    stack = _tf_stack(path)
    return f"{stack}:{address}" if stack else address


def _tf_address_from_file(uri, line):
    """'type.name' of the resource block enclosing `line` in a repo file. Reads
    only files inside the repository; anything else resolves to None."""
    if not uri or not isinstance(line, int) or line < 1:
        return None
    try:
        path = (_REPO_ROOT / uri).resolve()
        path.relative_to(_REPO_ROOT)
        lines = path.read_text().splitlines()
    except (OSError, ValueError):
        return None
    for raw in reversed(lines[:line]):
        m = _TF_RESOURCE_LINE.match(raw)
        if m:
            return f"{m.group(1)}.{m.group(2)}"
    return None


def ingest_checkov(path):
    """Load Checkov findings. Accepts either Checkov's native JSON or SARIF."""
    if not path or not Path(path).exists():
        return []
    try:
        doc = json.loads(Path(path).read_text())
    except json.JSONDecodeError:
        return []
    findings = []
    # SARIF detection: presence of the runs[] array and a SARIF version field.
    if isinstance(doc, dict) and doc.get("version") and "runs" in doc:
        for run in doc.get("runs") or []:
            for r in run.get("results") or []:
                rule_id = r.get("ruleId") or "checkov"
                level = (r.get("level") or "warning").lower()
                # SARIF "level" → severity. Most Checkov SARIF emits warning;
                # error indicates a higher-severity finding.
                sev = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(level, "MEDIUM")
                msg = (r.get("message") or {}).get("text", rule_id)
                loc, line, snippet = "", None, ""
                locs = r.get("locations") or []
                if locs:
                    phys = locs[0].get("physicalLocation") or {}
                    loc = (phys.get("artifactLocation") or {}).get("uri", "")
                    region = phys.get("region") or {}
                    line = region.get("startLine")
                    snippet = (region.get("snippet") or {}).get("text", "")
                address = _tf_address_from_snippet(snippet) or _tf_address_from_file(loc, line)
                findings.append({
                    "source": "checkov",
                    "tool_id": rule_id,
                    # The Terraform address is the finding's identity; the file is
                    # only where it was seen. Editing the file never resets the clock.
                    "tracking_id": f"checkov-{rule_id}-{_scoped(address, loc) if address else loc}",
                    "legacy_tracking_id": f"checkov-{rule_id}-{loc}",
                    "title": rule_id,
                    "description": msg,
                    "severity": sev,
                    "resource": address or loc,
                    "file": loc,
                    "start_line": line,
                })
        return findings
    # Native Checkov JSON: results.failed_checks[] shape.
    failed = (doc.get("results") or {}).get("failed_checks") or []
    for c in failed:
        findings.append({
            "source": "checkov",
            "tool_id": c.get("check_id", "checkov"),
            "tracking_id": f"checkov-{c.get('check_id','x')}-{_scoped(c.get('resource','x'), c.get('file_path'))}",
            "title": c.get("check_name", "checkov-finding"),
            "description": c.get("description") or c.get("guideline", ""),
            "severity": (c.get("severity") or "MEDIUM").upper(),
            "resource": c.get("resource") or "",
        })
    return findings


def false_positive_checks():
    """Check IDs suppressed as false positives: the in-force false-positive
    records of the decision register. A suppressed check listed there is the
    scanner being wrong, not an accepted risk, and is reported separately."""
    return set(FALSE_POSITIVE_BY_CHECK_ID)


def load_decision_records(path=None):
    """{DEC id: {decided_by, decided_on, review_by}} for each in-force record."""
    return _decisions.decision_fields(_decisions.load(path) if path else DECISIONS)


def _decision_detection_dates():
    """{DEC id: original detection date}, the source's own detection time for a
    suppression (REQ-SRC-1)."""
    return _decisions.detection_dates(DECISIONS)


def dedupe_findings(findings):
    """Collapse scanner results that share a tracking ID (Checkov reports a
    for_each resource once per instance, all at the same address) into one
    finding with an occurrence count."""
    seen = {}
    for f in findings:
        tid = f.get("tracking_id")
        if tid in seen:
            seen[tid]["occurrences"] = seen[tid].get("occurrences", 1) + 1
        else:
            seen[tid] = f
    return list(seen.values())


def ingest_suppressions(checkov_yaml):
    """Read .checkov.yaml's skip-check list and emit risk-accepted entries.

    Each entry becomes a risk-accepted record with VER-RPT-AVI fields populated
    (PAIN/IRV/LEV from SUPPRESSION_EVALUATION, explanation from
    SUPPRESSION_RATIONALE, decision cross-reference from RISK_ACCEPTED_BY_CHECK_ID). Checks
    dismissed as false positives are excluded here and reported by
    ingest_false_positives instead.
    """
    suppressions = []
    if not checkov_yaml:
        return suppressions
    p = Path(checkov_yaml)
    if not p.exists():
        return suppressions
    try:
        ids = _read_checkov_skip_list(p)
    except Exception as exc:
        print(f"warning: could not read {p}: {exc}", file=sys.stderr)
        return suppressions
    fp = false_positive_checks()
    detected = _decision_detection_dates()
    for check_id in ids:
        if check_id in fp:
            continue  # false positive — handled by ingest_false_positives
        evaluation = SUPPRESSION_EVALUATION.get(check_id, {"pain": "N1"})
        rationale = SUPPRESSION_RATIONALE.get(check_id, "Suppressed in .checkov.yaml; see the corresponding decision record for rationale.")
        suppressions.append({
            "tracking_id": check_id,
            "decision_id": RISK_ACCEPTED_BY_CHECK_ID.get(check_id),
            "source": "checkov-suppression",
            "tool_id": check_id,
            "title": f"{check_id} suppressed",
            "description": rationale,
            "resource": ".checkov.yaml",
            # What the suppression affects: the resources its decision names.
            "affected_resources": list(_decisions.records(DECISIONS).get(
                RISK_ACCEPTED_BY_CHECK_ID.get(check_id), {}).get("applies_to", {}).get("resources", [])),
            "current_disposition": "risk-accepted",
            "detected_at": detected.get(RISK_ACCEPTED_BY_CHECK_ID.get(check_id)),
            "pain": evaluation["pain"],
            "is_kev": False,
            "explanation": rationale,
        })
    return suppressions


def ingest_false_positives(checkov_yaml):
    """Emit the false-positive records: suppressed checks listed in the
    decision register as false positives AND centrally suppressed in
    .checkov.yaml. Disposition is 'false-positive'; each carries its decision_id so
    the finding stays tracked by its decision record (never dropped). Inline
    #checkov:skip= FP checks are not synthesized here — they arrive as real
    scanner findings and are classified in build_report()."""
    fp = false_positive_checks()
    if not checkov_yaml or not fp:
        return []
    p = Path(checkov_yaml)
    if not p.exists():
        return []
    try:
        ids = _read_checkov_skip_list(p)
    except Exception:
        return []
    return [{
        "tracking_id": c,
        "decision_id": FALSE_POSITIVE_BY_CHECK_ID.get(c),
        "source": "checkov-suppression",
        "tool_id": c,
        "title": f"{c} false positive",
        "resource": ".checkov.yaml",
        "current_disposition": "false-positive",
        "explanation": "Investigated; recorded as a false positive in the decision register.",
    } for c in ids if c in fp]


def ingest_tfsec(path):
    """Load tfsec JSON output."""
    if not path or not Path(path).exists():
        return []
    try:
        doc = json.loads(Path(path).read_text())
    except json.JSONDecodeError:
        return []
    findings = []
    for r in doc.get("results") or []:
        findings.append({
            "source": "tfsec",
            "tool_id": r.get("rule_id", "tfsec"),
            "tracking_id": (f"tfsec-{r.get('rule_id','x')}-{_scoped(r['resource'], r.get('location',{}).get('filename'))}"
                            if r.get("resource")
                            else f"tfsec-{r.get('rule_id','x')}-{r.get('location',{}).get('filename','x')}-{r.get('location',{}).get('start_line','0')}"),
            "legacy_tracking_id": f"tfsec-{r.get('rule_id','x')}-{r.get('location',{}).get('filename','x')}-{r.get('location',{}).get('start_line','0')}",
            "title": r.get("description", "tfsec-finding"),
            "description": r.get("resolution") or r.get("rule_description", ""),
            "severity": (r.get("severity") or "MEDIUM").upper(),
            "resource": r.get("resource") or "",
        })
    return findings


def ingest_dependabot(path):
    """Load Dependabot alerts (GitHub API JSON form)."""
    if not path or not Path(path).exists():
        return []
    try:
        doc = json.loads(Path(path).read_text())
    except json.JSONDecodeError:
        return []
    findings = []
    alerts = doc if isinstance(doc, list) else doc.get("alerts") or []
    for alert in alerts:
        if alert.get("state") in ("dismissed", "fixed"):
            continue
        adv = alert.get("security_advisory") or {}
        sev = (adv.get("severity") or "MEDIUM").upper()
        package = (alert.get("dependency") or {}).get("package") or {}
        # The alert's patched version is the fix state. Absent key -> unknown,
        # which counts as available (vendor dependency lapses).
        sv = alert.get("security_vulnerability")
        if isinstance(sv, dict) and "first_patched_version" in sv:
            patched = (sv.get("first_patched_version") or {}).get("identifier")
            fix_state, fix_versions = ("fixed", [patched]) if patched else ("not-fixed", [])
        else:
            fix_state, fix_versions = "unknown", []
        findings.append({
            "source": "dependabot",
            "tool_id": adv.get("ghsa_id") or adv.get("cve_id") or "dependabot",
            "tracking_id": f"dependabot-{adv.get('ghsa_id') or adv.get('cve_id') or alert.get('number','x')}",
            "title": adv.get("summary", "dependabot-finding"),
            "description": adv.get("description", ""),
            "severity": sev,
            "resource": f"{package.get('ecosystem','npm')}:{package.get('name','')}",
            "cve": adv.get("cve_id"),
            "detected_at": alert.get("created_at"),
            # CVSS impact vector for the CVSS-Environmental PAIN derivation; absent
            # -> assign_pain falls back to the severity proxy.
            "cvss_vector": _extract_cvss_vector(adv.get("cvss")),
            "fix_state": fix_state,
            "fix_versions": fix_versions,
        })
    return findings


def _extract_cvss_vector(cvss):
    """Pull a CVSS v3.x vector string from a scanner's cvss field, which is
    commonly a list of {version, vector, metrics} (Grype) or a single
    {vector_string} object (Dependabot). Prefers a 3.x vector, then any vector."""
    if not cvss:
        return None
    if isinstance(cvss, dict):
        return cvss.get("vector_string") or cvss.get("vector")
    if isinstance(cvss, list):
        vectors = [(str(c.get("version", "")), c.get("vector") or c.get("vector_string"))
                   for c in cvss if isinstance(c, dict)]
        vectors = [(ver, vec) for ver, vec in vectors if vec]
        if not vectors:
            return None
        for ver, vec in vectors:
            if ver.startswith("3"):
                return vec
        return vectors[0][1]
    return None


def ingest_grype(path):
    """Load Grype scan output (`grype ... -o json`).

    Grype is the Software Composition Analysis source for the Silk Reeling app's
    Python (Lambda) and JS (SPA) dependency trees, which Dependabot does not
    watch. Like Dependabot, every match is a CVE/GHSA-bearing component finding,
    so this mirrors ingest_dependabot's shape exactly: severity is carried as an
    uppercased string and PAIN is assigned downstream by assign_pain via
    SEVERITY_TO_PAIN (Critical -> N4, High -> N3, identical to Dependabot). The
    CVE id is preserved in the `cve` field so build_report's KEV cross-reference
    finds it, and the component identifier prefers the PURL.
    """
    if not path or not Path(path).exists():
        return []
    try:
        doc = json.loads(Path(path).read_text())
    except json.JSONDecodeError:
        return []
    findings = []
    for m in doc.get("matches") or []:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        vid = vuln.get("id") or "grype"
        # Grype severities (Critical/High/Medium/Low/Negligible/Unknown) onto the
        # vocabulary SEVERITY_TO_PAIN understands: Negligible -> LOW (N1),
        # Unknown -> MEDIUM (assign_pain's default tier). Critical/High pass
        # through unchanged so they land at the same N-rating Dependabot uses.
        sev = (vuln.get("severity") or "MEDIUM").upper()
        sev = {"NEGLIGIBLE": "LOW", "UNKNOWN": "MEDIUM"}.get(sev, sev)
        name = art.get("name") or ""
        version = art.get("version") or ""
        # Component identifier: PURL when Grype resolved one (e.g.
        # pkg:pypi/numpy@x / pkg:npm/...), else name@version.
        component = art.get("purl") or f"{name}@{version}"
        # KEV matching reads `cve`; only a CVE id can match the CISA catalog, so
        # carry the id there when it is a CVE (GHSA-only matches stay None).
        cve = vid if str(vid).upper().startswith("CVE-") else None
        # CVSS impact vector for the CVSS-Environmental PAIN derivation. Grype
        # carries a cvss[] list on the vulnerability and on relatedVulnerabilities;
        # prefer a v3.x vector. Absent -> assign_pain falls back to the severity proxy.
        cvss_vector = _extract_cvss_vector(vuln.get("cvss"))
        if not cvss_vector:
            for rel in m.get("relatedVulnerabilities") or []:
                cvss_vector = _extract_cvss_vector(rel.get("cvss"))
                if cvss_vector:
                    break
        findings.append({
            "source": "grype",
            "tool_id": vid,
            "tracking_id": f"grype-{vid}-{component}",
            "title": f"{vid} in {name}",
            "description": vuln.get("dataSource", ""),
            "severity": sev,
            "resource": component,
            "cve": cve,
            "cvss_vector": cvss_vector,
            # Fix state decides whether a vendor dependency still holds: it lapses
            # on the first scan where a fix is available, and an unknown state
            # counts as available. Grype: fixed / not-fixed / wont-fix / unknown.
            "fix_state": (vuln.get("fix") or {}).get("state") or "unknown",
            "fix_versions": list((vuln.get("fix") or {}).get("versions") or []),
        })
    return findings


ZAP_RISK_TO_SEVERITY = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFORMATIONAL"}


def _zap_generated_iso(doc):
    """The scan's own time from ZAP's '@generated' header, as ISO 8601, or None."""
    stamp = str(doc.get("@generated") or "").strip()
    for fmt in ("%a, %d %b %Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(stamp, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return None


ZAP_ALLOWLIST_PATH = Path(__file__).resolve().parent.parent / "security" / "zap" / "allowlist.json"


def load_zap_allowlist(path=ZAP_ALLOWLIST_PATH):
    """Governed record of where the outside-in probe was allowlisted (REQ-IRV-11):
    {"entries": [{"url_prefix", "reason", "decided_by", "decided_on"}]}. Fails
    closed on a malformed file or an entry without a decision."""
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"::error::ZAP allowlist {path} is unreadable ({type(exc).__name__})") from None
    entries = doc.get("entries") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise SystemExit(f"::error::ZAP allowlist {path} has no entries list")
    for e in entries:
        if not (isinstance(e, dict) and all(isinstance(e.get(k), str) and e.get(k)
                                            for k in ("url_prefix", "reason", "decided_by", "decided_on"))):
            raise SystemExit(f"::error::ZAP allowlist entry {e!r} needs url_prefix, reason, decided_by, decided_on")
    return {"entries": entries}


def _zap_allowlisted(uri, prefix):
    """Scheme and host must be equal (a bare string prefix would let
    https://example.com match https://example.com.evil.net), then path prefix."""
    from urllib.parse import urlsplit
    u, p = urlsplit(uri), urlsplit(prefix)
    return (u.scheme, u.hostname, u.port) == (p.scheme, p.hostname, p.port) and \
        (u.path or "/").startswith(p.path or "/")


def _zap_location(uri, allowlist):
    from urllib.parse import urlsplit
    host = urlsplit(uri).hostname or ""
    listed = any(_zap_allowlisted(uri, e["url_prefix"]) for e in (allowlist or {}).get("entries", []))
    return {"uri": uri, "host": host, "allowlisted": listed}


def ingest_zap(path, allowlist=None):
    """Load an OWASP ZAP JSON report (zaproxy/action-baseline `report_json`, or
    `zap.py ... -J report.json`). DAST source: each alert above informational is
    a web-app vulnerability found against the LIVE site (static pages + API), so
    every one is internet-reachable by definition. ZAP alerts are alert-type
    findings; most carry no CVE, so the alert reference is the tracking id the
    vulnerability gate dispositions against. Returns [] for a missing/garbled
    report — presence/freshness is enforced separately (zap_report_age_days) so a
    skipped scan fails the build rather than silently reading as zero findings."""
    if not path or not Path(path).exists():
        return []
    try:
        doc = json.loads(Path(path).read_text())
    except json.JSONDecodeError:
        return []
    findings = []
    generated = _zap_generated_iso(doc)
    for site in doc.get("site") or []:
        target = site.get("@name", "")
        for a in site.get("alerts") or []:
            sev = ZAP_RISK_TO_SEVERITY.get(str(a.get("riskcode", "0")), "MEDIUM")
            if sev == "INFORMATIONAL":
                continue
            ref = a.get("alertRef") or a.get("pluginid") or "zap"
            cveid = str(a.get("cveid") or "")
            # REQ-IRV-11: attribute by the URL observed (host included), and
            # record whether the probe was allowlisted there. A finding is
            # allowlisted only when every location was; one location reached
            # without an allowlist entry is real exposure.
            uris = list(dict.fromkeys(i.get("uri") for i in a.get("instances") or [] if i.get("uri")))
            locations = [_zap_location(u, allowlist) for u in uris]
            findings.append({
                "source": "zap",
                "tool_id": ref,
                "tracking_id": "zap-%s" % ref,
                "title": a.get("alert") or a.get("name") or ref,
                "description": (a.get("desc") or "").strip()[:500],
                "severity": sev,
                "resource": uris[0] if uris else target,
                "locations": locations,
                "allowlisted": bool(locations) and all(loc["allowlisted"] for loc in locations),
                "cve": cveid if cveid.upper().startswith("CVE-") else None,
                "internet_reachable": True,
                "detected_at": generated,
            })
    return findings


def zap_report_age_days(path, now):
    """Age (in days) of a ZAP report from its `@generated` header; None if the
    report is missing or carries no parseable timestamp. Used to fail the build
    closed on a stale/absent monthly scan."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        doc = json.loads(p.read_text())
    except json.JSONDecodeError:
        return None
    stamp = doc.get("@generated")
    if not stamp:
        return None
    for fmt in ("%a, %d %b %Y %H:%M:%S", "%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%S"):
        try:
            gen = datetime.strptime(stamp.strip(), fmt)
            # Fractional days: a whole-day floor would let a 3-day window read 3.9 days as 3.
            return round((now.replace(tzinfo=None) - gen).total_seconds() / 86400, 2)
        except ValueError:
            continue
    return None


class KevCatalog(set):
    """The CISA KEV catalog's CVE IDs, plus each entry's dates (VDR-TFR-KEV):
    `entries` is {cveID: {"due_date", "date_added"}} from the catalog."""

    def __init__(self, ids=(), entries=None):
        super().__init__(ids)
        self.entries = entries or {}


def ingest_kev(path):
    """Load the CISA KEV catalog: its CVE IDs, with the catalog's dueDate and
    dateAdded for each (BOD 26-04 remediation dates)."""
    if not path or not Path(path).exists():
        return KevCatalog()
    try:
        doc = json.loads(Path(path).read_text())
    except json.JSONDecodeError:
        return KevCatalog()
    entries = {v["cveID"]: {"due_date": v.get("dueDate"), "date_added": v.get("dateAdded")}
               for v in (doc.get("vulnerabilities") or []) if isinstance(v, dict) and v.get("cveID")}
    return KevCatalog(entries, entries)


def kev_dates(kev_cves, cve, now):
    """(due_at, date_added, overdue) for a KEV finding from the catalog, or
    (None, None, False). The catalog's due date is a day; it is read as the
    start of that day, UTC, the earlier reading."""
    entry = (getattr(kev_cves, "entries", None) or {}).get(cve) if cve else None
    due = _ts(f"{entry['due_date']}T00:00:00+00:00", None) if entry and entry.get("due_date") else None
    if due is None:
        return None, (entry or {}).get("date_added"), False
    return due.isoformat(), entry.get("date_added"), now >= due


class EpssScores(dict):
    """{cve: probability} plus the feed's own provenance (REQ-LEV-2): FIRST puts
    the model version and score date on a leading '#' line."""
    model_version = None
    score_date = None


def _epss_header(line, scores):
    for part in line.lstrip("#").split(","):
        key, _, val = part.partition(":")
        if key.strip() == "model_version":
            scores.model_version = val.strip() or None
        elif key.strip() == "score_date":
            scores.score_date = val.strip() or None


def ingest_epss(path):
    """Load EPSS exploit-probabilities -> {cve: probability}. Accepts the FIRST
    EPSS CSV (epss_scores-current.csv, optionally gzipped) or a JSON
    {"data":[{"cve","epss"}]} form. A missing or garbled feed yields an empty map,
    so every finding then falls back to the severity proxy (no silent downgrade)."""
    scores = EpssScores()
    if not path or not Path(path).exists():
        return scores
    raw = Path(path).read_bytes()
    if raw[:2] == b"\x1f\x8b":  # gzip magic
        import gzip
        try:
            raw = gzip.decompress(raw)
        except OSError:
            return scores
    text = raw.decode("utf-8", "replace")
    if text.lstrip().startswith("{"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return scores
        scores.model_version = doc.get("model_version")
        scores.score_date = doc.get("score_date")
        for row in doc.get("data") or []:
            cve = row.get("cve")
            try:
                if cve:
                    scores[cve] = float(row.get("epss"))
            except (TypeError, ValueError):
                continue
        return scores
    import csv
    import io
    ci, ei = 0, 1
    header_seen = False
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        if row[0].startswith("#"):
            _epss_header(",".join(row), scores)
            continue
        if not header_seen:
            header_seen = True
            try:
                ci, ei = row.index("cve"), row.index("epss")
            except ValueError:
                ci, ei = 0, 1
            continue
        if len(row) <= max(ci, ei):
            continue
        try:
            scores[row[ci]] = float(row[ei])
        except ValueError:
            continue
    return scores


_LEDGER_KEYS = ("first_detected", "first_evaluated", "clock_start", "clock_basis",
                "historical_pain", "rating_history", "completed_reductions")


def ingest_previous_ledger(path):
    """The previous published VDR is the ledger (REQ-DLN-1). Returns
    {tracking_id: {first_detected, first_evaluated, clock_start, pain,
    historical_pain, rating_history, completed_reductions}} for every finding
    and every risk-accepted record. A record published before first_evaluated
    existed was evaluated in the build that detected it, so first_evaluated
    defaults to first_detected."""
    if not path or not Path(path).exists():
        return {}
    try:
        prev = json.loads(Path(path).read_text())
    except json.JSONDecodeError:
        return {}
    ledger = {}
    for section in ("findings", "risk_accepted"):
        for f in prev.get(section) or []:
            tid, first = f.get("tracking_id"), f.get("first_detected")
            if not tid or not first:
                continue
            e = {k: f[k] for k in _LEDGER_KEYS if f.get(k) is not None}
            e.setdefault("first_evaluated", first)
            if f.get("current_pain") or f.get("pain"):
                e["pain"] = f.get("current_pain") or f.get("pain")
            ledger[tid] = e
    return ledger


def _ts(value, fallback):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return fallback


def clock_facts(f, prior, now):
    """The clock a finding is on (REQ-DLN-1; T34-T36), from the ledger.

    - first_detected: the earliest of the ledger and the source's own time.
    - first_evaluated: carried; set on the first build that evaluated it.
    - clock_start: first_evaluated, moved only by a verified mitigation (T34);
      any other change in evaluation re-selects the timeframe from the same
      start (T35). No disposition pauses it.
    - clock_basis: each start and the mitigation that earned it. A mitigation
      that is no longer in force takes its reset with it, and the finding is
      back on the clock it had before (T24, T25).
    The deadline, likely-overdue and maximum period are decided by the triage
    policy from clock_start and first_evaluated."""
    prior = prior or {}
    candidates = [x for x in (prior.get("first_detected"), f.get("detected_at"), f.get("first_detected")) if x]
    first_detected = min(candidates, key=lambda x: _ts(x, now)) if candidates else now.isoformat()
    first_evaluated = prior.get("first_evaluated") or now.isoformat()
    basis = [dict(b) for b in (prior.get("clock_basis") or []) if isinstance(b, dict) and b.get("start")]
    if not basis:
        basis = [{"start": first_evaluated, "mitigation": None}]
        if prior.get("clock_start") and prior["clock_start"] != first_evaluated:
            # A moved start recorded before its mitigation was: kept only while
            # some verified mitigation still covers the finding.
            basis.append({"start": prior["clock_start"], "mitigation": "unrecorded"})
    active = (f.get("mitigation_id") or "unrecorded") if f.get("verified_mitigation_at") else None
    kept = [b for b in basis
            if b.get("mitigation") is None or b["mitigation"] == active
            or (b["mitigation"] == "unrecorded" and active)]
    voided = [b["mitigation"] for b in basis if b not in kept]
    basis = kept or [{"start": first_evaluated, "mitigation": None}]
    if (active and all(b.get("mitigation") != active for b in basis)
            and _ts(f["verified_mitigation_at"], now) > _ts(basis[-1]["start"], now)):
        basis.append({"start": f["verified_mitigation_at"], "mitigation": active})
    clock_start = basis[-1]["start"]
    start_dt = _ts(clock_start, now)
    first_eval_dt = _ts(first_evaluated, now)
    return {
        "first_detected": first_detected,
        "first_evaluated": first_evaluated,
        "clock_start": clock_start,
        "clock_basis": basis,
        "voided": voided,
        "start_dt": start_dt,
        "first_evaluated_dt": first_eval_dt,
        "days_since_detected": (now - _ts(first_detected, now)).days,
        "days_since_clock_start": (now - start_dt).days,
    }


def rating_history(f, prior, now, pain, lev, irv, clk):
    """REQ-PAI-2: the rating history carried from the ledger, appended with the
    time and reason of each change, and the reductions completed."""
    prior = prior or {}
    history = list(prior.get("rating_history") or [])
    reductions = list(prior.get("completed_reductions") or [])
    point = {"at": now.isoformat(), "pain": pain, "lev": lev, "irv": irv}
    if not history:
        history.append({**point, "reason": "first evaluation"})
    else:
        last = history[-1]
        if (last.get("pain"), last.get("lev"), last.get("irv")) != (pain, lev, irv):
            reason = "re-evaluation: " + "; ".join(
                f"{k} {last.get(k)}->{v}" for k, v in (("pain", pain), ("lev", lev), ("irv", irv)) if last.get(k) != v)
            if f.get("verified_mitigation_at"):
                reason += "; verified mitigation"
            history.append({**point, "reason": reason})
            if last.get("pain") and last["pain"] > pain:
                reductions.append({"at": now.isoformat(), "from": last["pain"], "to": pain, "reason": reason})
    if clk["voided"]:
        history.append({**point, "reason": f"mitigation {', '.join(clk['voided'])} void; "
                                           f"clock returns to {clk['clock_start']}"})
    return {
        "historical_pain": prior.get("historical_pain") or (history[0].get("pain") if history else pain),
        "rating_history": history,
        "completed_reductions": reductions,
    }


# =============================================================================
# EVALUATION (per VDR-EVA-*)
# =============================================================================


_PACKAGE_TYPES = {"npm_package", "pypi_package"}


def load_inventory(ksi_signal_path):
    """Everything resolution needs from the bound inventory: identifier -> component
    index, Terraform components, and each component's type and classification."""
    classes, types, components, validations = {}, {}, {}, []
    p = Path(ksi_signal_path) if ksi_signal_path else None
    if p and p.exists():
        try:
            sig = json.loads(p.read_text())
        except json.JSONDecodeError:
            sig = {}
        for comp in sig.get("components") or []:
            cid = comp.get("component_id")
            if cid:
                classes[cid] = (comp.get("attributes") or {}).get("classification")
                types[cid] = comp.get("type")
                components[cid] = comp
        validations = sig.get("validations") or []
    # components and validations: what a mitigation's control and deploy-time
    # verifying check are read from.
    return {"index": build_component_index(ksi_signal_path) if p else {},
            "tf": tf_components_of(ksi_signal_path) if p else [],
            "classes": classes, "types": types,
            "components": components, "validations": validations}


def reach_facts(finding, cid, inventory):
    """What reachability is decided from (REQ-IRV-6): an outside-in observation
    (DAST reached it), the resolved component, whether it is a package, and the
    component's declared internet_reachable. The policy decides IRV."""
    cls = (inventory["classes"].get(cid) or {}) if cid else {}
    declared = cls.get("internet_reachable")
    return {"observed": finding.get("internet_reachable") is True,
            "component_id": cid,
            "is_package": bool(cid) and inventory["types"].get(cid) in _PACKAGE_TYPES,
            "declared": declared if isinstance(declared, bool) else None}


def classification_for(finding, inventory, index):
    """The classification PAIN uses: the resolved component's, or the fail-safe.
    Without an inventory (unit callers), the older index lookup applies."""
    if inventory is None:
        return resolve_classification(finding, index or {})
    cid = resolve_component(finding, inventory["index"], inventory["tf"])
    return (inventory["classes"].get(cid) if cid else None) or _FAILSAFE_CLASSIFICATION


_VEC_METRIC_RE = re.compile(r"/([A-Z]{1,3}):([A-Z])")


def parse_vector(vector):
    """{metric: value} from a CVSS v3.x or v4.0 vector; {} when absent."""
    return dict(_VEC_METRIC_RE.findall("/" + str(vector).split("/", 1)[-1])) if vector else {}


def _impacts(m):
    """(C, I, A) letters from v3 (C/I/A) or v4 (VC/VI/VA) metrics, or None."""
    for keys in (("C", "I", "A"), ("VC", "VI", "VA")):
        if all(k in m for k in keys):
            return tuple(m[k] for k in keys)
    return None


def _no_direct_impact(m):
    imp = _impacts(m)
    return imp is not None and all(x == "N" for x in imp)


PAIN_CLASSIFIER_DEVIATION = (
    "REQ-PAI-4 deviation: impact is combined by the CVSS-Environmental function (impact "
    "re-weighted by CR/IR/AR, governed word thresholds, scope flag) instead of the method's "
    "default decision tables. The function, its config version and sha256 are published here.")


def triage_item(f, kind, *, pain, is_kev, epss_scores, reach, mitigation=None,
                check_decision=None, register=None, clock=None, extra=None):
    """The facts the triage policy decides one finding from. `extra`: the
    grouping, projection and evaluation-time facts (group, projected_ns,
    detected_ns, default_evaluation), only for report findings."""
    cve = f.get("cve")
    scores = epss_scores or {}
    return {**(extra or {}),
        "id": f["tracking_id"],
        "kind": kind,
        "pain": pain,
        "is_kev": bool(is_kev),
        "exploitation": f.get("exploitation"),
        "metrics": parse_vector(f.get("cvss_vector")),
        "epss": scores[cve] if cve and cve in scores else None,
        "fully_mitigated": bool(f.get("fully_mitigated")),
        "reach": reach,
        "mitigation": ({"id": mitigation["id"], "valid": bool(mitigation["valid"]),
                        "effect": mitigation["effect"]} if mitigation else None),
        "check_decision": check_decision,
        "register": register,
        "advisory": f.get("cve") or f.get("tool_id"),
        "resource": str(f.get("resource") or ""),
        "fix_state": f.get("fix_state"),
        "clock": clock,
    }


def evaluation_facts(f, dec, clk, epss_scores, now):
    """The triage facts beyond the ratings: the finding's group (VER-EVA-GRV),
    a decision's projected remediation date (VER-TFR-MAV), when the source
    detected it and when it was first evaluated (VER-TFR-EVU), and whether its
    ratings rest on defaults (no vector, no prediction score)."""
    plan = dec.get("planned_reduction") or {}
    projected = None
    if plan.get("target_pain") == "N0" and plan.get("date"):
        projected = _triage.to_ns(datetime.combine(date.fromisoformat(plan["date"]), datetime.min.time(),
                                                   tzinfo=timezone.utc))
    # A decision record is an evaluation: a finding a person decided on before
    # the pipeline first saw it was evaluated then.
    evaluated = clk["first_evaluated_dt"]
    if dec.get("decided_on"):
        evaluated = min(evaluated, datetime.combine(date.fromisoformat(dec["decided_on"]), datetime.min.time(),
                                                    tzinfo=timezone.utc))
    cve = f.get("cve")
    return {
        "group": _evaluation.group_key(f, dec.get("id")),
        "projected_ns": projected,
        "detected_ns": _triage.to_ns(_ts(clk["first_detected"], now)),
        "evaluated_ns": _triage.to_ns(evaluated),
        "default_evaluation": not f.get("cvss_vector") and not (cve and cve in (epss_scores or {})),
    }


def _decide_one(finding, *, is_kev=False, irv=False, epss_scores=None, epss_threshold=0.1,
                lev_overrides=None, today=None, kind="suppression", register=None, mitigation=None):
    """The policy's decision for one finding, outside a report (unit callers)."""
    now = datetime.combine(today or datetime.now(timezone.utc).date(), datetime.min.time(),
                           tzinfo=timezone.utc).replace(hour=12)
    reach = {"observed": bool(irv), "component_id": "single-finding", "is_package": False,
             "declared": bool(irv)}
    clock = {"start_ns": _triage.to_ns(now), "first_evaluated_ns": _triage.to_ns(now)}
    item = triage_item({**finding, "tracking_id": "single-finding"}, kind, pain=_rules.impact_levels()[-1],
                       is_kev=is_kev, epss_scores=epss_scores, reach=reach, clock=clock,
                       register=register, mitigation=mitigation)
    return _triage.decide([item], now=now, epss_threshold=epss_threshold, margin_days=0,
                          lev_overrides=lev_overrides)[0]


def lev_determination(finding, epss_scores, epss_threshold, is_kev=False, irv=False):
    """VER-EVA-ELX by the method's Figure 7 (REQ-LEV-1), as decided by the triage
    policy for one finding. Returns (lev, basis).

      1. fully mitigated            -> NLEV
      2. known exploited (KEV)      -> LEV
      3. exploitation observed      -> LEV
      4. FRD-LEV floor: IRV and AV:N/PR:N/UI:N, with some direct impact -> LEV
         (REQ-LEV-3: no prediction score overrides it)
      5. no direct impact (C/I/A all None in a governed vector) -> NLEV
      6. prediction score >= theta  -> LEV, else NLEV
      7. no prediction score        -> LEV until one arrives"""
    d = _decide_one(finding, is_kev=is_kev, irv=irv, epss_scores=epss_scores, epss_threshold=epss_threshold)
    return d["lev"], d["lev_basis"]


def is_likely_exploitable(finding, epss_scores, epss_threshold, is_kev=False, irv=False):
    """Boolean form of lev_determination."""
    return lev_determination(finding, epss_scores, epss_threshold, is_kev=is_kev, irv=irv)[0]


# =============================================================================
# GOVERNED PER-CHECK VECTORS AND LEV OVERRIDES
# =============================================================================
# Config checks (Checkov, tfsec) carry no CVE and so no published vector. Each
# check ID gets a CVSS vector decided once, by a named person, and reviewed on a
# date; the pipeline applies it to every finding of that check. An entry without
# decided_by/decided_on, or past review_by, is not in force. The vector drives
# both PAIN (CVSS-Environmental) and LEV (floor; no direct impact).
DEFAULT_CHECK_VECTORS = (Path(__file__).resolve().parent.parent
                         / "infrastructure" / "schemas" / "check-vectors.json")
DEFAULT_LEV_OVERRIDES = Path(__file__).resolve().parent.parent / "data" / "lev-overrides.json"
_V3_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_V3_VALUES = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "NLH", "I": "NLH", "A": "NLH"}


def _parse_day(value, where):
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        raise SystemExit(f"::error::{where}: '{value}' is not a YYYY-MM-DD date (fail-closed)") from None


def _valid_v31(vector):
    if not isinstance(vector, str) or not vector.startswith("CVSS:3.1/"):
        return False
    m = parse_vector(vector)
    return all(k in m and m[k] in _V3_VALUES[k] for k in _V3_REQUIRED) and len(m) == len(_V3_REQUIRED)


def load_check_vectors(path=None, today=None, decisions=None):
    """{check_id: entry} for entries in force today. Malformed file or entry fails closed."""
    p = Path(path) if path else DEFAULT_CHECK_VECTORS
    today = today or datetime.now(timezone.utc).date()
    in_force_ids = {r["id"] for r in _decisions.in_force(decisions or DECISIONS)}
    try:
        doc = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"::error::check vectors at {p} unreadable: {exc} (fail-closed)") from exc
    if not isinstance(doc.get("vectors"), dict) or not doc.get("version"):
        raise SystemExit(f"::error::check vectors at {p} need 'version' and a 'vectors' object (fail-closed)")
    in_force = {}
    for check_id, e in doc["vectors"].items():
        where = f"check vectors {p} {check_id}"
        if not isinstance(e, dict) or not _valid_v31(e.get("vector")):
            raise SystemExit(f"::error::{where}: vector must be a complete CVSS:3.1 base vector (fail-closed)")
        if not str(e.get("rationale") or "").strip():
            raise SystemExit(f"::error::{where}: rationale is required (fail-closed)")
        review_by = _parse_day(e.get("review_by"), where)
        if not e.get("decided_by") or not e.get("decided_on"):
            continue  # proposed, not decided: not in force
        _parse_day(e["decided_on"], where)
        # A vector is decided through the decision register (DEC-180): a decided
        # entry that names no record in force would be a decision nobody made.
        if e.get("decision") not in in_force_ids:
            raise SystemExit(f"::error::{where}: decided, but decision {e.get('decision')!r} is not a decision "
                             "record in force (fail-closed)")
        if review_by < today:
            continue  # lapsed
        in_force[check_id] = e
    return in_force


def apply_check_vector(finding, vectors):
    """Attach the governed vector to a config finding that has none of its own."""
    if finding.get("cvss_vector") or finding.get("tool_id") not in vectors:
        return finding
    out = dict(finding)
    out["cvss_vector"] = vectors[finding["tool_id"]]["vector"]
    out["vector_source"] = "governed-check-vector"
    out["vector_rationale"] = vectors[finding["tool_id"]].get("rationale")
    out["vector_decision"] = vectors[finding["tool_id"]].get("decision")
    return out


_EPA_EFFECT = {"N0": "no adverse effect on agencies is expected", "N1": "minimal customer effects",
               "N2": "narrow customer effects", "N3": "a disruptive effect on one agency",
               "N4": "a debilitating effect on one agency or a disruptive effect on more than one",
               "N5": "a debilitating effect on more than one agency"}


def impact_rationale(f, pain, fully_mitigated):
    """VER-EVA-EPA: one line on the likely effect on agencies and what it rests on."""
    if fully_mitigated:
        return "Fully mitigated: the impact has been removed (N0)."
    cls = f.get("_classification") or {}
    where = (f"on a component holding {cls.get('data_sensitivity', 'unclassified')} data, "
             f"{cls.get('mission_criticality', 'unrated')} criticality, "
             f"{cls.get('agency_scope', 'multi')}-agency scope")
    if f.get("vector_source") == "governed-check-vector":
        basis = f"{f.get('vector_rationale') or 'governed vector'} (vector decided in {f.get('vector_decision')})"
    elif f.get("cvss_vector"):
        basis = "the advisory's CVSS vector"
    else:
        basis = "the scanner's severity (no vector): a default, not a contextual estimate"
    return f"{pain}, {_EPA_EFFECT.get(pain, pain)}: {basis}; {where}."


def load_lev_overrides(path=None):
    p = Path(path) if path else DEFAULT_LEV_OVERRIDES
    if not p.exists():
        return {}
    try:
        doc = json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"::error::LEV overrides at {p} are not valid JSON: {exc} (fail-closed)") from exc
    overrides = doc.get("overrides", {})
    for oid, o in overrides.items():
        for k in ("advisory", "selector", "lev", "justification", "decided_by", "decided_on", "review_by"):
            if o.get(k) in (None, ""):
                raise SystemExit(f"::error::LEV override {oid} lacks {k} (fail-closed)")
        _parse_day(o["review_by"], f"LEV override {oid}")
    return overrides


def apply_lev_override(finding, lev, overrides, today=None, is_kev=False):
    """REQ-LEV-4, as decided by the triage policy for one finding: a decision
    record may override an LEV result for one advisory across components matched
    by a selector, minus named exclusions. It lapses at review_by and never clears
    a known-exploited finding. Returns (lev, override_id or None)."""
    d = _decide_one(finding, is_kev=is_kev, lev_overrides=overrides, today=today, kind="finding")
    return (d["lev"], d["lev_override"]) if d["lev_override"] else (lev, None)


# =============================================================================
# CVSS-ENVIRONMENTAL PAIN DERIVATION (memo Eqs. 1-4)
# =============================================================================
# PAIN is a CVE's CVSS impact vector (C/I/A) re-weighted by the affected asset's
# CVSS Environmental requirements (CR/IR/AR), bucketed by governed word
# thresholds, then combined with the multi-agency scope flag m. The impact
# vector comes from the scanner; CR/IR/AR derive from the asset's
# resource-classification tags in the canonical inventory. This retires the flat
# severity->PAIN stub for CVE findings and fixes the availability blind spot (a
# Low-vendor-severity availability DoS on a high-availability asset now lands at
# the N-level its agency impact warrants, not at N1 by severity label).

_CIA_LETTER = {"N": "none", "L": "low", "H": "high"}

# Conservative fail-safe asset classification for an unresolved asset (memo s7):
# missing metadata must not lower PAIN, so an unknown asset scores loudly.
_FAILSAFE_CLASSIFICATION = {
    "data_sensitivity": "cui", "mission_criticality": "high",
    "internet_reachable": True, "agency_scope": "multi",
}

# (severity word, scope m) -> N-level, per memo Eq. 4.
_WORD_SCOPE_TO_N = {
    ("minimal", 0): "N1", ("minimal", 1): "N1",
    ("narrow", 0): "N2", ("narrow", 1): "N2",
    ("disruptive", 0): "N3", ("disruptive", 1): "N4",
    ("debilitating", 0): "N4", ("debilitating", 1): "N5",
}


def parse_cvss_cia(vector, config):
    """Extract (C, I, A) impact weights from a CVSS v3.x vector string using the
    governed impact weights. Returns None when the vector carries no C/I/A
    metrics (so the caller falls back to the severity proxy)."""
    imp = _impacts(parse_vector(vector))
    if imp is None or any(x not in _CIA_LETTER for x in imp):
        return None
    w = config["cvss_impact_weights"]
    return tuple(w[_CIA_LETTER[x]] for x in imp)


def build_classification_index(ksi_signal_path):
    """Index the canonical inventory's components by every identifier a finding
    might carry (component_id and its tail, native_id/global_id, tf_name and its
    Terraform-address form, PURL, name) -> the component's classification tags.
    The VDR already binds to one inventory (invariant e); this reads the
    classification that inventory published. Empty dict if the signal is absent."""
    index = {}
    p = Path(ksi_signal_path)
    if not p.exists():
        return index
    try:
        sig = json.loads(p.read_text())
    except json.JSONDecodeError:
        return index
    for comp in sig.get("components") or []:
        cls = (comp.get("attributes") or {}).get("classification")
        if not cls:
            continue
        attrs = comp.get("attributes") or {}
        keys = set()
        cid = comp.get("component_id")
        if cid:
            keys.add(cid)
            keys.add(cid.split("::")[-1])
        # native_id is a scalar (ARN/id); global_id is a dict of cross-CSP
        # identifiers ({"purl": ...} / {"sha256": ...}). Index the scalar values,
        # never the dict itself (which is unhashable and would crash the set add).
        for k in ("native_id", "global_id"):
            v = comp.get(k)
            if isinstance(v, str):
                keys.add(v)
            elif isinstance(v, dict):
                keys.update(x for x in v.values() if isinstance(x, str))
        for k in ("tf_name", "name", "purl"):
            if isinstance(attrs.get(k), str):
                keys.add(attrs[k])
        if attrs.get("tf_name") and comp.get("resource_type"):
            keys.add(f"{comp['resource_type']}.{attrs['tf_name']}")
        for key in keys:
            index.setdefault(str(key), cls)
    return index


def build_component_index(ksi_signal_path):
    """The same identifier keys as build_classification_index, mapped to the
    component_id instead of its classification, so each published finding can
    name the inventory component it affects (the trust center's boundary map
    places findings on components). Empty dict if the signal is absent."""
    index = {}
    p = Path(ksi_signal_path)
    if not p.exists():
        return index
    try:
        sig = json.loads(p.read_text())
    except json.JSONDecodeError:
        return index
    for comp in sig.get("components") or []:
        cid = comp.get("component_id")
        if not cid:
            continue
        attrs = comp.get("attributes") or {}
        keys = {cid, cid.split("::")[-1]}
        for k in ("native_id", "global_id"):
            v = comp.get(k)
            if isinstance(v, str):
                keys.add(v)
            elif isinstance(v, dict):
                keys.update(x for x in v.values() if isinstance(x, str))
        for k in ("tf_name", "name", "purl", "tf_address"):
            if isinstance(attrs.get(k), str):
                keys.add(attrs[k])
        if attrs.get("tf_name") and comp.get("resource_type"):
            keys.add(f"{comp['resource_type']}.{attrs['tf_name']}")
        for key in keys:
            index.setdefault(str(key), cid)
    return index


_TF_ADDRESS = re.compile(r"^(?:module\.[\w-]+\.)*(aws_[a-z0-9_]+)\.([\w-]+)")


def resolve_component(finding, index, tf_components=()):
    """The component a finding affects, or None. Stricter than
    resolve_classification, because a map is read as a claim about a specific
    resource: an exact identifier; else a Terraform address, matched by name to
    the one component whose resource type prefixes the finding's (so
    aws_s3_bucket_server_side_encryption_configuration.logs lands on the logs
    bucket); else, for package-style resources only, the longest containment
    match. A file-level finding (".checkov.yaml", "infrastructure/x.tf") is left
    unattributed rather than pinned to whatever component shares a substring."""
    for c in (finding.get("resource"), finding.get("tool_id"), finding.get("cve")):
        if c and str(c) in index:
            return index[str(c)]
        # The inventory publishes ARNs with ACCOUNT in place of the account ID
        # (scripts/_redact.py); a finding that names a full ARN matches it so.
        if c and _redact.redact_text(str(c)) in index:
            return index[_redact.redact_text(str(c))]
    # A site root ("https://host" or "https://host/") is the page it serves:
    # the root object, index.html (VER-EVA-EIR: evaluated, not assumed).
    root = str(finding.get("resource") or "")
    if re.fullmatch(r"https?://[^/]+/?", root):
        return resolve_component({"resource": root.rstrip("/") + "/index.html"}, index, tf_components)
    res = _redact.redact_text(str(finding.get("resource") or ""))
    m = _TF_ADDRESS.match(res)
    if m:
        rtype, rname = m.group(1), m.group(2)
        hits = {cid for cid, tf_type, tf_name in tf_components
                if tf_name == rname and tf_type and rtype.startswith(tf_type)}
        return hits.pop() if len(hits) == 1 else None
    if ":" in res and "/" not in res.split(":", 1)[0]:
        matches = [(key, cid) for key, cid in index.items()
                   if len(key) >= 4 and (key in res or res in key)]
        if matches:
            matches.sort(key=lambda kc: len(kc[0]), reverse=True)
            return matches[0][1]
    return None


_DECISION_RESOURCE = re.compile(r"^aws-([a-z0-9-]+?)(?:::([\w.-]+))?$")


def resolve_decision_resource(name, inventory):
    """The component a decision record's resource name denotes, or None. An
    exact inventory identifier first; else the register's `aws-<type>[::<name>]`
    form, matched to the one Terraform component of that resource type (and
    name, when given). Ambiguous or unknown: None, never a guess."""
    if not isinstance(name, str) or not name:
        return None
    if name in inventory["index"]:
        return inventory["index"][name]
    m = _DECISION_RESOURCE.match(name)
    if not m:
        return None
    tf_type = "aws_" + m.group(1).replace("-", "_")
    want = m.group(2).replace("-", "_") if m.group(2) else None
    hits = {cid for cid, t, n in inventory["tf"] if t == tf_type and (want is None or n == want)}
    return hits.pop() if len(hits) == 1 else None


def resolve_decision_resources(names, inventory):
    """The component a decision's resources resolve to: the one they all name,
    or, when they name several, an internet-reachable one first (the
    conservative choice for IRV). None when none resolves."""
    cids = []
    for n in names or []:
        cid = resolve_decision_resource(n, inventory)
        if cid and cid not in cids:
            cids.append(cid)
    if not cids:
        return None
    reachable = [c for c in cids if (inventory["classes"].get(c) or {}).get("internet_reachable") is True]
    return (reachable or cids)[0]


def tf_components_of(ksi_signal_path):
    """(component_id, tf_type, tf_name) for every Terraform-backed component."""
    p = Path(ksi_signal_path)
    if not p.exists():
        return []
    try:
        sig = json.loads(p.read_text())
    except json.JSONDecodeError:
        return []
    out = []
    for comp in sig.get("components") or []:
        attrs = comp.get("attributes") or {}
        if attrs.get("tf_name"):
            out.append((comp.get("component_id"), attrs.get("tf_type"), attrs.get("tf_name")))
    return out


def resolve_classification(finding, index):
    """Resolve a finding's affected asset to its classification tags. Tries the
    finding's resource / tool_id / cve as exact index keys first, then a
    containment match for PURL / 'ecosystem:name' SCA resources (e.g. the package
    name 'widget' inside the resource 'pip:widget'). Falls back to the
    conservative fail-safe when nothing resolves (memo s7: unknown scores loudly).

    The containment match is deliberately conservative so it can never quietly
    LOWER a finding's PAIN by latching onto the wrong, lower-criticality asset:
    only specific keys (>= 4 chars) are eligible and the LONGEST (most specific)
    match wins; anything ambiguous or unmatched takes the fail-safe."""
    for c in (finding.get("resource"), finding.get("tool_id"), finding.get("cve")):
        if c and str(c) in index:
            return index[str(c)]
        if c and _redact.redact_text(str(c)) in index:  # see resolve_component
            return index[_redact.redact_text(str(c))]
    res = _redact.redact_text(str(finding.get("resource") or ""))
    if res:
        matches = [(key, cls) for key, cls in index.items()
                   if len(key) >= 4 and (key in res or res in key)]
        if matches:
            matches.sort(key=lambda kc: len(kc[0]), reverse=True)
            return matches[0][1]
    return _FAILSAFE_CLASSIFICATION


def requirement_triplet(classification, config):
    """Map classification tags to (CR, IR, AR) requirement weights: CR from
    data_sensitivity, IR and AR from mission_criticality, via the governed maps."""
    rw = config["requirement_weights"]
    ds = config["data_sensitivity_to_requirement"].get(
        classification.get("data_sensitivity", "cui"), "high")
    mc = config["mission_criticality_to_requirement"].get(
        classification.get("mission_criticality", "high"), "high")
    return rw[ds], rw[mc], rw[mc]


def scope_flag(classification, config):
    """The multi-agency scope term m (REQ-PAI-3, T44): 1 for an asset tagged
    multi-agency or with no declared scope (missing is treated as multi-agency);
    for an asset declared single-agency, the governed value (0 here)."""
    if classification.get("agency_scope") == "single":
        return int(config.get("multi_agency_default", 0))
    return 1


def severity_word(s, config):
    """Bucket the normalized impact scalar S into a FedRAMP customer-effect word."""
    t = config["pain_word_thresholds"]
    if s < t["minimal_to_narrow"]:
        return "minimal"
    if s < t["narrow_to_disruptive"]:
        return "narrow"
    if s < t["disruptive_to_debilitating"]:
        return "disruptive"
    return "debilitating"


def pain_from_environmental(cia, req, m, config, technical_impact=None):
    """PAIN N-level from the impact triplet (C,I,A weights), the asset requirement
    triplet (CR,IR,AR weights), and scope m (memo Eqs. 1-4). technical_impact ==
    'total' floors each in-scope dimension to High before weighting (memo s6
    refinement); it never invents impact on a dimension the CVE marks None."""
    C, I, A = cia
    CR, IR, AR = req
    if technical_impact == "total":
        high = config["cvss_impact_weights"]["high"]
        C = high if C > 0 else C
        I = high if I > 0 else I
        A = high if A > 0 else A
    cap = config["isc_cap"]
    isc = min(1 - (1 - C * CR) * (1 - I * IR) * (1 - A * AR), cap)
    s = isc / cap
    return _WORD_SCOPE_TO_N[(severity_word(s, config), m)]


def assign_pain(finding, index, config):
    """VER-EVA-EPA: assign N1-N5 by the deterministic CVSS-Environmental method.

    A CVE finding carrying a CVSS vector is scored by impact-re-weighted-by-asset
    (CR/IR/AR resolved from the inventory classification), bucketed by the
    governed thresholds and combined with the scope flag. A finding with no CVSS
    vector (IaC/config/DAST) has no impact vector to weight, so it keeps the
    documented severity-proxy fallback (SEVERITY_TO_PAIN)."""
    cia = parse_cvss_cia(finding.get("cvss_vector"), config)
    if cia is None:
        sev = (finding.get("severity") or "").upper()
        if sev:
            return SEVERITY_TO_PAIN.get(sev, "N2")
        # REQ-PAI-7: neither a vector nor a severity -> total technical impact.
        high = config["cvss_impact_weights"]["high"]
        cia = (high, high, high)
    cls = finding.get("_classification") or resolve_classification(finding, index)
    req = requirement_triplet(cls, config)
    m = scope_flag(cls, config)
    return pain_from_environmental(cia, req, m, config,
                                   technical_impact=technical_impact(finding))


def technical_impact(finding):
    """REQ-PAI-7: total when the vector's confidentiality and integrity are both
    High, partial otherwise; with no vector, the severity fallback applies
    (partial); with neither, total. An explicit value on the finding wins."""
    if finding.get("technical_impact"):
        return finding["technical_impact"]
    imp = _impacts(parse_vector(finding.get("cvss_vector")))
    if imp is not None:
        return "total" if imp[0] == "H" and imp[1] == "H" else "partial"
    return "partial" if finding.get("severity") else "total"


def class_c_sla_days(pain, lev, irv):
    """Class C remediation timeframe from VDR-TFR-PVR, as the triage policy reads it
    from the pinned rules (data.rules)."""
    return _triage.evaluate("data.vdr.triage.timeframe(input.p, input.l, input.i)",
                            {"p": pain, "l": bool(lev), "i": bool(irv), "items": []})


# =============================================================================
# BUILD REPORT
# =============================================================================


def consolidate_by_cve(report_findings, risk_accepted):
    """Consolidate CVE-bearing findings into one ledger entry per CVE.

    The same CVE reported by several scanners (Grype + Dependabot) or affecting
    several components is ONE finding with several assets, not several rows. Each
    entry carries the earliest first_detected, the affected assets (PURL / ARN /
    URL drawn from each finding's resource), the scanners that saw it, the worst
    PAIN, KEV status, and disposition(s). Config findings (no CVE) are not
    consolidated here: they are configuration weaknesses, reported separately.
    """
    groups = {}
    for rec in list(report_findings) + list(risk_accepted):
        cve = rec.get("cve")
        if not cve:
            continue
        g = groups.get(cve)
        if g is None:
            g = groups[cve] = {"cve": cve, "assets": [], "scanners": [],
                               "pain": rec.get("pain"), "first_detected": rec.get("first_detected"),
                               "is_kev": False, "dispositions": set(), "decision_ids": set()}
        asset = rec.get("resource") or ""
        if asset and asset not in g["assets"]:
            g["assets"].append(asset)
        src = rec.get("source")
        if src and src not in g["scanners"]:
            g["scanners"].append(src)
        fd = rec.get("first_detected")
        if fd and (not g["first_detected"] or fd < g["first_detected"]):
            g["first_detected"] = fd
        if rec.get("pain") and (not g["pain"] or rec["pain"] > g["pain"]):
            g["pain"] = rec["pain"]
        g["is_kev"] = g["is_kev"] or bool(rec.get("is_kev"))
        g["dispositions"].add(rec.get("current_disposition", "open"))
        if rec.get("decision_id"):
            g["decision_ids"].add(rec["decision_id"])
    out = []
    for cve, g in sorted(groups.items()):
        g["dispositions"] = sorted(g["dispositions"])
        g["decision_ids"] = sorted(g["decision_ids"])
        out.append(g)
    return out


def load_conformance(path):
    """{profile_version, conformance_sha256, summary} from a conformance-results
    file. Fails closed: GOV-2 requires every output to carry them."""
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f"::error::conformance results not found at {path} (REQ-GOV-2)")
    raw = p.read_bytes()
    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SystemExit(f"::error::conformance results at {path} are not JSON: {exc}") from exc
    if doc.get("schema") != "conformance-results/1" or not isinstance(doc.get("profile_version"), str):
        raise SystemExit(f"::error::{path} is not a conformance-results/1 document")
    return {"profile_version": doc["profile_version"], "conformance_sha256": hashlib.sha256(raw).hexdigest(),
            "conformance_generated_at": doc.get("generated_at"), "summary": doc.get("summary")}


class BlockingList(list):
    """The blocking tracking IDs, plus the triage block rule behind each one
    (`rules`), so the caller can apply the gate's governed mode per rule."""

    def __init__(self, *a):
        super().__init__(*a)
        self.rules = {}


# The triage block rule each gate check covers (infrastructure/schemas/gate-modes.json).
BLOCK_RULE_CHECK = {"kev": "vdr.kev", "top-impact-lev-irv": "vdr.top-impact-lev-irv",
                    "past-deadline": "vdr.past-deadline"}


def build_report(findings, suppressions, kev_cves, ledger, index=None, config=None,
                 epss_scores=None, disposition_register=None, check_vectors=None,
                 lev_overrides=None, inventory=None, now=None, mitigations=None, runtime=None,
                 decision_records=None):
    # index: inventory classification index (asset CR/IR/AR source). config: the
    # governed PAIN config. epss_scores: {cve: probability} for the LEV union.
    # disposition_register: the operator vulnerability disposition register.
    # All default for callers that don't supply them (e.g. unit tests); the config
    # is loaded fail-closed so scoring is never silently uncalibrated. Without an
    # index, CVE findings resolve to the conservative fail-safe classification
    # (memo s7); without EPSS, LEV falls back to the severity proxy. Without a
    # register, SCA/DAST findings stay open — the fail-closed default.
    if config is None:
        config, _ = load_pain_config()
    if index is None:
        index = {}
    if disposition_register is None:
        disposition_register = {}
    epss_scores = epss_scores or {}
    now = now or datetime.now(timezone.utc)
    today = now.date()
    mitigations = mitigations or {}
    if decision_records is None:
        decision_records = load_decision_records()
    full_records = {r["id"]: r for r in _decisions.in_force(DECISIONS)}
    incidents = _evaluation.load_incidents()
    matched_register, matched_mitigations, lapsed = set(), set(), []
    margin_days = int(config["likely_overdue_margin_days"])
    report_findings = []
    summary = {
        "by_pain": {"N0": 0, "N1": 0, "N2": 0, "N3": 0, "N4": 0, "N5": 0},
        "blocking": 0,
        "kev": 0,
        "risk_accepted": len(suppressions),
        "ledger_carried_forward": 0,
        "ledger_newly_detected": 0,
    }
    blocking = BlockingList()

    check_vectors = check_vectors or {}
    lev_overrides = lev_overrides or {}
    inv = inventory or {"index": {}, "tf": [], "classes": {}, "types": {}}
    summary["unresolved_components"] = 0
    # 1. Facts. Everything the triage policy decides from, per finding: the
    #    resolved component and its declared reachability, the PAIN arithmetic,
    #    KEV and EPSS, the verified state of a mitigation, the disposition and
    #    decision records, and the clock from the ledger.
    prepared, items = [], []
    for f in findings:
        f = apply_check_vector(f, check_vectors)
        cid = resolve_component(f, inv["index"], inv["tf"])
        f = {**f, "_classification": classification_for(f, inventory, index)}
        # A mitigation's evidence (fingerprint, live read, signature) is checked
        # here; what a valid one changes is the policy's decision.
        mit = mitigation_state(f, mitigations, inv, runtime, today) if mitigations else None
        if mit:
            matched_mitigations.update(mit.get("matched") or [mit["id"]])
        if mit and mit["valid"]:
            f = {**f, "verified_mitigation_at": mit["verified_on"], "mitigation_id": mit["id"]}
        if cid is None and f.get("source") != "process":
            # A process finding names the pipeline, not an inventory component.
            summary["unresolved_components"] += 1
        is_kev = bool(f.get("cve") and f["cve"] in kev_cves)

        # Disposition facts. A config finding whose check is a documented
        # suppression (centralized .checkov.yaml, inline #checkov:skip=, or a
        # tfsec/AVD equivalent) carries its decision record; a vulnerability
        # (Grype/Dependabot/ZAP) carries its register entry. Whether either is in
        # force is decided by the policy (REQ-DSP-1, REQ-DSP-2, T16).
        check_disposition, check_ref = classify_finding(f.get("tool_id"))
        check_decision, reg = None, None
        if check_disposition is not None:
            dec = decision_records.get(check_ref) or {}
            check_decision = {"disposition": check_disposition, "decision_id": check_ref,
                              "record": {k: dec[k] for k in _DECISION_FIELDS if k in dec}}
        else:
            reg = register_entry(f, disposition_register)
            if reg:
                matched_register.add(reg[0])

        tid = f["tracking_id"]
        if tid not in ledger and f.get("legacy_tracking_id") in ledger:
            tid = f["legacy_tracking_id"]  # identity changed format; keep the clock
        if tid in ledger:
            summary["ledger_carried_forward"] += 1
        else:
            summary["ledger_newly_detected"] += 1
        clk = clock_facts(f, ledger.get(tid), now)
        dec_id = (check_decision or {}).get("decision_id") or (reg[1].get("decision_id") if reg else None)
        dec = full_records.get(dec_id) or {}
        items.append(triage_item(
            f, "finding", pain=assign_pain(f, index, config), is_kev=is_kev, epss_scores=epss_scores,
            reach=reach_facts(f, cid, inv), mitigation=mit, check_decision=check_decision,
            register=({"key": reg[0], "entry": reg[1]} if reg else None),
            clock={"start_ns": _triage.to_ns(clk["start_dt"]),
                   "first_evaluated_ns": _triage.to_ns(clk["first_evaluated_dt"])},
            extra=evaluation_facts(f, dec, clk, epss_scores, now)))
        prepared.append((f, cid, mit, is_kev, check_decision, reg, tid, clk, dec))

    # Risk-accepted entries (.checkov.yaml suppressions) are decided for
    # reachability and exploitability only: they carry no deadline.
    sup_prepared = []
    for s in suppressions:
        s = apply_check_vector(s, check_vectors)
        # A .checkov.yaml suppression names a file, not a resource: it affects
        # the resources its decision record names (VER-RPT-AVI), so those are
        # what reachability and classification are decided from.
        s_cid = (resolve_component(s, inv["index"], inv["tf"])
                 or resolve_decision_resources(s.get("affected_resources"), inv))
        s = {**s, "_classification": ((inv["classes"].get(s_cid) or _FAILSAFE_CLASSIFICATION)
                                      if s_cid and inventory is not None
                                      else classification_for(s, inventory, index))}
        s_pain = assign_pain(s, index, config) if s.get("cvss_vector") else s.get("pain")
        items.append(triage_item(s, "suppression", pain=s_pain, is_kev=s.get("is_kev", False),
                                 epss_scores=epss_scores, reach=reach_facts(s, s_cid, inv)))
        sup_prepared.append((s, s_cid, s_pain))

    # 2. Decisions: one evaluation of policies/triage.rego for the whole report.
    decisions = _triage.decide(items, now=now, epss_threshold=config["epss_threshold"],
                               margin_days=margin_days, lev_overrides=lev_overrides,
                               evaluation_days=_rules.evaluation_days())

    # 3. Publish.
    for (f, cid, mit, is_kev, check_decision, reg, tid, clk, dec), d in zip(prepared, decisions[:len(prepared)], strict=True):
        pain, irv, lev, sla = d["pain"], d["irv"], d["lev"], d["sla_days"]
        disposition, finding_decision_id = d["disposition"], d["decision_id"]
        is_suppressed, needs_remediation = d["closed"], d["needs_remediation"]
        fully_mitigated = d["fully_mitigated"]
        record = None
        if check_decision is not None:
            record = {"key": check_decision["decision_id"], "disposition": check_decision["disposition"],
                      "decision_id": check_decision["decision_id"], "status": d["record_status"],
                      "reason": d["record_reason"], "source": "decision-record",
                      **_decision_fields(check_decision["record"])}
        elif reg:
            record = {"key": reg[0], "disposition": reg[1].get("disposition"),
                      "decision_id": reg[1].get("decision_id"), "status": d["record_status"],
                      "reason": d["record_reason"], "source": "decisions",
                      **_decision_fields(reg[1])}
        if record and record["status"] == "lapsed":
            lapsed.append(record["key"])
        hist = rating_history(f, ledger.get(tid), now, pain, lev, irv, clk)
        days_since_detected = clk["days_since_clock_start"]
        due_at = _triage.from_ns(d["due_ns"], clk["start_dt"].tzinfo) if d["due_ns"] is not None else None
        accepted_at = (_triage.from_ns(d["accepted_ns"], clk["first_evaluated_dt"].tzinfo)
                       if d["accepted"] else None)
        epss_used = None
        if f.get("cve") and f["cve"] in epss_scores:
            epss_used = {"score": epss_scores[f["cve"]],
                         "model_version": getattr(epss_scores, "model_version", None),
                         "score_date": getattr(epss_scores, "score_date", None)}

        block_this = d["blocking"]
        block_reason = {
            "kev": "KEV (CISA Known Exploited Vulnerability)",
            "top-impact-lev-irv": f"{pain}+LEV+IRV (most-severe Class C tier)",
            "past-deadline": (f"past Class C SLA ({days_since_detected}d > {sla}d from {clk['clock_start']} "
                              f"for PAIN={pain}, LEV={lev}, IRV={irv})"),
        }.get(d["block_rule"]) if block_this else None

        # VER-RPT-VDT per-vulnerability record fields. History and reductions come
        # from the ledger (REQ-PAI-2); the deadline runs whatever the disposition.
        is_overdue = d["is_overdue"]
        # VDR-TFR-KEV: a known exploited vulnerability is remediated by the
        # catalog's due date, even when fully mitigated: the earlier of that and
        # the Class C deadline, and overdue once the catalog's date has passed.
        kev_due_at, kev_added, kev_overdue = kev_dates(kev_cves, f.get("cve"), now) if is_kev else (None, None, False)
        if kev_due_at and due_at:
            due_at = min(due_at, kev_due_at, key=lambda x: _ts(x, now))
        elif kev_due_at and needs_remediation:
            due_at = kev_due_at
        is_overdue = is_overdue or kev_overdue
        next_reduction = ({"estimated_time": due_at, "target_pain": "remediated"}
                          if sla is not None or kev_due_at else None)
        overdue_explanation = (block_reason if block_this
                               else f"within Class C SLA: {days_since_detected}d of {sla}d allowed"
                               if sla is not None
                               else "informational severity; no remediation SLA applies")
        report_findings.append({
            "tracking_id": f["tracking_id"],
            "source": f["source"],
            "tool_id": f.get("tool_id"),
            "title": f.get("title", ""),
            "description": f.get("description", ""),
            "resource": f.get("resource", ""),
            # Outside-in (ZAP) only: where it was observed and whether the probe
            # was allowlisted there (REQ-IRV-11). Absent for other sources.
            **({"locations": f["locations"], "allowlisted": f.get("allowlisted")}
               if "locations" in f else {}),
            "cve": f.get("cve"),
            "first_detected": clk["first_detected"],
            "first_evaluated": clk["first_evaluated"],
            "clock_start": clk["clock_start"],
            "clock_basis": clk["clock_basis"],
            "days_since_first_detected": clk["days_since_detected"],
            "completed_evaluation": now.isoformat(),
            "pain": pain,
            "current_pain": pain,
            "historical_pain": hist["historical_pain"],
            "rating_history": hist["rating_history"],
            "component_id": cid,
            "unresolved_component": cid is None,
            "internet_reachable": irv,
            "irv_basis": d["irv_basis"],
            "likely_exploitable": lev,
            "lev_basis": d["lev_basis"],
            "lev_override": d["lev_override"],
            "epss": epss_used,
            "cvss_vector": f.get("cvss_vector"),
            "vector_source": f.get("vector_source") or ("scanner" if f.get("cvss_vector") else None),
            "technical_impact": technical_impact(f),
            "impact_rationale": impact_rationale(f, pain, fully_mitigated),
            "is_kev": is_kev,
            **({"kev_due_at": kev_due_at, "kev_date_added": kev_added, "kev_overdue": kev_overdue}
               if is_kev and (kev_due_at or kev_added) else {}),
            "completed_reductions": hist["completed_reductions"],
            "next_reduction": next_reduction if needs_remediation else None,
            "current_disposition": d["label"] or "open",
            "final_disposition": disposition if is_suppressed else "open",
            "decision_id": finding_decision_id,
            "disposition_record": record,
            "fully_mitigated": fully_mitigated,
            "mitigation": mit,
            "fix_state": f.get("fix_state"),
            "fix_versions": f.get("fix_versions"),
            "remediation_sla_days": sla if needs_remediation else None,
            "remediation_due_at": due_at if needs_remediation else None,
            "occurrences": f.get("occurrences", 1),
            "is_overdue": is_overdue,
            "will_be_overdue": d["will_be_overdue"],
            "accepted": d["accepted"],
            "accepted_at": accepted_at,
            **({"accepted_basis": d["accepted_basis"]} if d["accepted"] else {}),
            # VER-RPT-AVI: the recorded justification when an in-force record
            # carries one; otherwise the gap is stated, never filled in.
            "acceptance_explanation": (
                ((reg[1].get("justification") or "").strip() or NOT_RECORDED
                 if reg and d["record_status"] == "in-force"
                 else (dec.get("justification") or "").strip() or NOT_RECORDED
                 if d["accepted_basis"] == "projected-past-maximum-period" else NOT_RECORDED)
                if d["accepted"] else None),
            "overdue_explanation": (block_reason if block_this
                                    else f"documented suppression ({disposition}); tracked as {finding_decision_id}"
                                    if is_suppressed else overdue_explanation),
            "supplementary_info": "",
            "is_blocking": block_this,
            "block_reason": block_reason,
            # VER-EVA-GRV: the group the finding is evaluated in, at its most
            # exposed open member; the group's deadline binds this finding.
            "group_id": d["group"],
            "group_pain": d["group_pain"],
            "group_lev": d["group_lev"],
            "group_irv": d["group_irv"],
            "group_due_at": (_triage.from_ns(d["group_due_ns"], clk["start_dt"].tzinfo)
                             if d["group_due_ns"] is not None else None),
            # VER-TFR-EVU: null when evaluated in time; otherwise why not.
            "evaluation_late": d["evaluation_late"],
            "evaluation": _evaluation.evaluation_record(
                {"internet_reachable": irv, "irv_basis": d["irv_basis"], "likely_exploitable": lev,
                 "lev_basis": d["lev_basis"]}, f,
                cid=cid, ctype=inv["types"].get(cid), metrics=parse_vector(f.get("cvss_vector")),
                classification=f.get("_classification"), auto=_evaluation.automatable(f, dec),
                expl=_evaluation.exploitation(f, is_kev, incidents, now.isoformat()),
                proximate=None, prevalence=None, epss=epss_used, is_kev=is_kev),
        })
        report_findings[-1]["public_disclosure"] = _evaluation.disclosure(report_findings[-1])
        # Histogram and blocking counts reflect genuinely-open findings only;
        # suppressed findings are summarized via the risk-accepted/FP counts.
        if not is_suppressed:
            summary["by_pain"][pain] += 1
            if is_kev:
                summary["kev"] += 1
        if block_this:
            summary["blocking"] += 1
            blocking.append(f["tracking_id"])
            blocking.rules[f["tracking_id"]] = d["block_rule"]

    # Register hygiene: records past review_by, and records with no current
    # finding (remediated, withdrawn advisory, or a scan that stopped seeing it).
    summary["lapsed_dispositions"] = sorted(set(lapsed))
    summary["unmatched_dispositions"] = sorted(set(disposition_register) - matched_register)
    summary["unmatched_mitigations"] = sorted(set(mitigations) - matched_mitigations)
    summary["total_findings"] = sum(1 for r in report_findings if r["final_disposition"] == "open")
    summary["dispositioned_findings"] = sum(1 for r in report_findings if r["final_disposition"] != "open")
    # risk_accepted count = synthesized .checkov.yaml suppressions + scanner
    # findings classified risk-accepted (e.g. inline CKV2_AWS_56 → DEC-026).
    summary["risk_accepted"] = len(suppressions) + sum(
        1 for r in report_findings if r["final_disposition"] == "risk-accepted")

    # Risk-accepted entries are not subject to the SLA — they carry their
    # rationale (the VER-RPT-AVI explanation field) and a decision cross-reference.
    risk_accepted_records = []
    for (s, s_cid, s_pain), d in zip(sup_prepared, decisions[len(prepared):], strict=True):
        s_clk = clock_facts(s, ledger.get(s["tracking_id"]), now)
        risk_accepted_records.append({
            "tracking_id": s["tracking_id"],
            "decision_id": s.get("decision_id"),
            "source": s["source"],
            "tool_id": s.get("tool_id"),
            "title": s.get("title", ""),
            "resource": s.get("resource", ""),
            **({"affected_resources": s["affected_resources"]} if s.get("affected_resources") else {}),
            "first_detected": s_clk["first_detected"],
            "first_evaluated": s_clk["first_evaluated"],
            "completed_evaluation": now.isoformat(),
            "pain": s_pain,
            "component_id": s_cid,
            "internet_reachable": d["irv"],
            "irv_basis": d["irv_basis"],
            "likely_exploitable": d["lev"],
            "lev_basis": d["lev_basis"],
            "cvss_vector": s.get("cvss_vector"),
            "vector_source": s.get("vector_source"),
            "is_kev": s.get("is_kev", False),
            "current_disposition": s.get("current_disposition", "risk-accepted"),
            "explanation": s.get("explanation", ""),
        })

    # VER-EVA-GRV/EFA: groups, prevalence and proximate findings are read across
    # every finding; then each finding's public form follows its disclosure
    # determination (VER-RPT-NID).
    groups = _evaluation.attach_groups(report_findings, len(inv.get("classes") or {}))
    report_findings = [_evaluation.redact(r) for r in report_findings]
    cve_findings = consolidate_by_cve(report_findings, risk_accepted_records)
    summary["unique_cves"] = len(cve_findings)
    summary["unique_cves_open"] = sum(1 for c in cve_findings if "open" in c["dispositions"])

    # Single source of truth for categorization (assessment F-2 / Decision 1).
    _profile = json.loads((Path(__file__).resolve().parent.parent / "data" / "system-profile.json").read_text())
    report = {
        "report_version": "2.0.0",
        "report_id": str(uuid.uuid4()),
        "emitted_at": now.isoformat(),
        "system_id": "urn:samaydlette:website-prod",
        "ksi_signal_ref": "/.well-known/ksi-signal.json",
        "decision_register": "data/decisions.json",
        "class": "C",
        "impact_level": _profile["impact_level"],
        "summary": summary,
        "findings": report_findings,
        "groups": groups,
        "cve_findings": cve_findings,
        "risk_accepted": risk_accepted_records,
        "rules_reference": {
            "evaluation": "FedRAMP 20x VER-EVA-* (PAIN, IRV, LEV)",
            "timeframes": ("FedRAMP 20x VDR-TFR-PVR Class C remediation; "
                           "VDR-TFR-PDD 14-day drift detection; VER-TFR-EVU 5-day evaluation; "
                           "VDR-TFR-MVX 3-day machine V&V"),
            "reporting": ("FedRAMP 20x VER-RPT-VDT (per-vulnerability), VER-RPT-AVI (accepted); "
                          "human-readable rendering published per VER-TFR-MHR"),
            "kev": "VDR-TFR-KEV / CISA BOD 26-04",
            "fedramp_rules": rules_pin(),
        },
    }
    return report, blocking


# =============================================================================
# ENTRY
# =============================================================================


def render_markdown(report):
    """Human-readable rendering of the VDR report. CR26 VER-TFR-MHR requires a
    consistent, human-readable report published at least monthly; this is that
    rendering, derived from the signed vdr-report.json (which stays the source
    of truth). Consumers verify the JSON's Sigstore bundle, then read this."""
    s = report.get("summary", {})
    bp = s.get("by_pain", {})
    out = ["# Vulnerability Detection and Response Report", ""]
    out.append(f"- **Class:** {report.get('class')} (impact level {report.get('impact_level')})")
    out.append(f"- **Emitted:** {report.get('emitted_at')}")
    out.append(f"- **Bound to inventory signal:** `{report.get('ksi_signal_id')}`")
    out.append("- **Source of truth:** the signed `vdr-report.json`; this is its "
               "human-readable rendering per VER-TFR-MHR.")
    out += ["", "## Summary", ""]
    fnd = report.get("findings", [])
    # Counted from the findings themselves, so the summary and the table below
    # cannot disagree. (summary.total_findings counts open findings only; it
    # used to be printed as "Total findings" above a table of every finding.)
    by_disp = Counter(f.get("final_disposition", "") for f in fnd)
    n_open = by_disp.pop("open", 0)
    out.append(f"- Findings: **{len(fnd)}** | Open: **{n_open}** | "
               f"Dispositioned: **{sum(by_disp.values())}**"
               + (" (" + ", ".join(f"{k} {v}" for k, v in sorted(by_disp.items())) + ")" if by_disp else ""))
    # summary.risk_accepted counts accepted risks of both kinds: findings
    # dispositioned risk-accepted, and suppressed checks (which raise no finding
    # and are listed in their own section). Say which is which.
    ra_list = report.get("risk_accepted", [])
    out.append(f"- Blocking: **{s.get('blocking', 0)}** | KEV: **{s.get('kev', 0)}** | "
               f"Accepted risks: **{s.get('risk_accepted', 0)}** "
               f"({by_disp.get('risk-accepted', 0)} findings below, {len(ra_list)} suppressed checks)")
    out.append("- Open findings by PAIN: " + ", ".join(f"{k}={bp.get(k, 0)}" for k in ("N1", "N2", "N3", "N4", "N5")))
    out.append(f"- Unique CVEs: {s.get('unique_cves', 0)} ({s.get('unique_cves_open', 0)} open)")
    out += ["", f"## Findings ({len(fnd)}: {n_open} open)", ""]
    if fnd:
        out.append("| Tracking ID | Source | PAIN | IRV | LEV | First detected | Due | Overdue | Disposition |")
        out.append("|---|---|---|---|---|---|---|---|---|")
        for f in fnd:
            out.append("| {tid} | {src} | {pain} | {irv} | {lev} | {fd} | {due} | {od} | {disp} |".format(
                tid=f.get("tracking_id", ""), src=f.get("source", ""), pain=f.get("pain", ""),
                irv="Y" if f.get("internet_reachable") else "N",
                lev="Y" if f.get("likely_exploitable") else "N",
                fd=(f.get("first_detected") or "")[:10], due=(f.get("remediation_due_at") or "—")[:10],
                od="YES" if f.get("is_overdue") else "no", disp=f.get("final_disposition", "")))
    else:
        out.append("_No findings._")
    ra = ra_list
    out += ["", f"## Accepted risks with suppressed checks ({len(ra)})", ""]
    if ra:
        out.append("| Tracking ID | PAIN | Decision | Explanation |")
        out.append("|---|---|---|---|")
        for r in ra:
            out.append("| {tid} | {pain} | {dec} | {ex} |".format(
                tid=r.get("tracking_id", ""), pain=r.get("pain", ""), dec=r.get("decision_id") or "—",
                ex=(r.get("explanation", "") or "").replace("|", "\\|")[:160]))
    else:
        out.append("_None._")
    out += ["", "---",
            "_Rules: VER-EVA-* (evaluation); VDR-TFR-PVR (Class C remediation timeframes); "
            "VER-RPT-VDT / VER-RPT-AVI (reporting); VDR-TFR-KEV / CISA BOD 26-04 (KEV)._", ""]
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--opa", default="validations.json", help="OPA gate output (default: validations.json in CWD)")
    parser.add_argument("--checkov", default=None, help="Checkov SARIF or JSON output")
    parser.add_argument("--tfsec", default=None, help="tfsec JSON output")
    parser.add_argument("--dependabot", default=None, help="Dependabot alerts JSON")
    parser.add_argument("--grype", default=None, help="Grype SCA scan output (grype -o json)")
    parser.add_argument("--zap", default=None, help="OWASP ZAP JSON report (committed monthly DAST scan)")
    parser.add_argument("--zap-max-age-days", type=int, default=14, help="Fail the build if the ZAP report is older than this or missing; default 14 tracks the VDR-TFR-PDD Class C drift-detection cadence (0 disables)")
    parser.add_argument("--zap-api", default=None, help="Authenticated ZAP API scan report of the Silk Reeling API (scripts/_zap_api.py); presence and age are the detection gate's (detection.zap-api)")
    parser.add_argument("--codeql", default=None, help="CodeQL code-scanning alerts and analyses (scripts/_codeql.py); completeness and age are the detection gate's (detection.codeql)")
    parser.add_argument("--kev", default=None, help="CISA KEV catalog JSON")
    parser.add_argument("--conformance", default=None, help="Signed conformance results (scripts/build-conformance.py): the report names their profile version and sha256 (REQ-GOV-2). Given but missing or invalid: the build fails.")
    parser.add_argument("--detection", default=None, help="The detection gate's summary (scripts/detection-gate.py --output): recorded in the methodology so the report says what its inputs were and how old.")
    parser.add_argument("--check-vectors", default=None, help="Governed per-check CVSS vectors (default infrastructure/schemas/check-vectors.json).")
    parser.add_argument("--mitigations", default=None, help="Governed mitigation records (default data/mitigations.json).")
    parser.add_argument("--runtime-signal", default=None, help="The signed runtime signal (/.well-known/ksi-signal-runtime.json): the live read a full mitigation needs. Absent, unverified or stale: those mitigations are void.")
    parser.add_argument("--runtime-pubkey", default=None, help="Pinned public key record the runtime signal is verified against (default infrastructure/keys/runtime-signing-key.json).")
    parser.add_argument("--fingerprint", default=None, metavar="COMPONENT_ID", help="Print the fingerprint of one --ksi-signal component (for a new mitigation record) and exit.")
    parser.add_argument("--lev-overrides", default=None, help="LEV override decision records (default data/lev-overrides.json).")
    parser.add_argument("--epss", default=None, help="EPSS scores (FIRST epss_scores-current.csv, optionally gzipped, or JSON). Enables the EPSS likely-exploitable union (EPSS >= threshold OR active); without it, LEV falls back to the severity proxy.")
    parser.add_argument("--checkov-yaml", default=".checkov.yaml", help="Path to .checkov.yaml whose skip-check list defines suppressions (default: .checkov.yaml in CWD)")
    parser.add_argument("--previous-vdr", default=None, help="Path to previous VDR report; preserves first_detected timestamps across builds for SLA-clock enforcement.")
    parser.add_argument("--failed-runs", default=None, help="Failed runs of the pipeline (gh run list --status failure --json workflowName,createdAt,updatedAt,event,headBranch): each stopped run on main since the previous report is listed in process_failures (VDR-CSO-FAV). Given but unreadable: the build fails.")
    parser.add_argument("--output", default="vdr-report.json", help="Output report path")
    parser.add_argument("--md-output", default="vdr-report.md", help="Human-readable VDR rendering path (VER-TFR-MHR); empty to skip")
    parser.add_argument("--ksi-signal", default="ksi-signal.json", help="Canonical inventory; its signal_id binds this VDR to one inventory (reconciliation invariant e)")
    parser.add_argument("--pain-config", default=None, help="Governed PAIN classifier config (default: infrastructure/schemas/vdr-pain-config.json). Loaded and validated fail-closed; recorded in the report methodology block.")
    parser.add_argument("--decisions", default=None, help="Decision register (default: data/decisions.json). The same file scripts/vuln-gate.py and reconciliation read; a decided finding carries its disposition and decision_id into the report. Missing or invalid: the build fails.")
    args = parser.parse_args()
    if args.decisions:
        use_decisions(args.decisions)
    if args.fingerprint:
        comp = load_inventory(args.ksi_signal)["components"].get(args.fingerprint)
        if comp is None:
            raise SystemExit(f"::error::{args.fingerprint} is not a component of {args.ksi_signal}")
        print(component_fingerprint(comp))
        return 0

    # Load the governed classifier calibration. Fails closed if absent/malformed
    # so the knobs are always present and auditable (memo s14). assign_pain
    # consumes them; the methodology block records which version was used.
    pain_config, pain_config_sha256 = load_pain_config(args.pain_config)
    gates = _gates.load_gate_modes()

    ksi_signal_id = None
    _sig_path = Path(args.ksi_signal)
    if _sig_path.exists():
        ksi_signal_id = json.loads(_sig_path.read_text()).get("signal_id")

    findings = []
    findings.extend(ingest_opa(args.opa))
    findings.extend(ingest_checkov(args.checkov))
    findings.extend(ingest_tfsec(args.tfsec))
    findings.extend(ingest_dependabot(args.dependabot))
    findings.extend(ingest_grype(args.grype))
    findings.extend(_codeql.ingest_codeql(args.codeql))

    # DAST: ingest the committed monthly ZAP report. Bootstrapping is allowed —
    # a MISSING report only warns (DAST coverage absent until the first scan is
    # committed), so the pipeline stays green before the operator's first scan.
    # Once a report IS present, it is enforced: an undated or stale one fails the
    # build closed (a skipped/forgotten scan must not read as zero findings).
    if args.zap:
        if not Path(args.zap).exists():
            err = Path(f"{args.zap}.error")
            why = err.read_text(errors="replace").strip()[:200] if err.is_file() else "no file"
            msg = f"No ZAP report at {args.zap} ({why}); DAST coverage is absent (see security/zap/README.md)."
            if _gates.blocks(gates, "detection.zap.missing"):
                print(f"::error::{msg}", file=sys.stderr)
                return 1
            _gates.record_event(gates, "detection.zap.missing", msg)
        else:
            findings.extend(ingest_zap(args.zap, load_zap_allowlist()))
            if args.zap_max_age_days > 0:
                age = zap_report_age_days(args.zap, datetime.now(timezone.utc))
                stale = None
                if age is None:
                    stale = f"ZAP report at {args.zap} has no parseable @generated timestamp; regenerate it."
                elif age > args.zap_max_age_days:
                    stale = f"ZAP report is {age} days old (max {args.zap_max_age_days}); run a fresh DAST scan."
                if stale:
                    if _gates.blocks(gates, "detection.zap.stale"):
                        print(f"::error::{stale}", file=sys.stderr)
                        return 1
                    _gates.record_event(gates, "detection.zap.stale", stale)

    findings.extend(_zap_api.ingest_zap_api(args.zap_api, ingest_zap, load_zap_allowlist()))

    findings = dedupe_findings(findings)
    kev_cves = ingest_kev(args.kev)
    epss_scores = ingest_epss(args.epss)
    suppressions = ingest_suppressions(args.checkov_yaml)
    false_positives = ingest_false_positives(args.checkov_yaml)
    ledger = ingest_previous_ledger(args.previous_vdr)

    # Asset-classification index from the bound inventory: the source of each
    # finding's CR/IR/AR in the CVSS-Environmental derivation.
    classification_index = build_classification_index(args.ksi_signal)

    # Decisions for SCA/DAST vulnerabilities — the same register the
    # vulnerability gate reads, so a finding it accepts publishes with the
    # decision_id reconciliation invariant (h) requires.
    disposition_register = load_disposition_register()

    check_vectors = load_check_vectors(args.check_vectors)
    lev_overrides = load_lev_overrides(args.lev_overrides)
    runtime = load_runtime_signal(args.runtime_signal, args.runtime_pubkey)
    inventory = load_inventory(args.ksi_signal)
    mitigations = load_mitigations(args.mitigations)

    def _build(fs):
        return build_report(fs, suppressions, kev_cves, ledger,
                            index=classification_index, config=pain_config,
                            epss_scores=epss_scores,
                            disposition_register=disposition_register,
                            check_vectors=check_vectors,
                            lev_overrides=lev_overrides,
                            inventory=inventory, mitigations=mitigations, runtime=runtime)

    # VDR-CSO-FAV: a detect-and-recover failure recorded earlier in this run,
    # or a finding still on a default after the evaluation window, is itself a
    # finding. The second is known only once the findings are decided, so the
    # report is decided again with them.
    events_path = os.environ.get(_gates.EVENTS_ENV)
    run_events = _gates.read_events(events_path) if events_path else []
    # VDR-TFR-PCD: every inventory component reached by a detection technique
    # within the month; a component none reached is a recorded gap.
    detection_doc = json.loads(Path(args.detection).read_text()) if args.detection else None
    coverage = _evaluation.coverage(inventory["components"], detection_doc, dast_summary(args.zap),
                                    datetime.now(timezone.utc))
    if coverage["uncovered"] and detection_doc is not None:
        run_events.append(_gates.record_event(
            gates, "vdr.coverage", f"no detection in {coverage['window_days']} days: "
                                   f"{', '.join(coverage['uncovered'][:10])}"))
    report, blocking = _build(findings + _evaluation.process_findings(run_events, []))
    # VER-EVA-EIR: a finding that resolves to no component was rated at the
    # fail-safe, not evaluated; that is recorded until it resolves.
    # (Without an inventory, as in unit fixtures, nothing resolves and nothing is recorded.)
    if report["summary"].get("unresolved_components") and inventory["components"]:
        unresolved = sorted(f["tracking_id"] for f in report["findings"]
                            if f.get("unresolved_component") and f.get("source") != "process")
        run_events.append(_gates.record_event(
            gates, "vdr.unresolved-component",
            f"{len(unresolved)} finding(s) resolve to no inventory component: {', '.join(unresolved[:5])}"))
    process = _evaluation.process_findings(run_events, report["findings"])
    if {p["tracking_id"] for p in process} - {f["tracking_id"] for f in report["findings"]}:
        report, blocking = _build(findings + process)
    report["coverage"] = coverage
    # Stopped runs of the pipeline since the previous report (block-mode
    # failures): each is listed with when it failed. Given but unreadable fails.
    if args.failed_runs:
        try:
            runs = json.loads(Path(args.failed_runs).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"::error::--failed-runs {args.failed_runs}: unreadable ({exc.__class__.__name__}) "
                             "(fail-closed)") from exc
        since = (json.loads(Path(args.previous_vdr).read_text()).get("emitted_at")
                 if args.previous_vdr and Path(args.previous_vdr).is_file() else None)
        report["process_failures"] = _evaluation.failed_runs(runs, since)
    report["ksi_signal_id"] = ksi_signal_id
    report["false_positives"] = false_positives
    # Name the inventory component each finding affects, so the trust center can
    # place findings on the boundary map. Resolution only; scoring is unchanged.
    component_index = build_component_index(args.ksi_signal)
    tf_components = tf_components_of(args.ksi_signal)
    for section in ("false_positives",):
        for f in report.get(section) or []:
            if isinstance(f, dict):
                cid = resolve_component(f, component_index, tf_components)
                if cid:
                    f["component_id"] = cid
    # Provenance for the PAIN derivation: which classifier produced these N-levels
    # and which governed config calibrated it. CVE findings with a CVSS vector are
    # scored by the CVSS-Environmental method; vectorless IaC/config/DAST findings
    # keep the documented severity-proxy fallback. LEV is the EPSS union (>=
    # threshold OR active-exploitation), with a severity-proxy fallback where EPSS
    # is unavailable.
    report["methodology"] = {
        "pain_classifier": "cvss-environmental",
        "pain_classifier_deviation": PAIN_CLASSIFIER_DEVIATION,
        "pain_classifier_fallback": ("governed per-check vector for config findings; severity-proxy "
                                     "where neither applies; total technical impact where no severity exists"),
        "lev_method": ("Figure 7, first match deciding: fully mitigated -> known exploited -> exploitation "
                       "observed -> floor (IRV and AV:N/PR:N/UI:N with direct impact) -> no direct impact "
                       "-> EPSS >= threshold -> no score = LEV"),
        "epss_feed": {"model_version": getattr(epss_scores, "model_version", None),
                      "score_date": getattr(epss_scores, "score_date", None)},
        "check_vectors_in_force": len(check_vectors),
        "check_vectors_sha256": hashlib.sha256(Path(args.check_vectors or DEFAULT_CHECK_VECTORS).read_bytes()).hexdigest(),
        "lev_overrides_in_force": len(lev_overrides),
        "epss_threshold": pain_config["epss_threshold"],
        "epss_threshold_rationale": pain_config["epss_threshold_rationale"],
        "epss_scores_loaded": len(epss_scores),
        "pain_config_version": pain_config["version"],
        "pain_config_sha256": pain_config_sha256,
        "fedramp_rules": rules_pin(),
        "reference": pain_config.get("method_reference", ""),
        "gates": _gates.published_view(gates),
        # VER-EVA-EFA: what each factor in a finding's evaluation record means.
        "evaluation_factors": _evaluation.FACTORS,
        "process_failures": ("VDR-CSO-FAV: a detect-and-recover check that failed this run, or a finding still "
                             "on a default after the VER-TFR-EVU window, is a finding with source 'process' "
                             f"(severity proxy {_evaluation.PROCESS_SEVERITY}); it is remediated when the check "
                             "passes. A block-mode failure stops the run; each stopped run is listed in "
                             "process_failures of the next report."),
    }

    # Apply each blocking finding's governed mode before writing, so a
    # detect-and-recover event lands in the report it belongs to.
    hard = []
    for tid in blocking:
        check = BLOCK_RULE_CHECK.get(blocking.rules.get(tid))
        if check is None or _gates.blocks(gates, check):
            hard.append(tid)
        else:
            _gates.record_event(gates, check, f"{tid} is blocking-tier")
    # Detect-and-recover events from this run so far (REQ-GAT-1): published,
    # never hidden. Empty unless the workflow collects them.
    events_file = os.environ.get(_gates.EVENTS_ENV)
    report["methodology"]["gate_events"] = _gates.read_events(events_file) if events_file else []
    # REQ-GOV-2: the profile this report conforms to, and the results of that
    # profile's conformance tests it was built under.
    report["methodology"]["profile"] = load_conformance(args.conformance) if args.conformance else None
    # VER-RPT-PER: the runs this report saw that the detection summary does not
    # list: the runtime verification (its signed signal, verified above) and the
    # DAST scan. Facts only; the CR26 period reports summarize them.
    report["methodology"]["runtime_verification"] = runtime_verification_summary(runtime)
    report["methodology"]["dast"] = dast_summary(args.zap)
    # G7: what each detection input was when this report was built (T52).
    report["methodology"]["detection"] = (json.loads(Path(args.detection).read_text())
                                          if args.detection else None)

    report = _offering.stamp_fedramp_id(report)  # CDS-CSO-FID
    output_path = Path(args.output)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=False))
    print(f"vdr-report.json: {report['summary']['total_findings']} findings, {report['summary']['blocking']} blocking, {report['summary']['risk_accepted']} risk-accepted")

    # VER-TFR-MHR: also emit a human-readable rendering (the JSON alone does not
    # satisfy the "human readable" obligation).
    if args.md_output:
        Path(args.md_output).write_text(render_markdown(report) + "\n")
        print("vdr-report.md: human-readable rendering written")

    # A blocking finding stops the build only if its gate check runs in block
    # mode; a recorded detect-and-recover mode published it above.
    if hard:
        print(f"::error::VDR build-block: {len(hard)} finding(s) exceed Class C tolerance: {', '.join(hard)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())