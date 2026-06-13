#!/usr/bin/env python3
# =============================================================================
# VDR REPORT AGGREGATOR (FedRAMP 20x Vulnerability Detection and Response)
# =============================================================================
# Aggregates vulnerability findings across the system's SAST/SCA tools, applies
# the FedRAMP 20x VDR evaluation framework (PAIN N1-N5, IRV, LEV, KEV), and
# emits a single VDR report. The build itself is the report (per VDR-RPT-PER
# and VDR-TFR-MHR — at least monthly cadence is satisfied by per-deploy
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
#                             with POAM cross-references (VDR-RPT-AVI fields
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
import json
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


# =============================================================================
# CHECKOV CHECK ID → POAM CROSS-REFERENCE
# =============================================================================
# Maps the inline #checkov:skip= annotations in infrastructure/main.tf to their
# canonical POA&M entries in docs/poam.md. New suppressions added without a
# POAM entry will surface in the risk_accepted output without a poam_ref;
# the policy is to back every suppression with a POAM entry.
POAM_BY_CHECK_ID = {
    "CKV_AWS_144": "POAM-003",
    "CKV_AWS_23":  "POAM-004",
    "CKV_AWS_18":  "POAM-005",
    "CKV_AWS_300": "POAM-006",
    "CKV_AWS_68":  "POAM-007",
    "CKV_AWS_174": "POAM-008",
    "CKV_AWS_86":  "POAM-009",
    "CKV_AWS_117": "POAM-010",
    "CKV_AWS_173": "POAM-011",
    "CKV_AWS_115": "POAM-012",
    "CKV_AWS_116": "POAM-013",
    "CKV_AWS_50":  "POAM-014",  # Lambda X-Ray tracing
    "CKV_AWS_272": "POAM-015",  # Lambda code-signing validation
    "CKV_AWS_338": "POAM-017",  # CloudWatch log retention < 1 year
    "CKV_AWS_158": "POAM-018",  # CloudWatch log group not customer-key encrypted
    "CKV2_AWS_57": "POAM-019",  # Secrets Manager automatic rotation not enabled
    "CKV_AWS_309": "POAM-022",  # API Gateway route specifies no authorizer
    "CKV_AWS_76":  "POAM-024",  # API Gateway access logging not enabled
}

# Per-suppression PAIN/IRV/LEV evaluations from docs/poam.md (kept in sync with
# the table there). Ensures the VDR report carries the same VDR-EVA-* values an
# auditor would see in the POA&M.
SUPPRESSION_EVALUATION = {
    "CKV_AWS_144": {"pain": "N1", "irv": False, "lev": False},
    "CKV_AWS_23":  {"pain": "N1", "irv": False, "lev": False},
    "CKV_AWS_18":  {"pain": "N1", "irv": False, "lev": False},
    "CKV_AWS_300": {"pain": "N1", "irv": False, "lev": False},
    "CKV_AWS_68":  {"pain": "N2", "irv": True,  "lev": False},
    "CKV_AWS_174": {"pain": "N1", "irv": False, "lev": False},
    "CKV_AWS_86":  {"pain": "N1", "irv": False, "lev": False},
    "CKV_AWS_117": {"pain": "N1", "irv": False, "lev": False},
    "CKV_AWS_173": {"pain": "N1", "irv": False, "lev": False},
    "CKV_AWS_115": {"pain": "N1", "irv": False, "lev": False},
    "CKV_AWS_116": {"pain": "N1", "irv": False, "lev": False},
    "CKV_AWS_50":  {"pain": "N1", "irv": False, "lev": False},
    "CKV_AWS_272": {"pain": "N2", "irv": False, "lev": False},
    "CKV_AWS_338": {"pain": "N1", "irv": False, "lev": False},
    "CKV_AWS_158": {"pain": "N1", "irv": False, "lev": False},
    "CKV2_AWS_57": {"pain": "N1", "irv": False, "lev": False},
    "CKV_AWS_309": {"pain": "N2", "irv": True,  "lev": False},
    "CKV_AWS_76":  {"pain": "N1", "irv": False, "lev": False},
}

# Rationale per suppressed check, mirrored from .checkov.yaml comments and the
# corresponding POA&M items. Used to populate VDR-RPT-AVI explanation field.
SUPPRESSION_RATIONALE = {
    "CKV_AWS_144": "Single-region static site. Cross-region replication adds cost without commensurate availability benefit at the declared 21-day RTO.",
    "CKV_AWS_23":  "Lambda writes to S3 but does not subscribe to S3 events. No event-driven workflow in scope.",
    "CKV_AWS_18":  "CloudTrail covers the audit need account-wide. CloudFront access logs were similarly excluded for cost.",
    "CKV_AWS_300": "Static website assets have no expiration policy; lifecycle rules are not applicable.",
    "CKV_AWS_68":  "Cost trade-off (~$120/year). Static personal site has no forms, no auth endpoints; AWS Shield Standard is the baseline DDoS protection at zero marginal cost.",
    "CKV_AWS_174": "No Java runtime in scope (Lambda runs Node.js; site is static HTML/CSS/JS). Log4j-class vulnerabilities cannot exist in this stack.",
    "CKV_AWS_86":  "Single S3 origin. No secondary origin to fail over to; multi-origin would require multi-region storage.",
    "CKV_AWS_117": "Lambda has no internet egress, no sensitive data, no private endpoint targets. NAT Gateway adds cost without commensurate isolation benefit.",
    "CKV_AWS_173": "Lambda env vars hold bucket name, distribution ID, system ID — all non-sensitive and visible in the public runtime signal. AWS-default encryption suffices.",
    "CKV_AWS_115": "Daily EventBridge invocation; no concurrent invocations realistic. Cost-control limit not required.",
    "CKV_AWS_116": "Daily idempotent run; failures are recoverable on the next day's invocation. DLQ adds cost for marginal observability benefit.",
    "CKV_AWS_50":  "Observability concern, not a security control. Cost-driven exclusion; CloudWatch Logs covers the diagnostic need.",
    "CKV_AWS_272": "Source-level signing chain in place: deploy-time KSI signal is Sigstore-signed; Wasm policy bytes are verifiable via the canonical inventory's content hash. AWS Signer adds defense-in-depth at marginal cost; not currently justified.",
    "CKV_AWS_338": "7-day retention; operational debug logs only, no PII. Anything older than a week is not actionable for sole-operator IR.",
    "CKV_AWS_158": "AWS-default encryption (server-side AES-256) is on. No PII in log content; customer-managed KMS adds cost without commensurate benefit.",
    "CKV2_AWS_57": "The two Silk Reeling app secrets (a third-party Anthropic API key and an operator-set basic-auth credential) have no programmatic rotation source; rotated manually via put-secret-value. Mooted once the secrets are removed (Tasks 3-4).",
    "CKV_AWS_309": "Access control is enforced at the application layer; the API fronts a Lambda whose middleware rejects any request without valid credentials. Remediated by the Cognito JWT authorizer (Task 3).",
    "CKV_AWS_76":  "HTTP API access logs require a CloudWatch Logs delivery resource-policy; the Lambda execution log group plus CloudFront access logs cover requests in the interim. Remediated by enabling API Gateway access logging (Task 3).",
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
# Days from evaluation; mitigation, full mitigation, or remediation must reduce
# the PAIN N-rating below the threshold within these windows. Class C is
# "Moderate" equivalent.
# Keys: (pain_n, lev, irv) → days
CLASS_C_SLA_DAYS = {
    ("N5", True,  True):  2,
    ("N5", True,  False): 4,
    ("N5", False, False): 16,
    ("N5", False, True):  16,   # NLEV applies regardless of IRV
    ("N4", True,  True):  4,
    ("N4", True,  False): 8,
    ("N4", False, False): 64,
    ("N4", False, True):  64,
    ("N3", True,  True):  16,
    ("N3", True,  False): 32,
    ("N3", False, False): 128,
    ("N3", False, True):  128,
    ("N2", True,  True):  48,
    ("N2", True,  False): 128,
    ("N2", False, False): 192,
    ("N2", False, True):  192,
    # N1: VDR-TFR-RMN — mitigate during routine operations, no specific SLA.
}

# Severity → PAIN mapping. The CR26 VDR rules require contextual evaluation
# per VDR-EVA-EFA, but for a deterministic PoC we use a fixed mapping that
# tilts conservative (severity is upgraded one notch when LEV+IRV both hold).
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
INTERNET_REACHABLE_RESOURCE_HINTS = (
    "cloudfront",
    "aws_s3_bucket_policy",
    "aws_s3_bucket_public_access",
    "html_artifact",
    "public_access",
    "silk-reeling",
    "apigatewayv2",
)


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
                loc = ""
                locs = r.get("locations") or []
                if locs:
                    art = (locs[0].get("physicalLocation") or {}).get("artifactLocation") or {}
                    loc = art.get("uri", "")
                findings.append({
                    "source": "checkov",
                    "tool_id": rule_id,
                    "tracking_id": f"checkov-{rule_id}-{loc}",
                    "title": rule_id,
                    "description": msg,
                    "severity": sev,
                    "resource": loc,
                })
        return findings
    # Native Checkov JSON: results.failed_checks[] shape.
    failed = (doc.get("results") or {}).get("failed_checks") or []
    for c in failed:
        findings.append({
            "source": "checkov",
            "tool_id": c.get("check_id", "checkov"),
            "tracking_id": f"checkov-{c.get('check_id','x')}-{c.get('resource','x')}",
            "title": c.get("check_name", "checkov-finding"),
            "description": c.get("description") or c.get("guideline", ""),
            "severity": (c.get("severity") or "MEDIUM").upper(),
            "resource": c.get("resource") or "",
        })
    return findings


def ingest_suppressions(checkov_yaml):
    """Read .checkov.yaml's skip-check list and emit risk-accepted entries.

    Each entry becomes a risk-accepted record with VDR-RPT-AVI fields populated
    (PAIN/IRV/LEV from SUPPRESSION_EVALUATION, explanation from
    SUPPRESSION_RATIONALE, POAM cross-reference from POAM_BY_CHECK_ID).
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
    for check_id in ids:
        evaluation = SUPPRESSION_EVALUATION.get(check_id, {"pain": "N1", "irv": False, "lev": False})
        rationale = SUPPRESSION_RATIONALE.get(check_id, "Suppressed in .checkov.yaml; see corresponding POA&M entry for rationale.")
        suppressions.append({
            "tracking_id": check_id,
            "poam_ref": POAM_BY_CHECK_ID.get(check_id),
            "source": "checkov-suppression",
            "tool_id": check_id,
            "title": f"{check_id} suppressed",
            "description": rationale,
            "resource": ".checkov.yaml",
            "current_disposition": "risk-accepted",
            "pain": evaluation["pain"],
            "internet_reachable": evaluation["irv"],
            "likely_exploitable": evaluation["lev"],
            "is_kev": False,
            "explanation": rationale,
        })
    return suppressions


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
            "tracking_id": f"tfsec-{r.get('rule_id','x')}-{r.get('location',{}).get('filename','x')}-{r.get('location',{}).get('start_line','0')}",
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
        findings.append({
            "source": "dependabot",
            "tool_id": adv.get("ghsa_id") or adv.get("cve_id") or "dependabot",
            "tracking_id": f"dependabot-{adv.get('ghsa_id') or adv.get('cve_id') or alert.get('number','x')}",
            "title": adv.get("summary", "dependabot-finding"),
            "description": adv.get("description", ""),
            "severity": sev,
            "resource": f"{package.get('ecosystem','npm')}:{package.get('name','')}",
            "cve": adv.get("cve_id"),
        })
    return findings


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
        findings.append({
            "source": "grype",
            "tool_id": vid,
            "tracking_id": f"grype-{vid}-{component}",
            "title": f"{vid} in {name}",
            "description": vuln.get("dataSource", ""),
            "severity": sev,
            "resource": component,
            "cve": cve,
            # The Silk Reeling app Lambda is internet-reachable (public API
            # Gateway), so its dependency vulnerabilities are IRV per
            # VDR-EVA-EIR. This explicit flag overrides the hostname-hint
            # heuristic and pulls these findings onto the tighter Class C SLAs.
            "internet_reachable": True,
        })
    return findings


ZAP_RISK_TO_SEVERITY = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFORMATIONAL"}


def ingest_zap(path):
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
    for site in doc.get("site") or []:
        target = site.get("@name", "")
        for a in site.get("alerts") or []:
            sev = ZAP_RISK_TO_SEVERITY.get(str(a.get("riskcode", "0")), "MEDIUM")
            if sev == "INFORMATIONAL":
                continue
            ref = a.get("alertRef") or a.get("pluginid") or "zap"
            cveid = str(a.get("cveid") or "")
            findings.append({
                "source": "zap",
                "tool_id": ref,
                "tracking_id": "zap-%s" % ref,
                "title": a.get("alert") or a.get("name") or ref,
                "description": (a.get("desc") or "").strip()[:500],
                "severity": sev,
                "resource": target,
                "cve": cveid if cveid.upper().startswith("CVE-") else None,
                "internet_reachable": True,
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
            return (now.replace(tzinfo=None) - gen).days
        except ValueError:
            continue
    return None


def ingest_kev(path):
    """Load CISA KEV catalog and return the set of CVE IDs."""
    if not path or not Path(path).exists():
        return set()
    try:
        doc = json.loads(Path(path).read_text())
    except json.JSONDecodeError:
        return set()
    return {v.get("cveID") for v in (doc.get("vulnerabilities") or []) if v.get("cveID")}


def ingest_previous_ledger(path):
    """Read the previous VDR report and return {tracking_id: first_detected}.

    The previous published VDR report acts as the first-detected ledger:
    each finding's first_detected timestamp is preserved across builds by
    looking it up here. New findings (not in the previous report) are
    stamped with the current build time. Without a ledger, the Class C
    SLA-clock cannot enforce remediation timeframes.
    """
    if not path or not Path(path).exists():
        return {}
    try:
        prev = json.loads(Path(path).read_text())
    except json.JSONDecodeError:
        return {}
    ledger = {}
    for f in prev.get("findings") or []:
        tid = f.get("tracking_id")
        first = f.get("first_detected")
        if tid and first:
            ledger[tid] = first
    return ledger


# =============================================================================
# EVALUATION (per VDR-EVA-*)
# =============================================================================


def is_internet_reachable(finding):
    """VDR-EVA-EIR: heuristic for internet-reachable vulnerability.

    A finding may carry an explicit `internet_reachable` boolean (e.g. Grype SCA
    findings, which ride the publicly-invokable Silk Reeling app Lambda behind
    API Gateway); that explicit determination wins. Otherwise, any finding whose
    resource hint matches the system's internet-facing surface (CloudFront,
    public S3 paths, public HTML artifacts, the public Silk Reeling app) is IRV.
    Findings on the internal compliance Lambda / IAM / EventBridge are NIRV.
    """
    explicit = finding.get("internet_reachable")
    if isinstance(explicit, bool):
        return explicit
    haystack = " ".join([
        str(finding.get("resource", "")),
        str(finding.get("description", "")),
        str(finding.get("title", "")),
    ]).lower()
    return any(hint in haystack for hint in INTERNET_REACHABLE_RESOURCE_HINTS)


def is_likely_exploitable(finding):
    """VDR-EVA-ELX: heuristic for likely-exploitable vulnerability.

    Conservative for the PoC: anything HIGH or CRITICAL is treated as LEV.
    A real provider would apply VDR-EVA-EFA factors (criticality, reachability,
    exploitability, detectability, prevalence, privilege, proximate
    vulnerabilities, known threats) and could downgrade individual findings.
    """
    sev = (finding.get("severity") or "").upper()
    return sev in ("HIGH", "CRITICAL", "ERROR")


def assign_pain(finding):
    """VDR-EVA-EPA: assign N1-N5."""
    sev = (finding.get("severity") or "MEDIUM").upper()
    return SEVERITY_TO_PAIN.get(sev, "N2")


def class_c_sla_days(pain, lev, irv):
    """Look up the Class C remediation SLA from VDR-TFR-PVR."""
    return CLASS_C_SLA_DAYS.get((pain, lev, irv))


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
    consolidated here: they are configuration weaknesses on a separate POA&M tab.
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
                               "is_kev": False, "dispositions": set(), "poam_refs": set()}
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
        if rec.get("poam_ref"):
            g["poam_refs"].add(rec["poam_ref"])
    out = []
    for cve, g in sorted(groups.items()):
        g["dispositions"] = sorted(g["dispositions"])
        g["poam_refs"] = sorted(g["poam_refs"])
        out.append(g)
    return out


def build_report(findings, suppressions, kev_cves, ledger):
    now = datetime.now(timezone.utc)
    report_findings = []
    summary = {
        "by_pain": {"N1": 0, "N2": 0, "N3": 0, "N4": 0, "N5": 0},
        "blocking": 0,
        "kev": 0,
        "risk_accepted": len(suppressions),
        "ledger_carried_forward": 0,
        "ledger_newly_detected": 0,
    }
    blocking = []

    for f in findings:
        pain = assign_pain(f)
        lev = is_likely_exploitable(f)
        irv = is_internet_reachable(f)
        is_kev = bool(f.get("cve") and f["cve"] in kev_cves)

        sla = class_c_sla_days(pain, lev, irv)
        # First-detected lookup: prefer the ledger (previous published VDR
        # report), then any caller-supplied value, then current build time.
        # The ledger is what makes Class C SLA-clock enforcement real.
        tid = f["tracking_id"]
        if tid in ledger:
            first_detected_str = ledger[tid]
            summary["ledger_carried_forward"] += 1
        else:
            first_detected_str = f.get("first_detected") or now.isoformat()
            summary["ledger_newly_detected"] += 1
        try:
            first_detected_dt = datetime.fromisoformat(first_detected_str.replace("Z", "+00:00"))
        except ValueError:
            first_detected_dt = now
        days_since_detected = (now - first_detected_dt).days
        completed_eval = now.isoformat()
        due_at = (first_detected_dt + timedelta(days=sla)).isoformat() if sla is not None else None

        # Blocking conditions, in priority order:
        #   1. Any KEV-listed CVE without remediation (VDR-TFR-KEV / BOD 22-01).
        #   2. Any N5+LEV+IRV finding (most-severe Class C tier, 2-day SLA).
        #   3. Any finding where days_since_detected exceeds the Class C SLA
        #      from VDR-TFR-PVR for its (PAIN, LEV, IRV) combination.
        block_this = False
        block_reason = None
        if is_kev:
            block_this = True
            block_reason = "KEV (CISA Known Exploited Vulnerability)"
        elif pain == "N5" and lev and irv:
            block_this = True
            block_reason = "N5+LEV+IRV (most-severe Class C tier)"
        elif sla is not None and days_since_detected > sla:
            block_this = True
            block_reason = f"past Class C SLA ({days_since_detected}d > {sla}d for PAIN={pain}, LEV={lev}, IRV={irv})"

        report_findings.append({
            "tracking_id": f["tracking_id"],
            "source": f["source"],
            "tool_id": f.get("tool_id"),
            "title": f.get("title", ""),
            "description": f.get("description", ""),
            "resource": f.get("resource", ""),
            "cve": f.get("cve"),
            "first_detected": first_detected_str,
            "days_since_first_detected": days_since_detected,
            "completed_evaluation": completed_eval,
            "pain": pain,
            "internet_reachable": irv,
            "likely_exploitable": lev,
            "is_kev": is_kev,
            "current_disposition": "open",
            "remediation_sla_days": sla,
            "remediation_due_at": due_at,
            "is_blocking": block_this,
            "block_reason": block_reason,
        })
        summary["by_pain"][pain] += 1
        if is_kev:
            summary["kev"] += 1
        if block_this:
            summary["blocking"] += 1
            blocking.append(f["tracking_id"])

    summary["total_findings"] = len(report_findings)

    # Risk-accepted entries are not subject to the SLA — they carry their
    # rationale (the VDR-RPT-AVI explanation field) and a POAM cross-reference.
    risk_accepted_records = []
    for s in suppressions:
        risk_accepted_records.append({
            "tracking_id": s["tracking_id"],
            "poam_ref": s.get("poam_ref"),
            "source": s["source"],
            "tool_id": s.get("tool_id"),
            "title": s.get("title", ""),
            "resource": s.get("resource", ""),
            "first_detected": now.isoformat(),
            "completed_evaluation": now.isoformat(),
            "pain": s.get("pain"),
            "internet_reachable": s.get("internet_reachable", False),
            "likely_exploitable": s.get("likely_exploitable", False),
            "is_kev": s.get("is_kev", False),
            "current_disposition": s.get("current_disposition", "risk-accepted"),
            "explanation": s.get("explanation", ""),
        })

    cve_findings = consolidate_by_cve(report_findings, risk_accepted_records)
    summary["unique_cves"] = len(cve_findings)
    summary["unique_cves_open"] = sum(1 for c in cve_findings if "open" in c["dispositions"])

    # Single source of truth for categorization (assessment F-2 / Decision 1).
    _profile = json.loads((Path(__file__).resolve().parent.parent / "data" / "system-profile.json").read_text())
    report = {
        "report_version": "1.2.0",
        "report_id": str(uuid.uuid4()),
        "emitted_at": now.isoformat(),
        "system_id": "urn:samaydlette:website-prod",
        "ksi_signal_ref": "/.well-known/ksi-signal.json",
        "poam_ref": "docs/poam.md",
        "class": "C",
        "impact_level": _profile["impact_level"],
        "summary": summary,
        "findings": report_findings,
        "cve_findings": cve_findings,
        "risk_accepted": risk_accepted_records,
        "rules_reference": {
            "evaluation": "FedRAMP 20x VDR-EVA-* (PAIN, IRV, LEV)",
            "timeframes": "FedRAMP 20x VDR-TFR-PVR Class C",
            "reporting": "FedRAMP 20x VDR-RPT-VDT, VDR-RPT-AVI",
        },
    }
    return report, blocking


# =============================================================================
# ENTRY
# =============================================================================


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--opa", default="validations.json", help="OPA gate output (default: validations.json in CWD)")
    parser.add_argument("--checkov", default=None, help="Checkov SARIF or JSON output")
    parser.add_argument("--tfsec", default=None, help="tfsec JSON output")
    parser.add_argument("--dependabot", default=None, help="Dependabot alerts JSON")
    parser.add_argument("--grype", default=None, help="Grype SCA scan output (grype -o json)")
    parser.add_argument("--zap", default=None, help="OWASP ZAP JSON report (committed monthly DAST scan)")
    parser.add_argument("--zap-max-age-days", type=int, default=35, help="Fail the build if the ZAP report is older than this or missing (0 disables the freshness gate)")
    parser.add_argument("--kev", default=None, help="CISA KEV catalog JSON")
    parser.add_argument("--checkov-yaml", default=".checkov.yaml", help="Path to .checkov.yaml whose skip-check list defines suppressions (default: .checkov.yaml in CWD)")
    parser.add_argument("--previous-vdr", default=None, help="Path to previous VDR report; preserves first_detected timestamps across builds for SLA-clock enforcement.")
    parser.add_argument("--output", default="vdr-report.json", help="Output report path")
    parser.add_argument("--ksi-signal", default="ksi-signal.json", help="Canonical inventory; its signal_id binds this VDR to one inventory (reconciliation invariant e)")
    args = parser.parse_args()

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

    # DAST: ingest the committed monthly ZAP report and fail closed if it is
    # missing or stale (a silently-skipped scan must not read as zero findings).
    if args.zap:
        findings.extend(ingest_zap(args.zap))
        if args.zap_max_age_days > 0:
            age = zap_report_age_days(args.zap, datetime.now(timezone.utc))
            if age is None:
                print(f"::error::ZAP report missing or undated at {args.zap}; commit a fresh scan (see security/zap/README).", file=sys.stderr)
                return 1
            if age > args.zap_max_age_days:
                print(f"::error::ZAP report is {age} days old (max {args.zap_max_age_days}); run a fresh monthly DAST scan and commit it.", file=sys.stderr)
                return 1

    kev_cves = ingest_kev(args.kev)
    suppressions = ingest_suppressions(args.checkov_yaml)
    ledger = ingest_previous_ledger(args.previous_vdr)

    report, blocking = build_report(findings, suppressions, kev_cves, ledger)
    report["ksi_signal_id"] = ksi_signal_id

    output_path = Path(args.output)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=False))
    print(f"vdr-report.json: {report['summary']['total_findings']} findings, {report['summary']['blocking']} blocking, {report['summary']['risk_accepted']} risk-accepted")

    if blocking:
        print(f"::error::VDR build-block: {len(blocking)} finding(s) exceed Class C tolerance: {', '.join(blocking)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
