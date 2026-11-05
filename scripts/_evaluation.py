"""The evaluation record for each finding (VER-EVA-*), beside the triage decision.

policies/triage.rego decides the ratings, the deadline and blocking. This module
states what the evaluation considered, as facts with their basis, so a reader
can see each factor VER-EVA-EFA names and the assumptions VER-EVA-AIA and
VDR-CSO-RES require:

  criticality   the component's classification (what PAIN is computed from)
  reachability  the policy's IRV and its basis
  exploitability the policy's LEV and its basis
  detectability how an attacker would learn of it
  prevalence    how many findings and components share its group
  privilege     what exploitation needs and what it reaches
  proximate     other findings and mitigations on the same component
  known_threats KEV and the exploit-prediction score
  automatable   yes unless evidence says otherwise (VER-EVA-AIA)
  exploitation  whether exploitation of it has been observed (VDR-CSO-RES)

It also groups findings (VER-EVA-GRV) and decides what the public artifacts may
say about each one (VER-RPT-NID, VER-RPT-RPD). Factors are recorded, not fed
into the impact tables: REQ-PAI-4 makes the tables global, and a provider that
changes them publishes the deviation. Grouping is fed to the policy, which
evaluates a group at its most exposed member.
"""

import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INCIDENTS = REPO / "data" / "incidents.json"

# Decision records that set these policies (data/decisions.json).
EXPLOITATION_POLICY = "DEC-181"
DISCLOSURE_POLICY = "DEC-182"

FACTORS = {
    "criticality": "The resolved component's declared classification (data sensitivity, mission "
                   "criticality, agency scope); the fail-safe classification when it resolves to none. "
                   "PAIN is computed from it.",
    "reachability": "Internet-reachability as the triage policy decides it (VER-EVA-EIR), with its basis.",
    "exploitability": "Likely exploitability by the method's Figure 7 (VER-EVA-ELX), with its basis.",
    "detectability": "How an attacker would learn of the vulnerability: observed from outside (DAST), "
                     "a published advisory, or configuration readable in the public source repository.",
    "prevalence": "How many findings and components share the finding's group, and the share of the "
                  "inventory's components they cover.",
    "privilege": "What exploitation requires (CVSS PR) and what it reaches (CVSS S, and whether the "
                 "component is an identity or key-management resource).",
    "proximate": "Other findings (open, dispositioned or mitigated) and verified mitigations on the same "
                 "component, which the group and the decision records are read with.",
    "known_threats": "CISA KEV membership and the exploit-prediction score with its date.",
    "automatable": "VER-EVA-AIA: yes unless a decision record carries evidence that exploitation cannot "
                   "be automated, or the CVSS 4.0 vector says AU:N.",
    "exploitation": "VDR-CSO-RES: active when an incident record names the finding or the vulnerability "
                    "is observed exploited; otherwise none observed, under the exploitation assessment "
                    f"policy ({EXPLOITATION_POLICY}).",
}

_PRIVILEGED_TYPES = ("iam", "identity", "kms", "key", "cognito", "user_pool")


def group_key(f, decision_id):
    """VER-EVA-GRV: a CVE groups every instance of it; otherwise a decision
    record groups what it decided together (one root cause, one decision);
    otherwise the check ID groups instances of one rule."""
    if f.get("cve"):
        return f"cve:{f['cve']}"
    if decision_id:
        return f"decision:{decision_id}"
    return f"check:{f.get('source')}:{f.get('tool_id')}"


def automatable(f, dec):
    """(value, source). Defaults to yes (VER-EVA-AIA)."""
    a = (dec or {}).get("automatable")
    if isinstance(a, dict) and a.get("value") == "no" and str(a.get("evidence") or "").strip():
        return {"value": "no", "source": f"decision {dec['id']}", "evidence": a["evidence"].strip()}
    vec = str(f.get("cvss_vector") or "")
    if vec.startswith("CVSS:4.0/") and "/AU:" in vec:
        au = vec.split("/AU:", 1)[1][:1]
        return {"value": "yes" if au == "Y" else "no", "source": "CVSS 4.0 AU", "evidence": vec}
    return {"value": "yes", "source": "VER-EVA-AIA default", "evidence": None}


def detectability(f, irv):
    src = f.get("source")
    if src == "zap" or f.get("locations"):
        return {"value": "observed-outside-in", "basis": "found by an unauthenticated outside-in scan"}
    if f.get("cve") or src in ("grype", "dependabot"):
        return {"value": "public-advisory",
                "basis": "a published advisory names the package; " +
                         ("the component is internet-reachable" if irv else "the component is not internet-reachable")}
    if src == "process":
        return {"value": "provider-only", "basis": "a failure of the provider's own pipeline"}
    return {"value": "public-source", "basis": "configuration in the public source repository"}


def privilege(f, cid, ctype, metrics):
    pr = {"N": "none", "L": "low", "H": "high"}.get(metrics.get("PR"), "unknown")
    ident = any(t in f"{ctype or ''} {cid or ''}".lower() for t in _PRIVILEGED_TYPES)
    if metrics.get("S") == "C":
        gained = "beyond-component"
    elif ident:
        gained = "identity-or-keys"
    elif metrics:
        gained = "within-component"
    else:
        gained = "unknown"
    return {"required": pr, "gained": gained,
            "basis": ("CVSS PR/S" if metrics else "no vector") + ("; identity or key-management component" if ident else "")}


def load_incidents(path=INCIDENTS):
    """Incident records, when the register exists. Missing: none."""
    p = Path(path)
    if not p.is_file():
        return []
    doc = json.loads(p.read_text(encoding="utf-8"))
    recs = doc.get("incidents") if isinstance(doc, dict) else doc
    return recs if isinstance(recs, list) else []


def exploitation(f, is_kev, incidents, now_iso):
    """VDR-CSO-RES: whether exploitation of this finding has been observed."""
    if str(f.get("exploitation") or "").lower() == "active":
        return {"value": "active", "basis": "reported by the source", "assessed_at": now_iso}
    keys = [k for k in (f.get("tracking_id"), f.get("cve")) if k]
    for inc in incidents:
        blob = json.dumps(inc, sort_keys=True)
        if any(k in blob for k in keys):
            return {"value": "active", "basis": f"incident {inc.get('id', '?')} names it", "assessed_at": now_iso}
    basis = "no incident record names it"
    if is_kev:
        basis += "; exploited elsewhere (CISA KEV), which the policy treats as likely exploitable"
    return {"value": "none-observed", "basis": f"{basis} ({EXPLOITATION_POLICY})", "assessed_at": now_iso}


def evaluation_record(row, f, *, cid, ctype, metrics, classification, auto, expl, proximate, prevalence,
                      epss, is_kev):
    return {
        "criticality": classification,
        "reachability": {"irv": row["internet_reachable"], "basis": row["irv_basis"]},
        "exploitability": {"lev": row["likely_exploitable"], "basis": row["lev_basis"]},
        "detectability": detectability(f, row["internet_reachable"]),
        "prevalence": prevalence,
        "privilege": privilege(f, cid, ctype, metrics),
        "proximate": proximate,
        "known_threats": {"kev": bool(is_kev), "epss": epss},
        "automatable": auto,
        "exploitation": expl,
    }


def attach_groups(rows, inventory_size):
    """Group membership, prevalence and proximate findings, after every row is
    built. Returns the published groups."""
    groups, by_component = {}, {}
    for r in rows:
        groups.setdefault(r["group_id"], []).append(r)
        if r.get("component_id"):
            by_component.setdefault(r["component_id"], []).append(r)
    out = []
    for gid, members in sorted(groups.items()):
        comps = sorted({m["component_id"] for m in members if m.get("component_id")})
        prevalence = {"findings": len(members), "components": len(comps),
                      "inventory_share": round(len(comps) / inventory_size, 3) if inventory_size else None}
        for m in members:
            m["evaluation"]["prevalence"] = prevalence
        g = members[0]
        out.append({
            "group_id": gid,
            "basis": gid.split(":", 1)[0],
            "members": sorted(m["tracking_id"] for m in members),
            "components": comps,
            "pain": g.get("group_pain"),
            "likely_exploitable": g.get("group_lev"),
            "internet_reachable": g.get("group_irv"),
            "remediation_due_at": g.get("group_due_at"),
            "open_members": sum(1 for m in members if m["final_disposition"] == "open"),
            "dispositions": sorted({m["final_disposition"] for m in members}),
        })
    for r in rows:
        others = [o for o in by_component.get(r.get("component_id"), []) if o is not r]
        r["evaluation"]["proximate"] = {
            "findings": sorted({o["tracking_id"] for o in others}),
            "open": sum(1 for o in others if o["final_disposition"] == "open"),
            "mitigations": sorted({o["mitigation"]["id"] for o in others + [r]
                                   if isinstance(o.get("mitigation"), dict) and o["mitigation"].get("valid")}),
        }
    return out


# ---- disclosure (VER-RPT-NID, VER-RPT-RPD) ------------------------------------------
# What the public artifacts withhold while a finding is open, internet-reachable,
# likely exploitable and rated N3 or higher: the detail that tells an attacker
# where and how (description, observed locations, fixed versions, evidence). The
# tracking ID, ratings, dates and status stay, so any party can make a
# risk-based decision. Policy: DEC-182.
WITHHELD_FIELDS = ("description", "locations", "fix_versions", "supplementary_info")
_WITHHOLD_FROM = 3


def disclosure(row):
    pain = str(row.get("pain") or "")
    n = int(pain[1:]) if pain[1:].isdigit() else 0
    if (row.get("final_disposition") == "open" and row.get("internet_reachable") and row.get("likely_exploitable")
            and n >= _WITHHOLD_FROM and not row.get("fully_mitigated")):
        return {"level": "summary", "policy": DISCLOSURE_POLICY,
                "reason": f"open, IRV, LEV and {pain}: detail withheld from public artifacts until remediated or "
                          "dispositioned; available to necessary parties from the provider"}
    return {"level": "full", "policy": DISCLOSURE_POLICY,
            "reason": "not an open IRV+LEV finding at N3 or above: disclosing it will not likely lead to exploitation"}


def redact(row):
    """The public form of a finding under its disclosure determination."""
    if (row.get("public_disclosure") or {}).get("level") != "summary":
        return row
    out = dict(row)
    for k in WITHHELD_FIELDS:
        if k in out:
            if out[k] not in (None, "", [], {}):
                out[k] = f"[withheld under {DISCLOSURE_POLICY}]" if isinstance(out[k], str) else None
    return out


# ---- failures are vulnerabilities (VDR-CSO-FAV) ------------------------------------------
# A detection or response check that fails in detect-and-recover mode, or a
# finding still resting on a default after the evaluation window, is a process
# vulnerability: a finding with a tracking ID, a clock, a rating and a deadline,
# open for as long as the failure lasts and gone (remediated) when the check
# passes. A check in block mode stops the run instead; each such stopped run of
# the deploy or the nightly is listed in the next report with when it failed.
PROCESS_SEVERITY = "MEDIUM"  # severity proxy: N2, narrow effect (detection degraded)
PIPELINE_WORKFLOWS = ("Deploy Website with OPA Compliance", "Evidence Nightly (VDR refresh)", "ZAP DAST Scan")


def process_findings(events, rows):
    out = {}
    for ev in events or []:
        tid = f"process-{ev['check']}"
        if tid not in out:
            out[tid] = {"source": "process", "tool_id": ev["check"], "tracking_id": tid,
                        "title": f"Process failure: {ev.get('gate', '')} {ev['check']} ({ev.get('mode', '')})",
                        "description": ev.get("detail", ""), "severity": PROCESS_SEVERITY,
                        "resource": f"pipeline:{ev['check']}", "detected_at": ev.get("at")}
    for r in rows or []:
        if r.get("evaluation_late") == "default-after-evaluation-window" and r.get("source") != "process":
            tid = f"process-evaluation-{r['tracking_id']}"
            out[tid] = {"source": "process", "tool_id": "evaluation.default-after-window", "tracking_id": tid,
                        "title": "Process failure: evaluation still on a default after the VER-TFR-EVU window",
                        "description": f"{r['tracking_id']} has no vector and no prediction score",
                        "severity": PROCESS_SEVERITY, "resource": f"pipeline:evaluation:{r['tracking_id']}"}
    return sorted(out.values(), key=lambda f: f["tracking_id"])


def failed_runs(runs, since, workflows=PIPELINE_WORKFLOWS):
    """Stopped runs of the pipeline on main since the previous report: when each
    failed and which workflow. No run IDs or URLs are kept."""
    out = []
    for r in runs or []:
        if (r.get("workflowName") in workflows and r.get("headBranch") == "main"
                and str(r.get("createdAt") or "") > str(since or "")):
            out.append({"tracking_id": f"process-run-{r['workflowName'].lower().replace(' ', '-')}-{r['createdAt']}",
                        "workflow": r["workflowName"], "event": r.get("event"),
                        "failed_at": r.get("createdAt"), "ended_at": r.get("updatedAt")})
    return sorted(out, key=lambda x: x["failed_at"])


# ---- detection coverage per component (VDR-TFR-PCD) -----------------------------------------
# Which detection techniques reached each inventory component, and when. A
# component no technique reached within the window is a detection gap: the
# build records a vdr.coverage event, which makes it a process finding.
PCD_WINDOW_DAYS = 31  # VDR-TFR-PCD Class C: at least once every month
_IAC = ("checkov", "tfsec")
_SCA = ("grype", "dependabot")
# Component type -> the techniques that detect vulnerabilities in it.
TECHNIQUES = {
    "npm_package": _SCA, "pypi_package": _SCA,
    "html_artifact": ("zap-site",),
    "api_gateway": _IAC + ("zap-api",),
    "function": _IAC + _SCA + ("codeql",),
}
# Components outside the provider's own detection: the third party detects in
# its service, and the provider monitors it through the third-party register.
EXTERNAL_TYPES = {"external_service": "third-party service: detection is the provider's own "
                                      "(data/third-party-components.json)"}


def _feed_times(detection, dast):
    """{technique: ISO time it last ran}, from the detection gate's summary of
    this run (a feed without a source date counts at the gate's check time)
    and the DAST summary."""
    out = {}
    det = detection or {}
    for f in det.get("feeds") or []:
        if isinstance(f, dict) and f.get("status") == "ok":
            at = f.get("source_date") or det.get("checked_at")
            if at and (f["feed"] not in out or at > out[f["feed"]]):
                out[f["feed"]] = at
    if (dast or {}).get("status") == "ok" and dast.get("generated_at"):
        out["zap-site"] = dast["generated_at"]
    return out


def coverage(components, detection, dast, now):
    from datetime import datetime, timedelta
    times = _feed_times(detection, dast)
    floor = (now - timedelta(days=PCD_WINDOW_DAYS)).isoformat()
    rows, uncovered = [], []
    for cid, comp in sorted((components or {}).items()):
        ctype = comp.get("type")
        if ctype in EXTERNAL_TYPES:
            rows.append({"component_id": cid, "type": ctype, "techniques": [], "external": EXTERNAL_TYPES[ctype]})
            continue
        wanted = TECHNIQUES.get(ctype) or (_IAC if comp.get("resource_type") else ())
        techs = [{"technique": t, "at": times.get(t)} for t in wanted]
        recent = [t["at"] for t in techs if t["at"] and
                  datetime.fromisoformat(t["at"].replace("Z", "+00:00")).isoformat() >= floor]
        row = {"component_id": cid, "type": ctype, "techniques": techs,
               "last_detection": max(recent) if recent else None}
        rows.append(row)
        if not recent:
            uncovered.append(cid)
    return {"window_days": PCD_WINDOW_DAYS, "components": rows, "uncovered": uncovered,
            "covered": len(rows) - len(uncovered) - sum(1 for r in rows if "external" in r)}
