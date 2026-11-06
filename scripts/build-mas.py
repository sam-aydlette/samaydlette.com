#!/usr/bin/env python3
"""The Minimum Assessment Scope, generated: /.well-known/minimum-assessment-scope.json.

One machine-readable view of the cloud service offering's scope, joined from
what the pipeline already holds, so it cannot drift from it:

  MAS-CSO-IIR  the information resources: the canonical inventory (ksi-signal.json),
               plus every off-origin host the site's and app's Content Security
               Policies allow (infrastructure/bootstrap/cloudfront.tf), each placed
               on an inventoried component or put out of scope with a reason.
  MAS-CSO-FLO  the information flows (docs/boundary/boundary-classification.json)
               resolved against the inventory, each with a security category
               derived from its endpoints (the high-water mark of their FIPS 199
               categories); every external service and every data store is in at
               least one flow.
  MAS-CSO-MDI  the metadata inventory: every data store and log in the inventory,
               what it holds, which personal data, retention and location
               (data/minimum-assessment-scope.json supplies the meaning).
  MAS-CSO-TPR  each third-party information resource with the four fields FedRAMP
               requires (data/third-party-components.json, decided records only).
  FRC-CSX-MAS  how every KSI applies to the scope: per component through the KSI's
               evidence domain, or over the whole set.

Fails closed: any gap above stops the build, and so the deploy, before the SDR
is built. No ARN, account ID or address is published: components are named by
their inventory IDs.
"""

import argparse
import fnmatch
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _offering  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
INPUTS = REPO / "data" / "minimum-assessment-scope.json"
THIRD_PARTY = REPO / "data" / "third-party-components.json"
CLASSIFICATION = REPO / "docs" / "boundary" / "boundary-classification.json"
CLOUDFRONT_TF = REPO / "infrastructure" / "bootstrap" / "cloudfront.tf"
BOOTSTRAP_DIR = REPO / "infrastructure" / "bootstrap"
SCHEMA = "minimum-assessment-scope/1"
LEVELS = ("low", "moderate", "high")
OBJECTIVES = ("confidentiality", "integrity", "availability")
TPR_FIELDS = ("usage_and_configuration", "justification", "mitigations", "compensating_controls")
PACKAGE_TYPES = ("npm_package", "pypi_package")
CODE = {
    "builder": "scripts/build-mas.py",
    "inventory": "scripts/build-ksi-signal.py",
    "inputs": "data/minimum-assessment-scope.json",
    "flows": "docs/boundary/boundary-classification.json",
    "third_party": "data/third-party-components.json",
    "csp": "infrastructure/bootstrap/cloudfront.tf",
}
DERIVATION = (
    "Generated on every deploy by scripts/build-mas.py from this build's canonical inventory "
    "(ksi-signal.json, itself derived from Terraform state, the SBOMs, the site's HTML and the declared "
    "external services), the boundary classification's data-flow table, the operator's metadata and "
    "off-origin placements (data/minimum-assessment-scope.json) and the third-party records "
    "(data/third-party-components.json). Information resources are the inventory's components; the "
    "Content Security Policies the edge serves are parsed for every off-origin host, and each must be an "
    "inventoried component or out of scope with a stated reason. Each flow is resolved against the inventory "
    "and given the high-water mark of its endpoints' security categories. Every data store and log in the "
    "inventory must have a metadata entry, every external service and data store must be in a flow, every "
    "third-party resource must carry a decided record with the four MAS-CSO-TPR fields, and every component "
    "type must fall in at least one KSI's evidence domain or carry a whole-set reason. Any gap fails the "
    "build, so the deploy never publishes a scope with one."
)


def _fail(msg):
    raise SystemExit(f"::error::MAS: {msg} (fail-closed)")


# --- MAS-CSO-IIR: off-origin hosts from the CSPs ---------------------------------------

_URL = re.compile(r"https://([A-Za-z0-9.${}_-]+)")
_LOCAL = re.compile(r"\$\{local\.([A-Za-z0-9_]+)\}")
_VAR = re.compile(r"\$\{var\.([A-Za-z0-9_]+)\}")


def _locals(text):
    """{name: definition text} for every `name = ...` in a locals block (to the
    next blank line, enough for this repository's style)."""
    out = {}
    for block in re.finditer(r"locals\s*\{(.*?)\n\}", text, re.S):
        body = block.group(1)
        for m in re.finditer(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)(?=^\s*[A-Za-z0-9_]+\s*=|\Z)", body, re.S | re.M):
            v = m.group(2).strip()
            q = re.match(r'^"([^"\n]*)"', v)  # a plain string local: its content, without the quotes
            out[m.group(1)] = q.group(1) if q else v
    return out


def _var_defaults(text):
    return {m.group(1): m.group(2) for m in re.finditer(
        r'variable\s+"([A-Za-z0-9_]+)"\s*\{[^}]*?default\s*=\s*"([^"]*)"', text, re.S)}


def _expand(s, locals_, vars_, depth=0):
    if depth > 5:
        _fail("CSP expansion does not terminate")
    s = _VAR.sub(lambda m: vars_.get(m.group(1), m.group(0)), s)
    if "domain_name" in vars_:
        s = s.replace("${local.domain_dashed}", vars_["domain_name"].replace(".", "-"))
    return _LOCAL.sub(lambda m: _expand(locals_.get(m.group(1), m.group(0)), locals_, vars_, depth + 1), s)


def csp_hosts(tf_text, context_text=""):
    """Every host an https:// source in a content_security_policy names, with
    ${local.*} and ${var.*} references expanded from the same configuration."""
    whole = tf_text + "\n" + context_text
    locals_, vars_ = _locals(whole), _var_defaults(whole)
    hosts = set()
    for m in re.finditer(r"content_security_policy\s*=\s*join\(\s*\"; \",\s*\[(.*?)\]\s*\)", tf_text, re.S):
        expanded = _expand(m.group(1), locals_, vars_)
        # Every https:// source must yield a host: one that does not would be a
        # host this check silently missed.
        if expanded.count("https://") != len(_URL.findall(expanded)):
            _fail("a CSP https:// source does not resolve to a host")
        for h in _URL.findall(expanded):
            if "$" in h or "{" in h or "}" in h:
                _fail(f"cannot resolve the CSP source host {h!r}")
            hosts.add(h.lower())
    return sorted(hosts)


def place_hosts(hosts, placements, component_ids):
    """[(host, placement)] for every host; fails on a host placed nowhere, on a
    placement naming a component the inventory lacks, or with no reason."""
    out, problems = [], []
    for h in hosts:
        p = placements.get(h)
        if not isinstance(p, dict):
            problems.append(f"the CSP allows {h}, which is neither an inventoried information resource nor "
                            "out of scope with a reason (data/minimum-assessment-scope.json off_origin_hosts)")
            continue
        if p.get("component"):
            if p["component"] not in component_ids:
                problems.append(f"{h} is placed on {p['component']}, which is not in the inventory")
            out.append({"host": h, "component": p["component"]})
        elif isinstance(p.get("out_of_scope"), str) and p["out_of_scope"].strip():
            out.append({"host": h, "out_of_scope": p["out_of_scope"]})
        else:
            problems.append(f"{h} has neither a component nor an out_of_scope reason")
    return out, problems


# --- MAS-CSO-FLO -------------------------------------------------------------------------

def _match(pattern, ids):
    return sorted(i for i in ids if fnmatch.fnmatchcase(i, pattern))


def _high_water(categories):
    out = {}
    for o in OBJECTIVES:
        vals = [c.get(o) for c in categories if c.get(o) in LEVELS]
        if vals:
            out[o] = max(vals, key=LEVELS.index)
    return out


def flows(classification, components, data_store_types):
    by_id = {c["component_id"]: c for c in components}
    ids = sorted(by_id)
    declared = {d["key"] for d in classification.get("declared", [])}
    out, problems, covered = [], [], set()
    for f in classification.get("flows", []):
        endpoints = []
        for ref in f["path"]:
            if "declared" in ref:
                if ref["declared"] not in declared:
                    problems.append(f"flow {f['id']} names an undeclared actor {ref['declared']}")
                endpoints.append({"declared": ref["declared"]})
                continue
            hit = _match(ref["component"], ids)
            if not hit:
                problems.append(f"flow {f['id']} endpoint {ref['component']} matches no inventoried component")
            covered.update(hit)
            endpoints.append({"components": hit})
        cats = [by_id[i].get("security_category") or {} for e in endpoints for i in e.get("components", [])]
        category = _high_water(cats)
        if len(category) != len(OBJECTIVES):
            problems.append(f"flow {f['id']} has no endpoint with a security category")
        out.append({"id": f["id"], "label": f["label"], "endpoints": endpoints, "security_category": category,
                    **{k: f[k] for k in ("protocol", "auth", "encryption", "data", "note") if f.get(k)}})
    must = sorted(i for i, c in by_id.items() if c.get("type") == "external_service" or c.get("type") in data_store_types)
    for i in must:
        if i not in covered:
            problems.append(f"{i} ({by_id[i].get('type')}) is in no information flow")
    return out, problems


# --- MAS-CSO-MDI -------------------------------------------------------------------------

def metadata_inventory(components, metadata, data_store_types):
    out, problems = [], []
    keys = list(metadata)
    for c in sorted(components, key=lambda c: c["component_id"]):
        cid, ctype = c["component_id"], c.get("type")
        third_party_observed = cid in metadata and ctype == "external_service"
        if ctype not in data_store_types and not third_party_observed:
            continue
        key = cid if cid in metadata else next((k for k in keys if fnmatch.fnmatchcase(cid, k)), None)
        if key is None:
            problems.append(f"{cid} ({ctype}) holds data or logs but has no metadata entry "
                            "(data/minimum-assessment-scope.json metadata)")
            continue
        m = metadata[key]
        if not (isinstance(m.get("holds"), str) and isinstance(m.get("personal_data"), list)
                and isinstance(m.get("retention"), str)):
            problems.append(f"metadata entry {key} needs holds, personal_data and retention")
            continue
        attrs = c.get("attributes") or {}
        entry = {"component": cid, "type": ctype, "holds": m["holds"], "personal_data": m["personal_data"],
                 "retention": m["retention"],
                 "location": attrs.get("region") or ("third party" if ctype == "external_service" else "not recorded"),
                 "controlled_by": "third party" if ctype == "external_service" else "provider"}
        if "retention_days" in m:
            entry["retention_days"] = m["retention_days"]
        out.append(entry)
    return out, problems


# --- MAS-CSO-TPR -------------------------------------------------------------------------

def third_party(components, tpr_doc):
    recs = (tpr_doc or {}).get("components") or {}
    out, problems = [], []
    for c in sorted(components, key=lambda c: c["component_id"]):
        if c.get("type") != "external_service":
            continue
        cid, rec = c["component_id"], recs.get(c["component_id"])
        if not rec:
            problems.append(f"{cid} has no third-party record (data/third-party-components.json)")
            continue
        if not (rec.get("decided_by") and rec.get("decided_on")):
            problems.append(f"{cid}'s third-party record has no decision (decided_by, decided_on)")
            continue
        missing = [f for f in TPR_FIELDS if not (isinstance(rec.get(f), str) and rec[f].strip())]
        if missing:
            problems.append(f"{cid}'s third-party record lacks {', '.join(missing)}")
            continue
        attrs = c.get("attributes") or {}
        out.append({"component": cid, "name": attrs.get("name") or cid, "provider": rec.get("provider"),
                    "website": rec.get("website"), "upstream_offering": rec.get("upstream_offering"),
                    **{f: rec[f] for f in TPR_FIELDS},
                    "decided_by": rec["decided_by"], "decided_on": rec["decided_on"]})
    return out, problems


# --- FRC-CSX-MAS -------------------------------------------------------------------------

def ksi_application(signal, whole_set_types):
    """Per KSI: the components its evidence domain covers, or the whole set.
    A KSI whose evidence is every component (or none, a documentation KSI)
    applies over the whole set; the rest apply per component."""
    comps = [c for c in signal.get("components", [])]
    all_ids = {c["component_id"] for c in comps}
    type_of = {c["component_id"]: c.get("type") for c in comps}
    out, domain_types = [], set()
    for k in signal.get("ksis", []):
        refs = set((k.get("evidence") or {}).get("component_refs") or [])
        whole = not refs or refs >= all_ids
        if not whole:
            domain_types.update(type_of[r] for r in refs if r in type_of)
        out.append({"ksi": k["id"], "method": k.get("method"), "status": k.get("status"),
                    "applies_to": "whole set" if whole else "per component",
                    "components": len(all_ids) if whole else len(refs & all_ids),
                    "component_types": sorted({type_of[r] for r in (all_ids if whole else refs & all_ids)})})
    problems = []
    if not out:
        problems.append("the inventory carries no KSIs")
    for t in sorted({type_of[i] for i in all_ids}):
        if t not in domain_types and not (isinstance(whole_set_types.get(t), str) and whole_set_types[t].strip()):
            problems.append(f"component type {t} is in no KSI's per-component evidence domain and has no whole-set "
                            "reason (data/minimum-assessment-scope.json whole_set_types)")
    per_type = {t: ("per component" if t in domain_types else f"whole set only: {whole_set_types[t]}")
                for t in sorted({type_of[i] for i in all_ids}) if t in domain_types or t in whole_set_types}
    return out, per_type, problems


# --- build -------------------------------------------------------------------------------

def build(signal, inputs, classification, tpr_doc, cloudfront_tf, bootstrap_context, commit, now):
    comps = signal.get("components", [])
    ids = {c["component_id"] for c in comps}
    dst = set(inputs.get("data_store_types") or [])
    hosts, p1 = place_hosts(csp_hosts(cloudfront_tf, bootstrap_context), inputs.get("off_origin_hosts") or {}, ids)
    fl, p2 = flows(classification, comps, dst)
    md, p3 = metadata_inventory(comps, inputs.get("metadata") or {}, dst)
    tp, p4 = third_party(comps, tpr_doc)
    ka, per_type, p5 = ksi_application(signal, inputs.get("whole_set_types") or {})
    problems = p1 + p2 + p3 + p4 + p5
    by_type = {}
    for c in comps:
        by_type[c.get("type")] = by_type.get(c.get("type"), 0) + 1
    resources = [{"component": c["component_id"], "type": c.get("type"),
                  "security_category": c.get("security_category"),
                  "function": (c.get("attributes") or {}).get("function")}
                 for c in sorted(comps, key=lambda c: c["component_id"]) if c.get("type") not in PACKAGE_TYPES]
    doc = {
        "schema": SCHEMA,
        "generated_at": now,
        "commit": commit,
        "ksi_signal_id": signal.get("signal_id"),
        "derivation": DERIVATION,
        "code": CODE,
        "information_resources": {
            "total": len(comps),
            "by_type": dict(sorted(by_type.items())),
            "software_packages": sum(by_type.get(t, 0) for t in PACKAGE_TYPES),
            "resources": resources,
            "off_origin_hosts": hosts,
        },
        "flows": fl,
        "metadata_inventory": md,
        "third_party_information_resources": tp,
        "ksi_application": {"ksis": ka, "component_types": per_type},
        "checks": {
            "off_origin_hosts_placed": not p1,
            "every_external_service_and_data_store_in_a_flow": not p2,
            "every_data_store_and_log_has_metadata": not p3,
            "every_third_party_resource_decided_with_all_fields": not p4,
            "every_component_type_in_a_ksi_domain": not p5,
        },
    }
    return doc, problems


def render_markdown(d):
    ir = d["information_resources"]
    out = ["# Minimum Assessment Scope", "",
           f"_Generated {d['generated_at']} from inventory `{d['ksi_signal_id']}` at commit `{(d['commit'] or '')[:12]}`._",
           "", "## How this is derived", "", d["derivation"], "",
           "Code: " + ", ".join(f"`{v}`" for v in d["code"].values()), "",
           "## Information resources (MAS-CSO-IIR)", "",
           f"{ir['total']} inventoried components, {ir['software_packages']} of them software packages.", "",
           "| Type | Count |", "|---|---|", *[f"| {t} | {n} |" for t, n in ir["by_type"].items()], "",
           "| Component | Type | C/I/A | Function |", "|---|---|---|---|"]
    for r in ir["resources"]:
        sc = r.get("security_category") or {}
        out.append(f"| `{r['component']}` | {r['type']} | {'/'.join(sc.get(o, '?') for o in OBJECTIVES)} | "
                   f"{(r.get('function') or '').replace('|', '/')} |")
    out += ["", "Off-origin hosts the Content Security Policies allow:", "",
            "| Host | Placement |", "|---|---|"]
    for h in ir["off_origin_hosts"]:
        out.append(f"| {h['host']} | " + (f"`{h['component']}`" if h.get("component") else f"Out of scope: {h['out_of_scope']}") + " |")
    out += ["", "## Information flows and security categories (MAS-CSO-FLO)", "",
            "| Flow | Endpoints | C/I/A | Protocol | Auth | Encryption | Data |", "|---|---|---|---|---|---|---|"]
    for f in d["flows"]:
        ends = " → ".join(e.get("declared") or ", ".join(e["components"]) or "(none)" for e in f["endpoints"])
        sc = f["security_category"]
        out.append(f"| {f['id']}: {f['label']} | {ends} | {'/'.join(sc.get(o, '?') for o in OBJECTIVES)} | "
                   f"{f.get('protocol', '')} | {f.get('auth', '')} | {f.get('encryption', '')} | {f.get('data', '')} |")
    out += ["", "## Metadata inventory (MAS-CSO-MDI)", "",
            "| Component | Holds | Personal data | Retention | Location |", "|---|---|---|---|---|"]
    for m in d["metadata_inventory"]:
        out.append(f"| `{m['component']}` | {m['holds']} | {', '.join(m['personal_data']) or 'none'} | "
                   f"{m['retention']} | {m['location']} ({m['controlled_by']}) |")
    out += ["", "## Third-party information resources (MAS-CSO-TPR)", ""]
    for t in d["third_party_information_resources"]:
        out += [f"### {t['name']} (`{t['component']}`)", "",
                f"- **Provider:** {t['provider']} ({t['website']})",
                f"- **General usage and configuration:** {t['usage_and_configuration']}",
                f"- **Justification for use:** {t['justification']}",
                f"- **Mitigation measures:** {t['mitigations']}",
                f"- **Compensating controls:** {t['compensating_controls']}",
                f"- **Decided by:** {t['decided_by']}, {t['decided_on']}", ""]
    out += ["## Key Security Indicators applied to the scope (FRC-CSX-MAS)", "",
            "| KSI | Method | Applies | Components | Types |", "|---|---|---|---|---|"]
    for k in d["ksi_application"]["ksis"]:
        out.append(f"| {k['ksi']} | {k['method']} | {k['applies_to']} | {k['components']} | {', '.join(k['component_types'])} |")
    out += ["", "| Component type | Coverage |", "|---|---|",
            *[f"| {t} | {v} |" for t, v in d["ksi_application"]["component_types"].items()],
            "", "## Checks", "", *[f"- {k}: {'pass' if v else 'FAIL'}" for k, v in d["checks"].items()],
            "", "---", "_Source of truth: the signed `minimum-assessment-scope.json`._"]
    return "\n".join(out)


def _read_json(path, what):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {what} {path} ({type(exc).__name__})")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--inputs", default=str(INPUTS))
    ap.add_argument("--classification", default=str(CLASSIFICATION))
    ap.add_argument("--third-party", default=str(THIRD_PARTY))
    ap.add_argument("--cloudfront-tf", default=str(CLOUDFRONT_TF))
    ap.add_argument("--commit", default="")
    ap.add_argument("--output", default="minimum-assessment-scope.json")
    ap.add_argument("--md-output", default="minimum-assessment-scope.md")
    a = ap.parse_args(argv)
    signal = _read_json(a.ksi_signal, "the KSI signal")
    inputs = _read_json(a.inputs, "the MAS inputs")
    if inputs.get("schema") != "mas-inputs/1":
        _fail(f"{a.inputs} is not a mas-inputs/1 document")
    tf = Path(a.cloudfront_tf).read_text()
    context = "\n".join(p.read_text() for p in sorted(Path(a.cloudfront_tf).parent.glob("*.tf")))
    doc, problems = build(signal, inputs, _read_json(a.classification, "the classification"),
                          _read_json(a.third_party, "the third-party records"), tf, context, a.commit,
                          datetime.now(timezone.utc).isoformat())
    if problems:
        for p in problems:
            print(f"::error::MAS: {p}")
        _fail(f"{len(problems)} gap(s) in the Minimum Assessment Scope")
    doc = _offering.stamp_fedramp_id(doc)  # CDS-CSO-FID
    Path(a.output).write_text(json.dumps(doc, indent=2) + "\n")
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(doc) + "\n")
    print(f"minimum-assessment-scope: {doc['information_resources']['total']} components, {len(doc['flows'])} flows, "
          f"{len(doc['metadata_inventory'])} metadata entries, {len(doc['third_party_information_resources'])} "
          f"third-party records, {len(doc['ksi_application']['ksis'])} KSIs applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
