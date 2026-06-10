#!/usr/bin/env python3
# =============================================================================
# SCuBA CLI — customer-run secure-configuration assessment  (Phase 2)
# =============================================================================
# The customer-run tool (loosely modeled on CISA's ScubaGoggles). It:
#   1. loads the signed SCuBA policy bundle (in production: fetch from
#      /.well-known/ and cosign-verify; here: read the local bundle),
#   2. evaluates each policy LOCALLY with OPA against the customer's own config
#      (nothing leaves the customer's environment),
#   3. projects each policy's 800-53 hub control to every framework via the
#      published control mappings (one config check -> N frameworks),
#   4. emits an OSCAL Assessment Results document + a terminal report.
#
# It FLAGS; it does not bless. A pass means "this config satisfies the mapped
# control"; it is evidence, not an authorization.
#
# Usage: scuba.py --config CONFIG.json [--bundle DIR] [--output RESULTS.json]
# =============================================================================

import argparse
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
NS = uuid.UUID("5c0ba000-0000-5000-8000-000000000001")


def opa_eval(rego_path, package, config_path):
    """Evaluate data.<package>.result with OPA, locally."""
    q = f"data.{package}.result"
    out = subprocess.run(
        ["opa", "eval", "-d", str(rego_path), "-i", str(config_path), q, "--format", "json"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        return {"pass": False, "detail": f"OPA error: {out.stderr.strip()[:120]}"}
    doc = json.loads(out.stdout)
    try:
        return doc["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError):
        return {"pass": False, "detail": "policy returned no result"}


def load_framework_projection():
    """Hub-control -> frameworks, from the published mappings/baselines."""
    mod = json.loads((REPO / "data/profiles/FedRAMP_rev5_MODERATE-baseline-resolved-profile_catalog.json").read_text())["catalog"]
    mod_set = set()
    def walk(n):
        for c in n.get("controls", []) or []:
            mod_set.add(c["id"]); walk(c)
        for g in n.get("groups", []) or []:
            walk(g)
    walk(mod)
    # reverse the Rev4->Rev5 mapping: rev5 control -> [rev4 controls]
    mp = json.loads((REPO / "data/mappings/SP800-53_rev4-to-rev5.mapping.json").read_text())["mapping-collection"]
    rev4_rev = {}
    for m in mp["mappings"][0]["maps"]:
        rev4_rev.setdefault(m["targets"][0]["id-ref"], []).append(m["sources"][0]["id-ref"])
    # reverse the 171->53r4 mapping: rev4 control -> [CMMC 171 requirements]
    m171 = json.loads((REPO / "data/mappings/SP800-171r2-to-SP800-53r4.mapping.json").read_text())["mapping-collection"]
    rev4_to_171 = {}
    for m in m171["mappings"][0]["maps"]:
        rev4_to_171.setdefault(m["targets"][0]["id-ref"], []).append(m["sources"][0]["id-ref"])
    return mod_set, rev4_rev, rev4_to_171


def frameworks_for(control, mod_set, rev4_rev, rev4_to_171):
    fw = [("NIST 800-53 Rev5", control)]
    if control in mod_set:
        fw.append(("FedRAMP Rev5 Moderate", control))
    r4 = rev4_rev.get(control, [])
    if r4:
        fw.append(("NIST 800-53 Rev4", ", ".join(sorted(r4))))
    # CMMC L2: 171 requirements whose 53r4 controls chain to this hub control
    cmmc = sorted({req for c in (set(r4) | {control}) for req in rev4_to_171.get(c, [])})
    if cmmc:
        fw.append(("CMMC L2 (800-171 Rev2)", ", ".join(cmmc)))
    fw.append(("GovRAMP / TX-RAMP / CJIS / IRAP", "mapping pending (added at each spoke checkpoint)"))
    return fw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--bundle", default=str(HERE))
    ap.add_argument("--output", default=None)
    a = ap.parse_args()

    bundle = json.loads((Path(a.bundle) / "bundle.json").read_text())
    mod_set, rev4_rev, rev4_to_171 = load_framework_projection()
    now = datetime.now(timezone.utc).isoformat()

    observations, findings, reviewed = [], [], []
    from collections import Counter
    default_by_resp = Counter()
    actions = []
    n_pass_actions = 0

    print(f"\n  SCuBA — {bundle['name']}")
    print(f"  config: {a.config}   (assessed locally; nothing transmitted)\n")

    for p in bundle["policies"]:
        reviewed.append(p["control"])
        if p.get("type") == "default":
            ok, detail = True, p.get("default_detail", "")
            default_by_resp[p.get("responsibility", "implemented")] += 1
        else:  # customer-action -> evaluate with OPA locally
            res = opa_eval(Path(a.bundle) / p["rego"], p["package"], a.config)
            ok, detail = bool(res.get("pass")), res.get("detail", "")
            n_pass_actions += ok
            actions.append((p, ok, detail))
        observations.append({
            "uuid": str(uuid.uuid5(NS, "obs:" + p["control"])),
            "title": f"{p['id']} {p['title']}",
            "description": detail,
            "methods": ["TEST"],
            "props": [{"name": "assessment-result", "value": "pass" if ok else "fail"},
                      {"name": "policy-type", "value": p.get("type", "default")},
                      {"name": "hub-control", "value": p["control"]}],
            "collected": now,
        })
        if not ok:
            findings.append({
                "uuid": str(uuid.uuid5(NS, "finding:" + p["control"])),
                "title": f"{p['id']} {p['title']} — not satisfied",
                "description": detail,
                "target": {"type": "objective-id", "target-id": p["control"],
                           "status": {"state": "not-satisfied"}},
            })

    print(f"  CUSTOMER ACTIONS ({len(actions)}):")
    for p, ok, detail in actions:
        print(f"  [{'PASS' if ok else 'FAIL'}] {p['id']}  {p['title']}")
        print(f"         {detail}")
        print(f"         hub control 800-53 {p['control']} -> satisfies:")
        for name, ref in frameworks_for(p["control"], mod_set, rev4_rev, rev4_to_171):
            print(f"            - {name}: {ref}")
    label = {"implemented": "provider-implemented", "not-applicable": "not applicable",
             "partially-inherited": "shared (provider + AWS)", "fully-inherited": "AWS-inherited",
             "planned": "provider (planned)", "customer-responsibility": "customer"}
    print(f"\n  NO CUSTOMER ACTION REQUIRED ({sum(default_by_resp.values())}):")
    for resp, n in default_by_resp.most_common():
        print(f"     {n:4}  {label.get(resp, resp)}")
    print(f"  (every control still has a policy + markdown in the bundle: policies/<control>.md)\n")
    print(f"  ── {len(observations)}/{len(observations)} controls covered; "
          f"{n_pass_actions}/{len(actions)} customer actions pass ──\n")
    n_pass = n_pass_actions + sum(default_by_resp.values())

    results_doc = {
        "assessment-results": {
            "uuid": str(uuid.uuid5(NS, "ar:" + a.config)),
            "metadata": {"title": f"SCuBA customer self-assessment — {bundle['name']}",
                         "last-modified": now, "version": "1.0.0", "oscal-version": "1.2.2"},
            "import-ap": {"href": "#scuba-bundle"},
            "results": [{
                "uuid": str(uuid.uuid5(NS, "result:" + a.config)),
                "title": "SCuBA local configuration assessment",
                "description": "Customer-run OPA assessment of local configuration against the SCuBA baseline.",
                "start": now,
                "reviewed-controls": {"control-selections": [
                    {"include-controls": [{"control-id": c} for c in reviewed]}]},
                "observations": observations,
                "findings": findings or None,
            }],
        }
    }
    if results_doc["assessment-results"]["results"][0]["findings"] is None:
        del results_doc["assessment-results"]["results"][0]["findings"]

    if a.output:
        Path(a.output).write_text(json.dumps(results_doc, indent=2) + "\n")
        print(f"  OSCAL Assessment Results written: {a.output}")

    sys.exit(0 if n_pass == len(bundle["policies"]) else 2)


if __name__ == "__main__":
    main()
