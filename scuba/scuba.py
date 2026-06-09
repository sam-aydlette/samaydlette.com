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
    return mod_set, rev4_rev


def frameworks_for(control, mod_set, rev4_rev):
    fw = [("NIST 800-53 Rev5", control)]
    if control in mod_set:
        fw.append(("FedRAMP Rev5 Moderate", control))
    r4 = rev4_rev.get(control, [])
    if r4:
        fw.append(("NIST 800-53 Rev4", ", ".join(sorted(r4))))
    fw.append(("CMMC L2 / GovRAMP / TX-RAMP / IRAP", "mapping pending (added at each spoke checkpoint)"))
    return fw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--bundle", default=str(HERE))
    ap.add_argument("--output", default=None)
    a = ap.parse_args()

    bundle = json.loads((Path(a.bundle) / "bundle.json").read_text())
    mod_set, rev4_rev = load_framework_projection()
    now = datetime.now(timezone.utc).isoformat()

    rows = []
    observations, findings, reviewed = [], [], []
    print(f"\n  SCuBA — {bundle['name']}")
    print(f"  config: {a.config}   (assessed locally; nothing transmitted)\n")
    n_pass = 0
    for p in bundle["policies"]:
        rego = Path(a.bundle) / "policies" / f"{p['name']}.rego"
        res = opa_eval(rego, p["package"], a.config)
        ok = bool(res.get("pass"))
        n_pass += ok
        fw = frameworks_for(p["control"], mod_set, rev4_rev)
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {p['id']}  {p['title']}")
        print(f"         {res.get('detail','')}")
        print(f"         hub control: 800-53 {p['control']}  -> satisfies:")
        for name, ref in fw:
            print(f"            - {name}: {ref}")
        print()
        reviewed.append(p["control"])
        observations.append({
            "uuid": str(uuid.uuid5(NS, "obs:" + p["id"])),
            "title": f"{p['id']} {p['title']}",
            "description": res.get("detail", ""),
            "methods": ["TEST"],
            "props": [{"name": "assessment-result", "value": "pass" if ok else "fail"},
                      {"name": "hub-control", "value": p["control"]}],
            "collected": now,
        })
        if not ok:
            findings.append({
                "uuid": str(uuid.uuid5(NS, "finding:" + p["id"])),
                "title": f"{p['id']} {p['title']} — not satisfied",
                "description": res.get("detail", ""),
                "target": {"type": "objective-id", "target-id": p["control"],
                           "status": {"state": "not-satisfied"}},
            })

    print(f"  ── {n_pass}/{len(bundle['policies'])} policies pass ──\n")

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
