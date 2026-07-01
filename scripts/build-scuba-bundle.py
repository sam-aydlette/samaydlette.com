#!/usr/bin/env python3
# =============================================================================
# SCuBA BUNDLE GENERATOR  (Phase 2)
# =============================================================================
# Generates a COMPLETE SCuBA policy bundle — one policy per in-scope control —
# from the hub-derived SSP, so a customer sees their responsibility for every
# control, not just the action items. Each policy is BOTH Rego (OPA) and
# markdown (human-readable).
#
#   - Controls with a hand-authored bespoke check (real customer action, e.g.
#     phishing-resistant MFA, TLS) use that policy.
#   - Every other control gets a DEFAULT policy: an OPA rule that passes with a
#     statement of who actually satisfies it (provider / AWS-inherited / N-A /
#     planned), derived from the control's authored control-origination. No
#     customer action required.
#
# Output: <out>/policies/<control>.rego + .md  and  <out>/bundle.json
# Bespoke policies + this generator are committed; the generated bundle is a
# build artifact (regenerable, signed + published in the pipeline).
# =============================================================================

import argparse
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
BESPOKE_DIR = HERE / "scuba" / "policies"
BESPOKE_MANIFEST = HERE / "scuba" / "bundle.json"


def classify(status, origination):
    if status == "not-applicable":
        return "not-applicable"
    if status == "planned":
        return "planned"
    if origination == "inherited":
        return "fully-inherited"
    if origination == "shared":
        return "partially-inherited"
    if origination in ("customer-configured", "customer-provided"):
        return "customer-responsibility"
    return "implemented"


WHO = {
    "fully-inherited": "AWS (leveraged FedRAMP certification)",
    "partially-inherited": "the provider and AWS (shared; no separate customer action)",
    "implemented": "the provider (cloud service offering and operator policies)",
    "not-applicable": "not applicable to this offering",
    "planned": "the provider (planned; not yet implemented)",
    "customer-responsibility": "the customer",
}


def pkg(cid):
    return "scuba.c_" + re.sub(r"[^a-z0-9]", "_", cid.lower())


def prop(ir, name):
    for p in ir.get("props", []) or []:
        if p.get("name") == name:
            return p.get("value")
    return None


def default_rego(cid, resp):
    who = WHO.get(resp, "the provider")
    return (
        f"# SCuBA default policy for {cid.upper()} — no customer action required.\n"
        f"# Satisfied by {who}. Generated from the control's authored origination.\n"
        f"package {pkg(cid)}\n\n"
        f"default pass := true\n\n"
        f'result := {{"pass": true, "detail": "No customer action required; satisfied by {who}."}}\n'
    )


def default_md(cid, title, resp, statement):
    who = WHO.get(resp, "the provider")
    snippet = (statement or "").split("\n")[0][:300]
    return (
        f"# {cid.upper()} — {title}\n\n"
        f"**Responsibility:** {resp} → satisfied by **{who}**.\n"
        f"**Customer action:** none required.\n\n"
        f"## Why no action is required\n{snippet}\n\n"
        f"_This is a default policy: the customer has no configuration responsibility "
        f"for this control under this cloud service offering. It is included so the "
        f"SCuBA gives complete, per-control coverage (the executable CRM)._\n"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssp", required=True)
    ap.add_argument("--out", default=str(HERE / "scuba" / "dist"))
    a = ap.parse_args()

    bespoke = {p["control"]: p for p in json.loads(BESPOKE_MANIFEST.read_text())["policies"]}
    irs = json.loads(Path(a.ssp).read_text())["system-security-plan"]["control-implementation"]["implemented-requirements"]

    out = Path(a.out)
    (out / "policies").mkdir(parents=True, exist_ok=True)
    manifest = {"name": "Silk Reeling Mirror — Customer Responsibility SCuBA (complete)",
                "version": "1.0.0", "hub_catalog": "NIST 800-53 Rev5", "policies": []}
    from collections import Counter
    kinds = Counter()
    resp_counts = Counter()

    for ir in sorted(irs, key=lambda r: r["control-id"]):
        cid = ir["control-id"]
        status = prop(ir, "implementation-status")
        orig = prop(ir, "control-origination")
        resp = classify(status, orig)
        resp_counts[resp] += 1
        rego_path = out / "policies" / f"{cid}.rego"
        md_path = out / "policies" / f"{cid}.md"

        if cid in bespoke:
            b = bespoke[cid]
            src_rego = (BESPOKE_DIR / f"{b['name']}.rego").read_text()
            src_md = (BESPOKE_DIR / f"{b['name']}.md").read_text()
            rego_path.write_text(src_rego)
            md_path.write_text(src_md)
            manifest["policies"].append({"id": b["id"], "control": cid, "title": b["title"],
                                         "type": "customer-action", "package": b["package"],
                                         "severity": b.get("severity", "high"),
                                         "rego": f"policies/{cid}.rego", "md": f"policies/{cid}.md",
                                         "responsibility": resp})
            kinds["customer-action"] += 1
        else:
            stmt = ""
            for s in ir.get("statements", []) or []:
                stmt = s.get("remarks", "") or ""
                break
            rego_path.write_text(default_rego(cid, resp))
            md_path.write_text(default_md(cid, cid.upper(), resp, stmt))
            manifest["policies"].append({"id": f"DEF-{cid.upper()}", "control": cid,
                                         "title": cid.upper(), "type": "default",
                                         "package": pkg(cid), "rego": f"policies/{cid}.rego",
                                         "md": f"policies/{cid}.md", "responsibility": resp,
                                         "default_detail": f"No customer action required; satisfied by {WHO.get(resp)}."})
            kinds["default"] += 1

    (out / "bundle.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"generated {len(manifest['policies'])} policies -> {out}")
    print(f"  kinds: {dict(kinds)}")
    print(f"  by responsibility: {dict(resp_counts)}")


if __name__ == "__main__":
    main()
