#!/usr/bin/env python3
"""The assessor guide: how to verify and validate each FedRAMP rule and KSI
here, by hand or by machine (IVV-CSO-STE, IVV-CSO-DUS).

Generated from the rule records (data/frr-records.json) and the KSI catalog, so
it cannot describe a mechanism the records do not cite. For every rule it gives
the provider's explanation and, for every piece of evidence, the command that
reproduces the check and a machine-readable form of the same check. The
simulated assessor (tools/simulated-assessor/assess.py) executes exactly those
machine-readable checks on every deploy: the guide is the demonstration.

It also states the sampling position (IVV-CSO-DUS): no check here uses a
representative sample.

    python3 scripts/build-assessor-guide.py --output assessor-guide.json --md-output assessor-guide.md
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _freshness  # noqa: E402
import _frr  # noqa: E402
import _ksi_applicability  # noqa: E402
import _offering  # noqa: E402
import _rules  # noqa: E402
import _signers  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SITE = "https://samaydlette.com"
REPO_URL = _signers.REPO_URL
ISSUER = _signers.ISSUER
# Every workflow that signs something published, from the one table of who
# writes what (scripts/_signers.py). The simulated assessor signs its own record
# under its own workflow identity.
IDENTITIES = dict(_signers.IDENTITIES)
SCHEMA = "assessor-guide/1"
SAMPLING = ("No representative samples are used in verification or validation (IVV-CSO-DUS). Every check runs "
            "over its full population: the OPA gate and the KSI signal evaluate every inventoried component; the "
            "reconciliation gate compares every live in-boundary resource with the inventory; the vulnerability "
            "scan covers every SBOM; every FedRAMP rule record is validated and every test it cites runs on every "
            "build; and the simulated assessor re-checks every rule and every KSI rather than a selection.")
HOW_TO_USE = ("Read each rule's explanation, then run the command beside each piece of evidence. Tests run from a "
              "clone of the repository after `make dev-setup`; published artifacts are fetched from the site and "
              "their signatures verified with cosign against the publishing workflow's identity; workflow steps "
              "are read in the workflow file and their run logs in the repository's Actions tab; decision records "
              "are in data/decisions.json. The `check` beside each command is the same check in machine-readable "
              "form. For a walkthrough of any mechanism, ask through the security contact in the Certification "
              "Package Overview.")


def _artifact_check(ref, fresh):
    entry = fresh.get(ref)
    if entry is None:
        raise SystemExit(f"::error::assessor guide: {ref} is not in the freshness config, so an assessor could "
                         "not tell how fresh it must be (fail-closed)")
    name = ref.split("/", 1)[1]
    sig = entry.get("signature")
    return {"url": f"{SITE}/{ref}", "bundle_url": f"{SITE}/{sig}" if sig else None,
            "identities": _signers.signers(name),
            "timestamp": entry["timestamp"], "max_age_hours": entry["max_age_hours"]}


def reproduce(ev, fresh):
    kind, ref = ev["kind"], ev["ref"]
    if kind == "test":
        return f"python3 -m pytest '{ref}'", {"pytest": ref}
    if kind == "step":
        wf, step = ref.split("#", 1)
        return (f"Read the step named {step!r} in .github/workflows/{wf}, and its log in the latest run of that "
                "workflow on main", {"workflow": wf, "step": step})
    if kind == "artifact":
        chk = _artifact_check(ref, fresh)
        cmd = f"curl -fsSLO {chk['url']}"
        if chk["bundle_url"]:
            # One verification per workflow allowed to have signed it; any one passing is enough.
            verify = " || ".join(
                f"cosign verify-blob --bundle {chk['bundle_url'].rsplit('/', 1)[1]} "
                f"--certificate-identity {IDENTITIES[i]} --certificate-oidc-issuer {ISSUER} {ref.rsplit('/', 1)[1]}"
                for i in chk["identities"])
            cmd += f" && curl -fsSLO {chk['bundle_url']} && {{ {verify}; }}"
        return cmd, {"artifact": chk}
    if kind == "decision":
        return f"jq '.decisions[] | select(.id == \"{ref}\")' data/decisions.json", {"decision": ref}
    raise SystemExit(f"::error::assessor guide: unknown evidence kind {kind!r}")


def build(records, applicable, catalog, fresh, now, commit=None, not_applicable=()):
    """`not_applicable` is the KSIs recorded as not applying, which the
    inventory carries no result for (data/ksi-applicability.json)."""
    rules = []
    for r in records["records"]:
        rid = r["frr_id"]
        evidence = []
        for ev in r.get("evidence", []):
            cmd, chk = reproduce(ev, fresh)
            evidence.append({"kind": ev["kind"], "ref": ev["ref"], "how_to_reproduce": cmd, "check": chk})
        entry = {"rule_id": rid, "name": applicable[rid]["name"], "force": applicable[rid]["force"],
                 "statement": applicable[rid]["statement"], "status": r["status"],
                 "explanation": r["implementation"], "evidence": evidence}
        for k in ("not_applicable", "not_demonstrated", "may_rationale", "simulated", "proposal", "approval"):
            if k in r:
                entry[k] = r[k]
        if "stand_in_proof" in r:
            proof = r["stand_in_proof"]
            entry["stand_in_proof"] = {
                "bad_input": {"ref": proof["bad_input"], "how_to_reproduce": f"python3 -m pytest '{proof['bad_input']}'",
                              "check": {"pytest": proof["bad_input"]}},
                "replaceable": {"statement": proof["replaceable"]["statement"]}}
            if proof["replaceable"].get("test"):
                t = proof["replaceable"]["test"]
                entry["stand_in_proof"]["replaceable"].update(
                    {"ref": t, "how_to_reproduce": f"python3 -m pytest '{t}'", "check": {"pytest": t}})
        rules.append(entry)
    ksis = [{"ksi_id": i["id"], "name": i.get("name", ""),
             "how_to_reproduce": (f"curl -fsSL {SITE}/.well-known/ksi-signal.json | jq '.ksis[] | "
                                  f"select(.id == \"{i['id']}\")' after verifying ksi-signal.bundle against the "
                                  "deploy identity; the SDR's keySecurityIndicators entry gives its measures"),
             "check": {"ksi_in_signal": i["id"]}}
            for f in catalog["KSI"].values() for i in f["indicators"] if i["id"] not in not_applicable]
    return {"schema": SCHEMA, "fedRampId": _offering.fedramp_id(), "generated_at": now.isoformat(), "commit": commit, "site": SITE,
            "repository": REPO_URL, "how_to_use": HOW_TO_USE, "sampling": SAMPLING,
            "identities": {**IDENTITIES, "oidc_issuer": ISSUER},
            # Who approves a stand-in or scope cut (Simulated, Not Demonstrated and
            # Not Applicable records): the operator, and nobody else.
            "operator": _frr.OPERATOR,
            "summary": {"rules": len(rules), "ksis": len(ksis),
                        "evidence_items": sum(len(r["evidence"]) for r in rules)},
            "rules": rules, "ksis": sorted(ksis, key=lambda k: k["ksi_id"])}


def render_markdown(g):
    out = ["# Assessor guide", "",
           "_How to verify and validate each FedRAMP rule and Key Security Indicator for this offering. Generated "
           "from the rule records on every deploy; the simulated assessor runs these exact checks._", "",
           f"- **Generated:** {g['generated_at']} | **Commit:** `{g['commit'] or 'local build'}`",
           f"- **Rules:** {g['summary']['rules']} | **KSIs:** {g['summary']['ksis']} | "
           f"**Evidence items:** {g['summary']['evidence_items']}", "",
           "## How to use this guide", "", g["how_to_use"], "",
           "## Sampling (IVV-CSO-DUS)", "", g["sampling"], "",
           "## Signing identities", ""]
    out += [f"- {k}: `{v}`" for k, v in g["identities"].items()]
    out += ["", "## FedRAMP rules", ""]
    for r in g["rules"]:
        out += [f"### {r['rule_id']}: {r['name']} ({r['force']}, {r['status']})", "", r["explanation"], ""]
        for k, label in (("not_applicable", "Not applicable"), ("may_rationale", "Use of this permission")):
            if k in r:
                out += [f"{label}: {r[k]}", ""]
        if "not_demonstrated" in r:
            out += [f"Not demonstrated: {r['not_demonstrated']}", ""]
        if "simulated" in r:
            out += [f"Simulated counterparty ({r['simulated']['counterparty']}): {r['simulated']['how']}", ""]
            for k, label in (("real", "What is real"), ("stand_in", "What is simulated")):
                if r["simulated"].get(k):
                    out += [f"{label}: {r['simulated'][k]}", ""]
        if "stand_in_proof" in r:
            sp = r["stand_in_proof"]
            rp = sp["replaceable"]
            out += [f"Stand-in proof: `{sp['bad_input']['how_to_reproduce']}`; replaceable: {rp['statement']}"
                    + (f" `{rp['how_to_reproduce']}`" if rp.get("how_to_reproduce") else ""), ""]
        if r["status"] in _frr.NEEDS_APPROVAL:
            out += [("Approved by " + f"{r['approval']['by']} on {r['approval']['on']}." if r.get("approval") else
                     f"Not approved by the operator ({g['operator']})."), ""]
        for ev in r["evidence"]:
            out.append(f"- {ev['kind']} `{ev['ref']}`: `{ev['how_to_reproduce']}`")
        if r["evidence"]:
            out.append("")
    out += ["## Key Security Indicators", ""]
    out += [f"- `{k['ksi_id']}` {k['name']}: `{k['how_to_reproduce']}`" for k in g["ksis"]]
    out += ["", "---", "_Source of truth: the signed `assessor-guide.json`._"]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--records", default=str(_frr.DEFAULT_PATH))
    ap.add_argument("--catalog", default=str(REPO / "infrastructure" / "schemas" / "ksi-catalog.json"))
    ap.add_argument("--freshness", default=str(REPO / "infrastructure" / "schemas" / "freshness-config.json"))
    ap.add_argument("--commit", default=None)
    ap.add_argument("--output", default="assessor-guide.json")
    ap.add_argument("--md-output", default="assessor-guide.md")
    a = ap.parse_args(argv)
    records = _frr.load(a.records)
    fresh = {x["path"]: x for x in _freshness.load_freshness_config(a.freshness)["artifacts"]}
    na = _ksi_applicability.not_applicable(_ksi_applicability.load(catalog=a.catalog))
    guide = build(records, _rules.applicable_provider_rules(), json.loads(Path(a.catalog).read_text()), fresh,
                  datetime.now(timezone.utc), a.commit, na)
    Path(a.output).write_text(json.dumps(guide, indent=2) + "\n")
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(guide) + "\n")
    print(f"assessor-guide: {guide['summary']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
