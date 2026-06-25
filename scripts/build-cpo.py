#!/usr/bin/env python3
# =============================================================================
# CERTIFICATION PACKAGE OVERVIEW BUILDER  (CR26 CPO)
# =============================================================================
# CR26 CPO-CSO-OVR (MUST) requires a Certification Package Overview, human- and
# machine-readable, that rolls up the CDS public information, the Minimum
# Assessment Scope, the cryptographic-module use (CMU-CSO-CMD), and the
# independent-assessment results (IVV-CSO-ICP). CPO-CSO-MTD requires the name,
# title, and contact of the accountable official plus version/timestamp/source.
# CPO-CSX-CPM (Class C) requires the package be maintained at least every two
# weeks — trivially met by the per-deploy pipeline. Together with the Security
# Decision Record, the CPO is CR26's replacement for the base System Security
# Plan; the OSCAL SSP is still generated as the Rev5-paradigm artifact.
#
# This is an overview/manifest: it points at the constituent artifacts the
# pipeline already publishes and summarizes scope, crypto, and assessment status.
#
#   build-cpo.py --offering ../data/cds/offering.json --profile ../data/system-profile.json \
#       --overview certification-overview-package.json --ksi-signal ksi-signal.json
# =============================================================================

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# The certification-package artifacts the pipeline publishes under /.well-known/.
# (artifact filename, type, signed)
PACKAGE_CONTENTS = [
    ("security-decision-record.json", "Security Decision Record (SDR — 20x SSP replacement)", True),
    ("oscal-ssp.json", "OSCAL Rev 5 System Security Plan (Rev5-paradigm)", True),
    ("oscal-poam.json", "OSCAL Plan of Action and Milestones", True),
    ("ksi-signal.json", "FedRAMP 20x KSI signal (canonical inventory)", True),
    ("vdr-report.json", "Vulnerability Detection and Response report", True),
    ("ongoing-certification-report.json", "Ongoing Certification Report (CCM)", True),
    ("certification-overview-package.json", "CDS certification-overview package", True),
    ("availability.json", "Availability feed (CDS-CSO-AVR)", True),
    ("policy-index.json", "Policy and procedure index (CDS-CSO-IRP)", True),
    ("iiw.csv", "FedRAMP Integrated Inventory Workbook (Appendix M)", True),
]
BASE = "https://samaydlette.com/.well-known/"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offering", default="../data/cds/offering.json")
    ap.add_argument("--profile", default="../data/system-profile.json")
    ap.add_argument("--overview", default="certification-overview-package.json")
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--output", default="certification-package-overview.json")
    ap.add_argument("--md-output", default="certification-package-overview.md")
    a = ap.parse_args()

    now = datetime.now(timezone.utc)
    off = json.loads(Path(a.offering).read_text())
    prof = json.loads(Path(a.profile).read_text())
    overview = json.loads(Path(a.overview).read_text()) if Path(a.overview).exists() else {}
    signal = json.loads(Path(a.ksi_signal).read_text()) if Path(a.ksi_signal).exists() else {}
    components = signal.get("components", []) if signal else []

    cpo = {
        "package_type": "certification-package-overview",
        "schema": "fedramp-certification-package-overview-schema-2026-06-24.json",
        "note": "With the Security Decision Record, the CR26 replacement for the base System "
                "Security Plan. The OSCAL Rev5 SSP is still generated (paradigm-agnostic).",
        # CPO-CSO-MTD
        "accountable_official": off.get("accountable_official"),
        "metadata": {
            "version": "live (regenerated each deploy)",
            "last_updated": now.isoformat(),
            "source_of_update": "scripts/build-cpo.py",
        },
        "maintenance_cadence": "per-deploy — exceeds the CPO-CSX-CPM Class C 2-week minimum",
        "class": prof.get("fedramp_class"),
        "impact_level": prof.get("impact_level"),
        "impact_level_canonical": prof.get("impact_level_canonical"),
        "ksi_signal_id": signal.get("signal_id"),
        # CPO-CSO-OVR rollup:
        "certification_data": {                                  # CDS public info
            "fedramp_id": overview.get("fedramp_id") or off.get("fedramp_id"),
            "service_description": off.get("service_description"),
            "service_model": off.get("service_model"),
            "deployment_model": off.get("deployment_model"),
            "security_contact": off.get("security_contact"),
            "overview_package": BASE + "certification-overview-package.json",
        },
        "minimum_assessment_scope": {                            # MAS
            "component_count": len(components),
            "services": off.get("services"),
            "authorization_boundary": "https://samaydlette.com/research/authorization-boundary.html",
            "reference": "MAS-CSO-IIR / MAS-CSO-FLO / MAS-CSO-TPR; MAS-CSO-MDI N/A (no federal customer data)",
        },
        "cryptographic_modules": {                               # CMU-CSO-CMD
            "modules": off.get("cryptographic_modules", []),
            "reference": "CMU-CSO-CMD; full narrative in the authorization-boundary FIPS section",
        },
        "independent_assessment": {                              # IVV-CSO-ICP
            "status": "N/A — no FedRAMP Recognized independent assessment service engaged "
                      "(self-attested PoC). Provider-side verification and validation are in "
                      "the Security Decision Record; the independent half is unmet by design.",
            "current_service": off.get("current_independent_assessment_service"),
        },
        "package_contents": [
            {"artifact": fn, "description": desc, "url": BASE + fn, "signed": signed}
            for fn, desc, signed in PACKAGE_CONTENTS
        ],
    }
    Path(a.output).write_text(json.dumps(cpo, indent=2) + "\n")
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(cpo) + "\n")
    ao = cpo["accountable_official"] or {}
    print(f"certification-package-overview: official {ao.get('name')}; "
          f"{len(cpo['package_contents'])} package artifacts; "
          f"{cpo['minimum_assessment_scope']['component_count']} components in scope")
    return 0


def render_markdown(c):
    ao = c["accountable_official"] or {}
    out = ["# Certification Package Overview", "",
           f"_{c['note']}_", "",
           f"- **Accountable official:** {ao.get('name')}, {ao.get('title')} ({ao.get('contact')})",
           f"- **Class:** {c['class']} | **Impact:** {c['impact_level_canonical']}",
           f"- **Version:** {c['metadata']['version']} | **Last updated:** {c['metadata']['last_updated']}",
           f"- **Maintenance:** {c['maintenance_cadence']}",
           f"- **Bound to inventory signal:** `{c['ksi_signal_id']}`", ""]
    mas = c["minimum_assessment_scope"]
    out += ["## Minimum Assessment Scope", "",
            f"- Components in scope: **{mas['component_count']}**",
            f"- Authorization boundary: {mas['authorization_boundary']}",
            f"- {mas['reference']}", ""]
    out += ["## Cryptographic modules (CMU-CSO-CMD)", "",
            "| Module | Validation | Role |", "|---|---|---|"]
    for m in c["cryptographic_modules"]["modules"]:
        out.append("| {mod} | {val} | {role} |".format(
            mod=m.get("module", ""), val=m.get("validation", ""), role=m.get("role", "")))
    out += ["", "## Independent assessment (IVV-CSO-ICP)", "", c["independent_assessment"]["status"], ""]
    out += ["## Package contents", "", "| Artifact | Description | Signed |", "|---|---|---|"]
    for p in c["package_contents"]:
        out.append("| [`{a}`]({u}) | {d} | {s} |".format(
            a=p["artifact"], u=p["url"], d=p["description"], s="yes" if p["signed"] else "no"))
    out += ["", "---", "_Source of truth: the signed `certification-package-overview.json` (CPO-CSO-OVR)._"]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
