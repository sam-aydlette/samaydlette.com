#!/usr/bin/env python3
# =============================================================================
# CERTIFICATION OVERVIEW PACKAGE BUILDER  (CR26 CDS)
# =============================================================================
# CR26 Certification Data Sharing (CDS) requires a publicly-shared, machine- and
# human-readable certification-overview package (CDS-CSO-PUB) carrying fifteen
# fields, a detailed service list with security categories (CDS-CSO-SVC), and a
# FedRAMP ID in all certification data (CDS-CSO-FID; a placeholder until assigned
# for an unsponsored system). This generator assembles the package from operator-
# declared editorial values (data/cds/offering.json), the authoritative system
# categorization (data/system-profile.json), and the canonical inventory's
# signal_id, and emits JSON + human-readable markdown (consistency between the
# two is the CDS-CSO-CBF automation requirement).
#
#   build-cds-overview.py --offering ../data/cds/offering.json \
#       --profile ../data/system-profile.json --ksi-signal ksi-signal.json
# =============================================================================

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

QUARTER_DAYS = 91


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offering", default="../data/cds/offering.json")
    ap.add_argument("--profile", default="../data/system-profile.json")
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--output", default="certification-overview-package.json")
    ap.add_argument("--md-output", default="certification-overview-package.md")
    a = ap.parse_args()

    now = datetime.now(timezone.utc)
    off = json.loads(Path(a.offering).read_text())
    prof = json.loads(Path(a.profile).read_text())
    signal_id = None
    if Path(a.ksi_signal).exists():
        signal_id = json.loads(Path(a.ksi_signal).read_text()).get("signal_id")
    else:
        print(f"::warning::ksi-signal not found at {a.ksi_signal}", file=sys.stderr)
    next_ocr = (now + timedelta(days=QUARTER_DAYS)).date().isoformat()

    pkg = {
        "package_type": "certification-overview-package",
        "schema": "fedramp-certification-overview-package-schema-2026-06-24.json",
        "emitted_at": now.isoformat(),
        "ksi_signal_id": signal_id,
        # The 15 CDS-CSO-PUB fields:
        "fedramp_id": off["fedramp_id"],                                       # 1 (CDS-CSO-FID)
        "service_model": off["service_model"],                                # 2
        "deployment_model": off["deployment_model"],                          # 3
        "business_category": off["business_category"],                        # 4
        "uei": off["uei"],                                                    # 5
        "sales_contact": off["sales_contact"],                                # 6
        "security_contact": off["security_contact"],                          # 7
        "product_website": off["product_website"],                            # 8
        "logo_url": off["logo_url"],                                          # 9
        "service_description": off["service_description"],                    # 10
        "services": off["services"],                                          # 11 (CDS-CSO-SVC)
        "secure_configuration_guidance_url": off["secure_configuration_guidance_url"],  # 12
        "documentation_overview_url": off["documentation_overview_url"],     # 13
        "next_ongoing_certification_report_date": next_ocr,                  # 14 (CCM-OCR-NRD)
        "current_independent_assessment_service": off["current_independent_assessment_service"],  # 15
        # Authoritative categorization (single source of truth).
        "class": prof.get("fedramp_class"),
        "impact_level": prof.get("impact_level"),
        "impact_level_canonical": prof.get("impact_level_canonical"),
        # Honest residuals for the trust-center subset (no sponsor).
        "trust_center_status": (
            "N/A absent a consuming agency. CDS-TRC-* (FedRAMP-compatible trust center, "
            "programmatic access, access logging, agency-access inventory) and CDS-UTC-* "
            "presuppose authorized agency consumers; with none, those are not exercised. "
            "All certification data here is instead shared fully publicly under CDS-CSO-PUB."),
    }
    Path(a.output).write_text(json.dumps(pkg, indent=2) + "\n")
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(pkg) + "\n")
    print(f"certification-overview-package: {len(pkg['services'])} services; "
          f"FedRAMP ID {pkg['fedramp_id'][:24]}...; next OCR {next_ocr}")
    return 0


def render_markdown(p):
    out = ["# Certification Overview Package", ""]
    out.append(f"- **Class:** {p['class']} | **Impact:** {p['impact_level_canonical']}")
    out.append(f"- **FedRAMP ID:** {p['fedramp_id']}")
    out.append(f"- **UEI:** {p['uei']}")
    out.append(f"- **Service / Deployment model:** {p['service_model']} / {p['deployment_model']}")
    out.append(f"- **Business category:** {p['business_category']}")
    out.append(f"- **Product website:** {p['product_website']}")
    sc = p["security_contact"]
    out.append(f"- **Security contact:** {sc.get('name')} ({sc.get('email')})")
    out.append(f"- **Sales contact:** {p['sales_contact'].get('name')} ({p['sales_contact'].get('url')})")
    out.append(f"- **Secure Configuration Guidance:** {p['secure_configuration_guidance_url']}")
    out.append(f"- **Documentation overview:** {p['documentation_overview_url']}")
    out.append(f"- **Independent assessment service:** {p['current_independent_assessment_service']}")
    out.append(f"- **Next Ongoing Certification Report:** {p['next_ongoing_certification_report_date']}")
    out.append(f"- **Bound to inventory signal:** `{p['ksi_signal_id']}`")
    out += ["", "## Service description", "", p["service_description"]]
    out += ["", "## Services (CDS-CSO-SVC)", "",
            "| Service | Security category | In MAS scope | Description |",
            "|---|---|---|---|"]
    for s in p["services"]:
        out.append("| {n} | {c} | {m} | {d} |".format(
            n=s.get("name", ""), c=s.get("security_category", ""),
            m="yes" if s.get("in_mas_scope") else "no",
            d=(s.get("description", "") or "").replace("|", "\\|")))
    out += ["", "## Trust-center status", "", p["trust_center_status"]]
    out += ["", "---", "_Source of truth: the signed `certification-overview-package.json` "
            "(CDS-CSO-PUB / SVC / FID)._"]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
