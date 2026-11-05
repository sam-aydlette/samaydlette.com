#!/usr/bin/env python3
# =============================================================================
# CERTIFICATION PACKAGE OVERVIEW BUILDER  (CR26 CPO, FedRAMP's 2026-06-24 schema)
# =============================================================================
# CPO-CSO-OVR: the overview of the offering, in both JSON and human-readable
# form, with what CPO-CSO-MTD, CDS-CSO-PUB and CDS-CSO-SVC require. It folds in
# what scripts/build-cds-overview.py used to publish separately (the CDS
# certification-overview package), so the public information has one source.
#
#   serviceIdentification   provider, service, FedRAMP ID (FedRAMP's fallback:
#                           the provider name and acronym, marked as not real),
#                           a simulated UEI, website, logo (CDS-CSO-PUB, FID)
#   serviceProperties       service and deployment model, business category,
#                           the package's repositories, and the next report date
#                           from the fixed CCM calendar (CCM-OCR-NRD)
#   contactInformation      security, sales and accountable official; never an
#                           email address (they point to security.txt)
#   certifiedServices       each service, with its own security category
#                           under providerExtensions.services (CDS-CSO-SVC)
#   metadata                version (semver on a content hash), lastUpdated,
#                           updateSource, accountable official (CPO-CSO-MTD)
#
# Simulated values are flagged under providerExtensions.simulated, naming the
# outside party they stand in for. Each top-level section is one small function,
# so a field can be added without touching the others. Validated against the
# vendored schema before it is written; nothing that fails is written.
#
#   build-cpo.py --offering ../data/cds/offering.json --profile ../data/system-profile.json \
#       --ksi-signal ksi-signal.json --previous-cpo previous-cpo.json
# =============================================================================

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ccm  # noqa: E402
import _fedramp_schema as fs  # noqa: E402
import _offering  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
BOUNDARY = REPO / "docs" / "boundary" / "boundary-classification.json"
BASE = "https://samaydlette.com/.well-known/"
LEVELS = ("low", "moderate", "high")

# The certification package (FRC-CSO-PKG) as the deploy publishes it.
# (file, repository types, description)
PACKAGE = [
    ("security-decision-record.json", ["Security Decision Record"],
     "Every applicable FedRAMP rule, KSI and Rev5 Moderate control, with implementation, validation and "
     "assessment (SDR-CSO-FRR; replaces the SSP)."),
    ("ongoing-certification-report.json", ["Ongoing Certification Report"],
     "The Ongoing Certification Report as it stands since the latest issue (CCM-OCR-AVL)."),
    ("ocr-issues.json", ["Ongoing Certification Report", "Historical Certification Data"],
     "Every issued Ongoing Certification Report, frozen and signed, with the snapshot of the certification "
     "data taken at each issue (CDS-CSO-HAD)."),
    ("quarterly-review.ics", ["Quarterly Review"], "Calendar file for the Quarterly Reviews (CCM-QTR-REG)."),
    ("vdr-detail-report.json", ["Vulnerability Detail Report"], "Vulnerability detail (VER-RPT-VDT)."),
    ("vdr-accepted-vulnerabilities.json", ["Accepted Vulnerability Info"], "Accepted vulnerabilities (VER-RPT-AVI)."),
    ("vdr-history.json", ["Historical Vulnerability Activity"], "Vulnerability history (VER-TFR-MRH)."),
    ("ksi-signal.json", ["Key Security Indicators"], "The canonical inventory and per-KSI results (MAS-CSO-IIR)."),
    ("boundary-map.json", ["Minimum Assessment Scope"], "The generated authorization boundary map and data flows."),
    ("policy-index.json", ["Policies and Procedures"], "Policy and procedure index (CDS-CSO-IRP)."),
    ("availability.json", ["Availability"], "Availability feed."),
    ("fedramp-certification-reports.json", ["FedRAMP Certification Reports"],
     "FedRAMP Certification Reports received, published unmodified (CDS-CSO-FRC). Simulated: see the file."),
    ("package-submission-log.json", ["Package Submission"],
     "Log of each submission of this package to FedRAMP (FRC-CSO-PKG). Simulated: nothing is sent."),
]


def _fail(msg):
    raise SystemExit(f"::error::CPO: {msg} (fail-closed)")


# --- sections ------------------------------------------------------------------------

def service_identification(off):
    return {"providerName": off["provider_name"], "serviceName": off["service_name"],
            "serviceAcronym": off["service_acronym"], "serviceDescription": off["service_description"],
            "certificationType": "20x",  # FRC-CSO-POP: one program, 20x
            "fedRampPackageId": off["fedramp_id"], "ueiNumber": off["uei"],
            "website": off["product_website"], "logo": off["logo_url"]}


def repositories():
    return [{"repositoryType": types, "url": BASE + f, "repositoryDescription": desc,
             "authenticationRequired": False} for f, types, desc in PACKAGE]


def service_properties(off, dates):
    return {"serviceType": off["service_model"], "deploymentModel": off["deployment_model"],
            "businessCategory": off["business_category"],
            "additionalRepositories": repositories(),
            "nextOngoingCertificationReportDate": dates["nextOngoingCertificationReportDate"]}


def contacts(off):
    """Security and Sales (the schema requires both), the accountable official,
    and the FedRAMP Security Inbox when the offering declares one. A contact
    that is not an email address is never put in the email field."""
    ao = off["accountable_official"]
    out = [{"contactType": "Security", "contactName": off["security_contact"]["name"]},
           {"contactType": "Sales", "contactName": off["sales_contact"]["name"]},
           {"contactType": "Accountable Official",
            "contactName": f"{ao['name']}, {ao['title']} (contact: {ao['contact']})"}]
    fsi = off.get("fedramp_security_inbox")
    if isinstance(fsi, dict):
        entry = {"contactType": "FedRAMP Security Inbox"}
        addr = fsi.get("address")
        if isinstance(addr, str) and fs._EMAIL_RE.match(addr) and "/" not in addr:
            entry["contactName"] = "FedRAMP Security Inbox"
            entry["contactEmail"] = addr
        else:
            entry["contactName"] = fsi.get("contact") or "FedRAMP Security Inbox"
        out.append(entry)
    return out


def certified_services(off):
    return [{"serviceName": s["name"], "serviceDescription": s["description"],
             **({"dateAvailable": s["date_available"]} if s.get("date_available") else {})}
            for s in off["services"]]


def services_detail(off, prof, groups):
    """CDS-CSO-SVC: each service's own FIPS 199 category (never above the
    system's), the boundary groups it is made of, and what is not included."""
    sysfips = prof.get("fips_199") or {}
    out = []
    for s in off["services"]:
        cat = s.get("security_category")
        if not isinstance(cat, dict):
            _fail(f"service {s.get('name')!r} has no per-service security category")
        for obj in ("confidentiality", "integrity", "availability"):
            v = cat.get(obj)
            if v not in LEVELS:
                _fail(f"service {s['name']!r}: {obj} {v!r} is not one of {LEVELS}")
            if sysfips.get(obj) in LEVELS and LEVELS.index(v) > LEVELS.index(sysfips[obj]):
                _fail(f"service {s['name']!r}: {obj} {v} exceeds the system's {sysfips[obj]}")
        unknown = sorted(set(s.get("boundary_groups") or []) - groups)
        if not s.get("boundary_groups") or unknown:
            _fail(f"service {s['name']!r}: boundary groups {unknown or 'none'} are not in the boundary classification")
        hw = max((cat[o] for o in ("confidentiality", "integrity", "availability")), key=LEVELS.index)
        out.append({"serviceName": s["name"], "securityCategory": {
            "confidentiality": cat["confidentiality"], "integrity": cat["integrity"],
            "availability": cat["availability"], "highWaterMark": hw, "rationale": cat.get("rationale", "")},
            "boundaryGroups": s["boundary_groups"], "inMinimumAssessmentScope": bool(s.get("in_mas_scope"))})
    return out


def simulated(off):
    """The values that stand in for an outside party, and which party."""
    return [{"field": "serviceIdentification.fedRampPackageId", "counterparty": "fedramp",
             "how": off["fedramp_id_simulated"]},
            {"field": "serviceIdentification.ueiNumber", "counterparty": "sam-gov", "how": off["uei_simulated"]}]


def provider_extensions(off, prof, signal, dates, groups):
    components = signal.get("components", []) if signal else []
    return {
        "fedRampId": off["fedramp_id"],
        "certification": "FedRAMP 20x, Program path, Class C",
        "class": prof.get("fedramp_class"),
        "impact_level": prof.get("impact_level"),
        "fips_199": prof.get("fips_199"),
        "ksi_signal_id": signal.get("signal_id"),
        "simulated": simulated(off),
        "services": services_detail(off, prof, groups),
        "notIncluded": off.get("not_included", []),
        "continuousMonitoring": dates,
        "minimumAssessmentScope": {
            "componentCount": len(components),
            "boundaryMap": BASE + "boundary-map.json",
            "authorizationBoundary": "https://samaydlette.com/research/authorization-boundary.html"},
        "cryptographicModules": off.get("cryptographic_modules", []),
        "independentAssessment": off.get("current_independent_assessment_service"),
        "documentationOverview": off.get("documentation_overview_url"),
    }


def build(off, prof, signal, cal, prev, now, groups):
    dates = _ccm.dates_summary(cal, now.date())
    ao = off["accountable_official"]
    doc = {
        "$schema": fs.stamp("cpo"),
        "serviceIdentification": service_identification(off),
        "serviceProperties": service_properties(off, dates),
        "contactInformation": contacts(off),
        "certifiedServices": certified_services(off),
        "metadata": {"accountableOfficial": {"name": ao["name"], "title": ao["title"], "contact": ao["contact"]}},
        "providerExtensions": provider_extensions(off, prof, signal, dates, groups),
    }
    return _offering.stamp_version(doc, prev, now, "Automated: scripts/build-cpo.py, from data/cds/offering.json, "
                                   "the system profile, the CCM calendar and the KSI signal")


def boundary_groups(path=BOUNDARY):
    return {g["key"] for g in json.loads(Path(path).read_text()).get("groups", [])}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--offering", default=str(_offering.OFFERING_PATH))
    ap.add_argument("--profile", default="../data/system-profile.json")
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--calendar", default=str(_ccm.CALENDAR_PATH))
    ap.add_argument("--previous-cpo", default=None)
    ap.add_argument("--output", default="certification-package-overview.json")
    ap.add_argument("--md-output", default="certification-package-overview.md")
    a = ap.parse_args(argv)

    now = datetime.now(timezone.utc)
    off = _offering.load(a.offering)
    prof = json.loads(Path(a.profile).read_text())
    if not Path(a.ksi_signal).exists():
        _fail(f"{a.ksi_signal} not found")
    signal = json.loads(Path(a.ksi_signal).read_text())
    prev = {}
    if a.previous_cpo and Path(a.previous_cpo).exists():
        try:
            prev = json.loads(Path(a.previous_cpo).read_text())
        except json.JSONDecodeError:
            prev = {}
    doc = build(off, prof, signal, _ccm.load(a.calendar, now.date()), prev, now, boundary_groups())
    fs.write_validated(doc, "cpo", a.output)
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(doc) + "\n")
    print(f"certification-package-overview {doc['metadata']['version']}: "
          f"{len(doc['certifiedServices'])} services; next report "
          f"{doc['serviceProperties']['nextOngoingCertificationReportDate']}")
    return 0


# --- human-readable view (CDS-CSO-CBF: same data as the JSON) -------------------------

def _cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(c):
    si, sp, m, pe = c["serviceIdentification"], c["serviceProperties"], c["metadata"], c["providerExtensions"]
    ao = m["accountableOfficial"]
    ccm = pe["continuousMonitoring"]
    out = ["# Certification Package Overview", "",
           f"_{pe['certification']}. With the Security Decision Record, the CR26 replacement for the System "
           "Security Plan._", "",
           f"- **Provider:** {si['providerName']} | **Service:** {si['serviceName']} ({si['serviceAcronym']})",
           f"- **FedRAMP ID:** {si['fedRampPackageId']} (simulated: no FedRAMP ID has been assigned)",
           f"- **UEI:** {si['ueiNumber']} (simulated: no SAM.gov registration)",
           f"- **Certification type:** {si['certificationType']} | **Class:** {pe['class']} | "
           f"**Impact:** {pe['impact_level']} (FIPS 199 high-water mark)",
           f"- **Service model:** {', '.join(sp['serviceType'])} | **Deployment model:** {sp['deploymentModel']}",
           f"- **Business category:** {', '.join(sp['businessCategory'])}",
           f"- **Website:** {si['website']} | **Logo:** {si['logo']}",
           f"- **Accountable official:** {ao['name']}, {ao['title']} ({ao['contact']})",
           f"- **Version:** {m['version']} | **Last updated:** {m['lastUpdated']}",
           f"- **Source:** {m['updateSource']}",
           f"- **Bound to inventory signal:** `{pe['ksi_signal_id']}`", "",
           "## Service description", "", si["serviceDescription"], "",
           "## Contacts", "", "| Type | Contact |", "|---|---|"]
    for ct in c["contactInformation"]:
        out.append(f"| {ct['contactType']} | {_cell(ct.get('contactEmail') or ct.get('contactName', ''))} |")
    out += ["", "## Continuous monitoring", "",
            f"- **Next Ongoing Certification Report:** {ccm['nextOngoingCertificationReportDate']}",
            f"- **Next Quarterly Review:** {ccm['nextQuarterlyReviewDate']} "
            f"({ccm['reviewBusinessDaysAfterIssue']} business days after the report)",
            f"- **Review calendar:** {ccm['quarterlyReviewCalendar']} | "
            f"**Registration:** {ccm['quarterlyReviewRegistration']}",
            f"- **Issued reports and snapshots:** {ccm['ongoingCertificationReportIssues']}",
            f"- **Issue dates:** {', '.join(ccm['issueDates'])}", "",
            "## Services (CDS-CSO-SVC)", "",
            "| Service | C / I / A | In scope | Description |", "|---|---|---|---|"]
    desc = {s["serviceName"]: s["serviceDescription"] for s in c["certifiedServices"]}
    for s in pe["services"]:
        cat = s["securityCategory"]
        out.append(f"| {_cell(s['serviceName'])} | {cat['confidentiality']} / {cat['integrity']} / "
                   f"{cat['availability']} | {'yes' if s['inMinimumAssessmentScope'] else 'no'} | "
                   f"{_cell(desc[s['serviceName']])} |")
    out += ["", "**Not included:**", ""] + [f"- {n['name']}: {n['why']}" for n in pe["notIncluded"]]
    out += ["", "## Simulated values", "",
            "This is a proof of concept. These values stand in for an outside party that does not exist here:", ""]
    out += [f"- `{s['field']}` ({s['counterparty']}): {s['how']}" for s in pe["simulated"]]
    out += ["", "## Package contents", "", "| Artifact | Type | Description |", "|---|---|---|"]
    for r in sp["additionalRepositories"]:
        out.append(f"| [{r['url'].rsplit('/', 1)[-1]}]({r['url']}) | {', '.join(r['repositoryType'])} | "
                   f"{_cell(r['repositoryDescription'])} |")
    out += ["", "## Cryptographic modules (CMU-CSO-CMD)", "", "| Module | Validation | Role |", "|---|---|---|"]
    for mod in pe["cryptographicModules"]:
        out.append(f"| {_cell(mod.get('module', ''))} | {_cell(mod.get('validation', ''))} | "
                   f"{_cell(mod.get('role', ''))} |")
    out += ["", "## Independent assessment", "", str(pe["independentAssessment"]), "",
            "---", "_Source of truth: the signed `certification-package-overview.json` (CPO-CSO-OVR)._"]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
