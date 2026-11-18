#!/usr/bin/env python3
# =============================================================================
# CERTIFICATION PACKAGE OVERVIEW BUILDER  (CR26 CPO, FedRAMP's 2026-06-24 schema)
# =============================================================================
# CPO-CSO-OVR: the overview of the one offering, in JSON and Markdown. It is
# written in FedRAMP's Certification Package Overview schema and validated
# against the vendored copy first; a CPO that fails is never written, so it is
# never signed or published.
#
# It also carries the public information (CDS-CSO-PUB) and the service list
# (CDS-CSO-SVC) that scripts/build-cds-overview.py used to publish in a separate
# file, so that information has one source and one file.
#
#   serviceIdentification   provider, service, FedRAMP ID, website, logo. The
#                           FedRAMP ID is FedRAMP's fallback (the provider name
#                           and acronym), suffixed so nobody mistakes it for an
#                           assigned ID. No UEI: the schema says to leave it
#                           out when there is none.
#   serviceProperties       service and deployment model, business category,
#                           trust center, secure configuration guidance, and the
#                           package's files as repositories
#   contactInformation      security and sales; never an email address
#   certifiedServices       each service, with its security category and
#                           whether it is in the Minimum Assessment Scope
#   metadata                accountable official, version, last update and its
#                           source (CPO-CSO-MTD)
#
# The fields this repo's other tools read stay at the top level, beside the
# schema's sections (the schema allows extra fields): ksi_signal_id (the
# inventory binding: reconciliation (e) and verify-published), impact_level
# (reconciliation (d)) and metadata.last_updated (the freshness window).
#
#   build-cpo.py --offering ../data/cds/offering.json --profile ../data/system-profile.json \
#       --ksi-signal ksi-signal.json
# =============================================================================

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fedramp_schema as fs  # noqa: E402
import _ocr_calendar  # noqa: E402
from _common import commit as _commit, run_url as _run_url  # noqa: E402

BASE = "https://samaydlette.com/.well-known/"
TRUST_CENTER = "https://samaydlette.com/trust/index.html"
BOUNDARY_PAGE = "https://samaydlette.com/research/authorization-boundary.html"

# The certification package's files under /.well-known/: (file, repository types, description).
PACKAGE = [
    ("security-decision-record.json", ["Security Decision Record"],
     "Every applicable FedRAMP rule and KSI with its status, and the Rev5 control projection "
     "(with this overview, the CR26 replacement for the System Security Plan). Signed."),
    ("ksi-signal.json", ["Key Security Indicators"],
     "The canonical inventory and per-KSI results that every other file is bound to. Signed."),
    ("vdr-report.json", ["Vulnerability Detection and Response"],
     "Vulnerability detection and response report. Signed."),
    ("ongoing-certification-report.json", ["Ongoing Certification Report"],
     "Ongoing Certification Report (CCM). Signed."),
    ("availability.json", ["Availability"], "Availability feed. Signed."),
    ("policy-index.json", ["Policies and Procedures"], "Policy and procedure index (CDS-CSO-IRP). Signed."),
]

NO_INDEPENDENT_ASSESSMENT = ("None performed. Independent assessment is Impractical here: one-person, no-budget. "
                             "Provider-side verification and validation are in the Security Decision Record.")


def _fail(msg):
    raise SystemExit(f"::error::CPO: {msg} (fail-closed)")


def _repo(types, url, desc):
    return {"repositoryType": types, "url": url, "repositoryDescription": desc, "authenticationRequired": False}


# --- the schema's sections -------------------------------------------------------------

def service_identification(off):
    return {"providerName": off["provider_name"], "serviceName": off["service_name"],
            "serviceAcronym": off["service_acronym"], "serviceDescription": off["service_description"],
            "certificationType": "20x",
            "fedRampPackageId": off["fedramp_id"],
            "website": off["product_website"], "logo": off["logo_url"]}


def service_properties(off, next_report):
    return {"serviceType": off["service_model"], "deploymentModel": off["deployment_model"],
            "nextOngoingCertificationReportDate": next_report.isoformat(),  # CCM-OCR-NRD
            "businessCategory": off["business_category"],
            "trustCenter": _repo(["Trust Center"], TRUST_CENTER,
                                 "The trust center: the security state this package reports, drawn from the "
                                 "signed files under /.well-known/. Public; no access request is needed."),
            "secureConfigurationGuidance": _repo(["Secure Configuration Guidance"],
                                                 off["secure_configuration_guidance_url"],
                                                 "The Secure Configuration Guide."),
            "additionalRepositories": [_repo(t, BASE + f, d) for f, t, d in PACKAGE]}


def contacts(off):
    """Security and Sales, which the schema requires. Neither is an email
    address, so neither goes in the email field."""
    return [{"contactType": "Security", "contactName": off["security_contact"]["name"]},
            {"contactType": "Sales", "contactName": off["sales_contact"]["name"]}]


def certified_services(off, prof):
    """CDS-CSO-SVC: every service in the offering, with its security category and
    whether it is in the Minimum Assessment Scope. A service's category must name
    the system's own impact level."""
    services = off.get("services") or []
    if not services:
        _fail("the offering lists no services (CDS-CSO-SVC)")
    out = []
    for s in services:
        cat = s.get("security_category")
        if not isinstance(cat, str) or prof["impact_level"] not in cat:
            _fail(f"service {s.get('name')!r}: security category {cat!r} does not name the system's "
                  f"impact level {prof['impact_level']!r}")
        if not isinstance(s.get("in_mas_scope"), bool):
            _fail(f"service {s.get('name')!r}: in_mas_scope must be true or false")
        out.append({"serviceName": s["name"], "serviceDescription": s["description"],
                    "securityCategory": cat, "inMinimumAssessmentScope": s["in_mas_scope"]})
    return out


# --- this repo's fields ------------------------------------------------------------------

def metadata(off, now, commit, run_url):
    """CPO-CSO-MTD: the accountable official, version, date and time of the last
    update, and its source."""
    ao = off.get("accountable_official") or {}
    if not all(isinstance(ao.get(k), str) and ao[k] for k in ("name", "title", "contact")):
        _fail("the accountable official needs a name, title and contact (CPO-CSO-MTD)")
    if not commit:
        _fail("no commit to version the package with (CPO-CSO-MTD)")
    return {"accountable_official": {k: ao[k] for k in ("name", "title", "contact")},
            "version": commit,
            "last_updated": now.isoformat(),
            "source_of_update": f"scripts/build-cpo.py at commit {commit}, "
                                + (f"deploy run {run_url}" if run_url else "local build")}


def build(off, prof, signal, now, commit, run_url, cal=None, issued=()):
    cal = cal or _ocr_calendar.load()
    next_report, overdue = _ocr_calendar.next_report(cal, issued, now.date())
    return {
        "$schema": fs.stamp("cpo"),
        "serviceIdentification": service_identification(off),
        "serviceProperties": service_properties(off, next_report),
        "contactInformation": contacts(off),
        "certifiedServices": certified_services(off, prof),
        "metadata": metadata(off, now, commit, run_url),
        "fedramp_id": off["fedramp_id"],          # CDS-CSO-FID: the same ID, where every report carries it
        "ksi_signal_id": signal.get("signal_id"),
        "class": prof.get("fedramp_class"),
        "impact_level": prof.get("impact_level"),
        "minimum_assessment_scope": {
            "component_count": len(signal.get("components", [])),
            "authorization_boundary": BOUNDARY_PAGE,
        },
        "cryptographic_modules": off.get("cryptographic_modules", []),
        "independent_assessment": NO_INDEPENDENT_ASSESSMENT,
        "next_ongoing_certification_report_overdue": overdue,
        "next_quarterly_review_date": _ocr_calendar.next_review(cal, issued, now.date()).isoformat(),  # CCM-QTR-NRD
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--offering", default="../data/cds/offering.json")
    ap.add_argument("--profile", default="../data/system-profile.json")
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--output", default="certification-package-overview.json")
    ap.add_argument("--md-output", default="certification-package-overview.md")
    a = ap.parse_args(argv)

    off = json.loads(Path(a.offering).read_text())
    prof = json.loads(Path(a.profile).read_text())
    if not Path(a.ksi_signal).exists():
        _fail(f"{a.ksi_signal} not found: the package must be bound to the inventory")
    signal = json.loads(Path(a.ksi_signal).read_text())

    cpo = build(off, prof, signal, datetime.now(timezone.utc), _commit(), _run_url())
    fs.write_validated(cpo, "cpo", a.output)
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(cpo) + "\n")
    print(f"certification-package-overview: {len(cpo['certifiedServices'])} services; "
          f"{len(cpo['serviceProperties']['additionalRepositories'])} package files; "
          f"{cpo['minimum_assessment_scope']['component_count']} components in scope")
    return 0


def render_markdown(c):
    si, sp, md = c["serviceIdentification"], c["serviceProperties"], c["metadata"]
    ao = md["accountable_official"]
    contact = {x["contactType"]: x["contactName"] for x in c["contactInformation"]}
    out = ["# Certification Package Overview", "",
           f"**{si['serviceName']}** ({si['serviceAcronym']}), provided by {si['providerName']}.", "",
           si["serviceDescription"], "",
           f"- **FedRAMP ID:** {si['fedRampPackageId']}",
           f"- **Certification type:** {si['certificationType']} | **Class:** {c['class']} | "
           f"**Impact level:** {c['impact_level']}",
           f"- **Service model:** {', '.join(sp['serviceType'])} | **Deployment model:** {sp['deploymentModel']}",
           f"- **Business category:** {', '.join(sp['businessCategory'])}",
           f"- **Website:** {si['website']} | **Logo:** {si['logo']}",
           f"- **Security contact:** {contact['Security']}",
           f"- **Sales contact:** {contact['Sales']}",
           f"- **Trust center:** {sp['trustCenter']['url']}",
           f"- **Secure Configuration Guidance:** {sp['secureConfigurationGuidance']['url']}",
           f"- **Independent assessment:** {c['independent_assessment']}",
           f"- **Next Ongoing Certification Report:** {sp['nextOngoingCertificationReportDate']}"
           + (" (overdue)" if c["next_ongoing_certification_report_overdue"] else ""),
           f"- **Next Quarterly Review:** {c['next_quarterly_review_date']}", "",
           "## Metadata", "",
           f"- **Accountable official:** {ao['name']}, {ao['title']} ({ao['contact']})",
           f"- **Version:** `{md['version']}`",
           f"- **Last updated:** {md['last_updated']}",
           f"- **Source of update:** {md['source_of_update']}",
           f"- **Bound to inventory signal:** `{c['ksi_signal_id']}`", "",
           "## Services", "",
           "| Service | Security category | In the Minimum Assessment Scope | Description |",
           "|---|---|---|---|"]
    for s in c["certifiedServices"]:
        out.append("| {n} | {cat} | {m} | {d} |".format(
            n=s["serviceName"], cat=s["securityCategory"], m="yes" if s["inMinimumAssessmentScope"] else "no",
            d=s["serviceDescription"].replace("|", "\\|")))
    mas = c["minimum_assessment_scope"]
    out += ["", "## Minimum Assessment Scope", "",
            f"- Components in scope: **{mas['component_count']}**",
            f"- Authorization boundary: {mas['authorization_boundary']}", "",
            "## Cryptographic modules (CMU-CSO-CMD)", "",
            "| Module | Validation | Role |", "|---|---|---|"]
    for m in c["cryptographic_modules"]:
        out.append(f"| {m.get('module', '')} | {m.get('validation', '')} | {m.get('role', '')} |")
    out += ["", "## Package files", "", "| File | Description |", "|---|---|"]
    for r in sp["additionalRepositories"]:
        out.append(f"| [`{r['url'].rsplit('/', 1)[-1]}`]({r['url']}) | {r['repositoryDescription']} |")
    out += ["", "---", "_Source of truth: the signed `certification-package-overview.json` (CPO-CSO-OVR)._"]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
