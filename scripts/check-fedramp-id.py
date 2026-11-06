#!/usr/bin/env python3
"""Deploy gate: every FedRAMP report this build publishes carries the offering's
FedRAMP ID (CDS-CSO-FID).

For each file named: a report in a FedRAMP schema ($schema under
https://fedramp.gov/schemas/) must carry providerExtensions.fedRampId equal to
data/cds/offering.json's fedramp_id, and the CPO also in
serviceIdentification.fedRampPackageId; any other JSON (the issue index, logs,
snapshot manifests, the trust-center data) must carry the same value at top
level, `fedRampId`. A file named here without one fails, as does a file that
cannot be read. Exit 0 pass, 1 fail.

  check-fedramp-id.py             # every file in REPORTS, in the current directory
  check-fedramp-id.py FILE...     # these files

REPORTS is the one list of what the deploy checks: a group that publishes a
FedRAMP report adds its file here, one line.
"""

import fnmatch
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _offering  # noqa: E402

# Every FedRAMP report the deploy publishes, by built file name. Add a line per report.
# A name with "*" is a glob over the build directory (each match is checked).
REPORTS = (
    "certification-package-overview.json",
    "security-decision-record.json",
    "ongoing-certification-report.json",
    # Vulnerability detection and response (group 4): the VDR report and its
    # trend ledger at top level; FedRAMP's VDT, AVI and history reports under
    # providerExtensions; the monthly activity report and non-machine V&V status.
    "vdr-report.json",
    "vdr-trend.json",
    "vdr-detail-report.json",
    "vdr-accepted-vulnerabilities.json",
    "vdr-history.json",
    "vdr-monthly.json",
    "vdr-non-machine-vv.json",
    # The canonical inventory (the runtime emitter copies the ID from it).
    "ksi-signal.json",
    # Certification cycle (group 2): the FedRAMP Certification Reports index and
    # the simulated package submission log.
    "fedramp-certification-reports.json",
    "package-submission-log.json",
    # Notifications (group 3): the SCN index (each notification also under its
    # providerExtensions), the evaluation log, the incident log, every
    # Initial/Ongoing/Final report (FedRAMP's incident schema), the simulated
    # deliveries and the simulated FedRAMP Security Inbox run.
    "significant-change-notifications.json",
    "scn-evaluations.json",
    "incident-reports.json",
    "incident-deliveries.json",
    "incident-INC-*.json",
    "fedramp-inbox-simulation.json",
    # Trust center, scope and assessor (group 5): site files, top-level fedRampId.
    "trust-center.json",
    "trust-manifest.json",
    "availability.json",
    "policy-index.json",
    "assessor-guide.json",
    "simulated-assessment.json",
    "agency-access-exercise.json",
    "frr-evidence.json",
    "minimum-assessment-scope.json",
    "secure-configuration-guide.json",
    "security-settings.json",
    "access-summary.json",
    "boundary-map.json",
    "reconcile-report.json",
    "conformance-results.json",
    # The independent monitor's feed as this deploy read it (availability-status.json
    # from the availability-status branch; it is built by scripts/availability-probe.py).
    "availability-probe.json",
)

# Published JSON that this deploy step does not check, and why. Every
# freshness-governed JSON artifact is in REPORTS or here
# (tests/test_fedramp_id_trust.py holds that).
EXEMPT = {
    "ksi-signal-runtime.json": "Written and KMS-signed by the runtime emitter Lambda after the deploy, not by a "
                               "deploy builder; it copies fedRampId from the deploy's KSI signal "
                               "(infrastructure/lambda/index.js), which this gate checks.",
    "vdr-status.json": "The nightly's unsigned status beacon, written by evidence-nightly.yml whatever the run's "
                       "outcome; it is stamped there (null only if the offering cannot be read).",
    "ocr-issues.json": "Issued by package-maintenance.yml (scripts/issue-ocr.py), which runs this gate over it "
                       "and the frozen reports before publishing.",
    "quarterly-reviews.json": "Written by package-maintenance.yml (scripts/hold-quarterly-review.py), which runs this "
                              "gate over it and each new quarterly-review-<date>.json before publishing.",
    "boundary-corroboration.json": "The independent corroboration (RAMPART on TAP), committed by the operator and "
                                   "published exactly as the corroborating tool wrote it; stamping it would alter "
                                   "another party's record. The boundary map it corroborates carries the ID.",
}
FEDRAMP_SCHEMAS = _offering.FEDRAMP_SCHEMA_BASES


def problems(name, doc, fid):
    out = []
    if not isinstance(doc, dict):
        return [f"{name}: not a JSON object"]
    if str(doc.get("$schema", "")).startswith(FEDRAMP_SCHEMAS):
        if (doc.get("providerExtensions") or {}).get("fedRampId") != fid:
            out.append(f"{name}: providerExtensions.fedRampId is missing or not the offering's FedRAMP ID")
        si = doc.get("serviceIdentification")
        if si is not None and si.get("fedRampPackageId") != fid:
            out.append(f"{name}: serviceIdentification.fedRampPackageId is not the offering's FedRAMP ID")
    elif doc.get("fedRampId") != fid:
        out.append(f"{name}: top-level fedRampId is missing or not the offering's FedRAMP ID")
    return out


def uncovered(artifact_paths, reports=REPORTS, exempt=EXEMPT):
    """Published JSON (freshness-config paths, e.g. ".well-known/x.json") that
    neither REPORTS nor EXEMPT accounts for, plus any exemption without a
    reason or also listed in REPORTS."""
    out = []
    for path in artifact_paths:
        name = path.rsplit("/", 1)[-1]
        if not name.endswith(".json"):
            continue
        listed = any(fnmatch.fnmatchcase(name, r) for r in reports)
        if listed and name in exempt:
            out.append(f"{name} is both checked and exempt")
        elif not listed and not str(exempt.get(name) or "").strip():
            out.append(f"{name} is published but neither checked for the FedRAMP ID nor exempt with a reason")
    return out


def _expand(names, root="."):
    out = []
    for n in names:
        out += sorted(str(p) for p in Path(root).glob(n)) if "*" in n else [n]
    return out


def main(argv=None):
    files = (sys.argv[1:] if argv is None else argv) or _expand(REPORTS)
    fid = _offering.fedramp_id()
    bad = []
    for f in files:
        try:
            doc = json.loads(Path(f).read_text())
        except (OSError, ValueError) as exc:
            bad.append(f"{f}: unreadable ({type(exc).__name__})")
            continue
        bad += problems(Path(f).name, doc, fid)
    for b in bad:
        print(f"::error::CDS-CSO-FID: {b}")
    if not bad:
        print(f"CDS-CSO-FID: {len(files)} file(s) carry the offering's FedRAMP ID")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
