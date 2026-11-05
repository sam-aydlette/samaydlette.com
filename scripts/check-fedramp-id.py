#!/usr/bin/env python3
"""Deploy gate: every FedRAMP report this build publishes carries the offering's
FedRAMP ID (CDS-CSO-FID).

For each file named: a report in a FedRAMP schema ($schema under
https://fedramp.gov/schemas/) must carry providerExtensions.fedRampId equal to
data/cds/offering.json's fedramp_id, and the CPO also in
serviceIdentification.fedRampPackageId; any other JSON that has a top-level
fedRampId (the issue index, logs, snapshot manifests) must carry the same
value. A file that cannot be read fails. Exit 0 pass, 1 fail.

  check-fedramp-id.py             # every file in REPORTS, in the current directory
  check-fedramp-id.py FILE...     # these files

REPORTS is the one list of what the deploy checks: a group that publishes a
FedRAMP report adds its file here, one line.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _offering  # noqa: E402

# Every FedRAMP report the deploy publishes, by built file name. Add a line per report.
REPORTS = (
    "certification-package-overview.json",
    "security-decision-record.json",
    "ongoing-certification-report.json",
)
FEDRAMP_SCHEMAS = ("https://fedramp.gov/schemas/", "https://www.fedramp.gov/schemas/")


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
    elif "fedRampId" in doc and doc["fedRampId"] != fid:
        out.append(f"{name}: fedRampId is not the offering's FedRAMP ID")
    return out


def main(argv=None):
    files = (sys.argv[1:] if argv is None else argv) or list(REPORTS)
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
