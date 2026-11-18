#!/usr/bin/env python3
"""Publication gate (CDS-CSO-FID): every FedRAMP report carries the offering's FedRAMP ID.

The reports are the artifacts the governed freshness config marks
`certification_data`. Each one present under --root must be JSON with a
top-level `fedramp_id` equal to the ID in data/cds/offering.json; the
Certification Package Overview must also carry it in
serviceIdentification.fedRampPackageId, FedRAMP's own field. Run immediately
before a workflow uploads, over the directory the artifacts were built in:

    python3 ../scripts/check-fedramp-id.py            # the deploy: its built reports
    python3 ../scripts/check-fedramp-id.py FILE...    # the nightly: exactly what it publishes
    python3 ../scripts/check-fedramp-id.py --root DIR  # a fetched copy, or a fixture

The nightly names its files because its working directory also holds the
published SDR, CPO and inventory it downloaded as inputs and does not publish.

A listed report that is absent is skipped, as in the redaction gate: each
workflow publishes only its own subset, and the round-trip and freshness checks
cover absence. No report to check at all is a misconfiguration and fails
(exit 2), so a wrong --root cannot pass silently. Any report without the ID, or
with another one, fails (exit 1).
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _freshness  # noqa: E402
from _common import fedramp_id  # noqa: E402


def reports(cfg, root):
    """The certification-data reports present under root, in config order."""
    return [root / Path(a["path"]).name for a in cfg["artifacts"]
            if a.get("certification_data") and (root / Path(a["path"]).name).is_file()]


def violations(paths, expected):
    found = []
    for p in paths:
        try:
            doc = json.loads(p.read_text())
        except ValueError:
            found.append(f"{p.name}: not JSON, so it cannot carry the FedRAMP ID")
            continue
        got = doc.get("fedramp_id") if isinstance(doc, dict) else None
        if got != expected:
            found.append(f"{p.name}: fedramp_id is {got!r}, not the offering's")
        if p.name == "certification-package-overview.json":
            pkg = (doc.get("serviceIdentification") or {}).get("fedRampPackageId")
            if pkg != expected:
                found.append(f"{p.name}: serviceIdentification.fedRampPackageId is {pkg!r}, not the offering's")
    return found


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", help="exactly these reports (default: every listed report under --root)")
    ap.add_argument("--root", default=".", help="directory holding the built reports")
    ap.add_argument("--config", default=None, help="governed freshness config (default: the repo's)")
    a = ap.parse_args(argv)
    cfg = _freshness.load_freshness_config(a.config)
    paths = [Path(p) for p in a.files] if a.files else reports(cfg, Path(a.root))
    if not paths:
        print(f"::error::check-fedramp-id: no certification-data report under {a.root}", file=sys.stderr)
        return 2
    found = violations(paths, fedramp_id())
    for v in found:
        print(f"::error::CDS-CSO-FID: {v}", file=sys.stderr)
    if found:
        return 1
    print(f"check-fedramp-id: {len(paths)} report(s) carry the offering's FedRAMP ID")
    return 0


if __name__ == "__main__":
    sys.exit(main())
