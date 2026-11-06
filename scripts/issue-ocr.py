#!/usr/bin/env python3
"""Issue the quarterly Ongoing Certification Report and snapshot the package
(CCM-OCR-AVL, CCM-OCR-SOR, CDS-CSO-HAD).

On or after each issue date in the CCM calendar, the first run that finds the
date missing from the published index (ocr-issues.json):

1. builds the frozen report for that date with scripts/build-ocr.py --issue,
   covering the previous issue to this one: ocr-issue-<date>.json and .md;
2. copies every certification artifact present in --work (the package as
   published at that moment, with its signatures) to snapshots/<date>/ and
   writes the snapshot manifest snapshot-<date>.json (name, sha256, bytes);
3. appends the issue to ocr-issues.json with the report's and manifest's
   sha256, the review date and where its Quarterly Review is published.

Issued files are never rebuilt: an issue already in the index is carried over
unchanged, and an index that loses or alters an earlier issue fails. The
publishing workflow signs each new file, refuses to overwrite one that is
already served, and checks the served bytes against the index.

Writes the list of new files to publish (one per line) to --new-files.

  issue-ocr.py --work DIR --previous-index prev-ocr-issues.json --out DIR \
      --new-files issued.txt  (plus build-ocr.py's inputs)
"""

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ccm  # noqa: E402
import _decisions  # noqa: E402
import _fedramp_schema as fs  # noqa: E402
import _offering  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
BASE = "https://samaydlette.com/.well-known/"
# What a snapshot holds: the certification data as published, with signatures.
SNAPSHOT = [
    "certification-package-overview.json", "certification-package-overview.md", "certification-package-overview.bundle",
    "security-decision-record.json", "security-decision-record.md", "security-decision-record.bundle",
    "ongoing-certification-report.json", "ongoing-certification-report.md", "ongoing-certification-report.bundle",
    "ksi-signal.json", "ksi-signal.bundle", "vdr-report.json", "vdr-report.bundle",
    "vdr-detail-report.json", "vdr-detail-report.bundle", "vdr-accepted-vulnerabilities.json",
    "vdr-accepted-vulnerabilities.bundle", "vdr-history.json", "vdr-history.bundle",
    "boundary-map.json", "boundary-map.bundle", "policy-index.json", "policy-index.bundle",
    "availability.json", "availability.bundle", "trust-center.json", "trust-center.bundle",
    "iiw.csv", "iiw.bundle", "fedramp-certification-reports.json", "fedramp-certification-reports.bundle",
    "package-submission-log.json", "package-submission-log.bundle",
]
# Without these the snapshot is not the certification data, and nothing is issued.
REQUIRED = ("certification-package-overview.json", "security-decision-record.json",
            "ongoing-certification-report.json", "ksi-signal.json")
ACCESS = ("Each issued report is at /.well-known/ocr-issue-<date>.json (and .md), signed (.bundle), and never "
          "rewritten. The certification data as published on that date is at /.well-known/snapshots/<date>/<file>, "
          "each file with its original signature, listed with sha256s in the signed manifest "
          "/.well-known/snapshot-<date>.json. Snapshots are kept for the duration of certification. Verify a file: "
          "compare its sha256 with the manifest, and its signature with cosign as in docs/verification.md.")


def _fail(msg):
    raise SystemExit(f"::error::OCR issue: {msg} (fail-closed)")


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _ocr_builder():
    spec = importlib.util.spec_from_file_location("build_ocr", REPO / "scripts" / "build-ocr.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check_index(prev, cal):
    """The previous index, checked: known schema, only calendar dates, in order."""
    if not prev:
        return []
    if prev.get("schema") != "ocr-issues/1" or not isinstance(prev.get("issues"), list):
        _fail("the published ocr-issues.json is not an ocr-issues/1 index")
    dates = [i.get("issueDate") for i in prev["issues"]]
    if dates != sorted(dates) or len(set(dates)) != len(dates):
        _fail("the published index is out of order or repeats an issue")
    for d in dates:
        if d not in {x.isoformat() for x in cal.issues}:
            _fail(f"the published index lists {d}, which is not a calendar issue date")
    return prev["issues"]


def snapshot(work, out, issue, fedramp_id, now):
    missing = [f for f in REQUIRED if not (work / f).exists()]
    if missing:
        _fail(f"cannot snapshot the package for {issue}: {', '.join(missing)} missing")
    d = out / "snapshots" / issue
    d.mkdir(parents=True, exist_ok=True)
    files = []
    for name in SNAPSHOT:
        src = work / name
        if src.exists():
            shutil.copyfile(src, d / name)
            files.append({"name": name, "url": f"{BASE}snapshots/{issue}/{name}", "sha256": _sha(src),
                          "bytes": src.stat().st_size})
    manifest = {"schema": "snapshot/1", "ocrIssue": issue, "takenAt": now.isoformat(), "fedRampId": fedramp_id,
                "certificationPackageOverviewUri": fs.CPO_URI, "access": ACCESS, "files": files}
    (out / f"snapshot-{issue}.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return [f"snapshots/{issue}/{f['name']}" for f in files] + [f"snapshot-{issue}.json"]


def run(a, now):
    today = now.date()
    cal = _ccm.load(a.calendar, today)
    off = _offering.load(a.offering)
    work, out = Path(a.work), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    prev = json.loads(Path(a.previous_index).read_text()) if a.previous_index and Path(a.previous_index).exists() else {}
    issues = list(check_index(prev, cal))
    have = {i["issueDate"] for i in issues}
    new_files = []
    ocr = _ocr_builder()
    for d in cal.issued(today):
        if d.isoformat() in have:
            continue
        iso = d.isoformat()
        name = f"ocr-issue-{iso}"
        doc = ocr.build(cal, today, ocr._load_json(a.vdr), _decisions.load(a.decisions), ocr._scn_rows(a.scn_register),
                        ocr._load_json(a.incidents), ocr._load_json(a.ksi_signal),
                        json.loads(Path(a.profile).read_text()), off, {}, now, d)
        fs.write_validated(doc, "ocr", out / f"{name}.json")
        (out / f"{name}.md").write_text(ocr.render_markdown(doc) + "\n")
        snap = snapshot(work, out, iso, off["fedramp_id"], now)
        issues.append({"issueDate": iso, "issuedAt": now.isoformat(), "late": today > d,
                       "reportPeriod": doc["reportPeriod"],
                       "report": f"{BASE}{name}.json", "reportMarkdown": f"{BASE}{name}.md",
                       "reportSha256": _sha(out / f"{name}.json"),
                       "snapshotManifest": f"{BASE}snapshot-{iso}.json",
                       "snapshotManifestSha256": _sha(out / f"snapshot-{iso}.json"),
                       "quarterlyReviewDate": cal.review_date(d).isoformat(),
                       "quarterlyReview": _ccm.review_url(d)})
        new_files += [f"{name}.json", f"{name}.md", *snap]
    issues.sort(key=lambda i: i["issueDate"])
    index = {"schema": "ocr-issues/1", "generated_at": now.isoformat(), "fedRampId": off["fedramp_id"],
             "certificationPackageOverviewUri": fs.CPO_URI,
             "continuousMonitoring": _ccm.dates_summary(cal, today), "access": ACCESS, "issues": issues}
    (out / "ocr-issues.json").write_text(json.dumps(index, indent=2) + "\n")
    if a.new_files:
        Path(a.new_files).write_text("".join(f + "\n" for f in new_files))
    return index, new_files


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work", required=True, help="directory holding the package as published")
    ap.add_argument("--out", required=True)
    ap.add_argument("--previous-index", default=None)
    ap.add_argument("--new-files", default=None)
    ap.add_argument("--calendar", default=str(_ccm.CALENDAR_PATH))
    ap.add_argument("--offering", default=str(_offering.OFFERING_PATH))
    ap.add_argument("--profile", default=str(REPO / "data" / "system-profile.json"))
    ap.add_argument("--vdr", default="vdr-report.json")
    ap.add_argument("--decisions", default=str(REPO / "data" / "decisions.json"))
    ap.add_argument("--scn-register", default=str(REPO / "docs" / "scn" / "scn-register.csv"))
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--incidents", default=str(REPO / "data" / "incidents.json"))
    a = ap.parse_args(argv)
    index, new = run(a, datetime.now(timezone.utc))
    print(f"ocr-issues: {len(index['issues'])} issued; {len([f for f in new if f.startswith('ocr-issue-')]) // 2} "
          f"new this run; next {index['continuousMonitoring']['nextOngoingCertificationReportDate']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
