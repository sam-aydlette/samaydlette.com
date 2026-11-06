#!/usr/bin/env python3
"""Simulated submission of the FedRAMP Certification Package (FRC-CSO-PKG).

FRC-CSO-PKG: the package supplied to FedRAMP holds at least the Certification
Package Overview (CPO-CSO-OVR), the Security Decision Record with every
applicable rule (SDR-CSO-FRR), and an Ongoing Certification Report
(CCM-OCR-AVL). On every deploy this:

1. checks the three reports this build is about to publish: each validates
   against FedRAMP's schema, the SDR lists every applicable rule once, and all
   carry the same FedRAMP ID;
2. builds a submission manifest (each report's sha256 and version, and a
   package digest over their content hashes);
3. hands it to the simulated FedRAMP intake below, a function in this file,
   and checks the receipt echoes the digest;
4. appends an entry to the published log (package-submission-log.json) when
   the package changed since the last entry, or a certification report is
   due; earlier entries must be carried over unchanged;
5. CDS-CSO-FRC: when a certification report is due, the simulated FedRAMP
   issues a stand-in report in response to that submission, and the entry logs
   it verbatim with the date received. A report is due for the first
   submission, after any adaptive or transformative Significant Change
   Notification no earlier report covered, and once a year; an ordinary deploy
   never re-issues one. scripts/publish-certification-reports.py publishes
   each logged report unmodified and fails the deploy past two weeks from
   receipt. Every report says, in its title and first line, that it is a
   simulated report NOT ISSUED BY FEDRAMP and that the system is not certified;
6. AFC-CSO-NOC: files a change notice with the simulated FedRAMP for every
   change of the FedRAMP Security Inbox contact not yet filed
   (scripts/check-fsi-notice.py), and fails unless each notice is dated
   within one business day of the change.

NOTHING IS SENT. There is no network call: FedRAMP is simulated, and the
"submission", the report and every notice are entries in this log. Any
unexpected outcome fails the deploy.

  submit-package.py --cpo certification-package-overview.json \
      --sdr security-decision-record.json --ocr ongoing-certification-report.json \
      --previous prev-log.json --output package-submission-log.json --commit SHA
"""

import argparse
import hashlib
import importlib.util
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _engagement  # noqa: E402
import _fedramp_schema as fs  # noqa: E402
import _offering  # noqa: E402
import _rules  # noqa: E402
import _scn  # noqa: E402

_spec = importlib.util.spec_from_file_location("check_fsi_notice", Path(__file__).resolve().parent / "check-fsi-notice.py")
assert _spec is not None and _spec.loader is not None
fsi_notice = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fsi_notice)

BASE = "https://samaydlette.com/.well-known/"
SIMULATION = ("FedRAMP is simulated. The package goes to simulated_fedramp_intake() in scripts/submit-package.py, "
              "a function that never touches the network, and the only trace is this signed log. Nothing has been "
              "submitted to the real FedRAMP, and nothing will be.")


def _fail(msg):
    raise SystemExit(f"::error::package submission: {msg} (fail-closed)")


def simulated_fedramp_intake(manifest):
    """The simulated counterparty. Accepts any well-formed manifest and returns
    a receipt; it is obviously not FedRAMP."""
    return {"receiptId": "SIM-" + manifest["packageSha256"][:12].upper(),
            "receivedBy": "Simulated FedRAMP intake: a Python function in this repository. Nothing left the building.",
            "packageSha256": manifest["packageSha256"],
            "message": "Thank you for your submission. It has been placed in a queue that does not exist."}


def simulated_fedramp_notice_intake(notice):
    """The simulated counterparty for a FedRAMP Security Inbox change notice
    (AFC-CSO-NOC). Nothing is sent; this receipt is the whole exchange."""
    digest = hashlib.sha256(json.dumps(notice, sort_keys=True).encode()).hexdigest()
    return {"receiptId": "SIM-NOC-" + digest[:12].upper(),
            "receivedBy": "FedRAMP (simulated): a Python function in this repository. Nothing left the building.",
            "message": "Noted. Our records, which do not exist, have been updated."}


# --- CDS-CSO-FRC: the simulated FedRAMP's certification report --------------------------

NOT_CERTIFIED = _offering.CERTIFICATION_STATUS
REPORT_TITLE = ("SIMULATED REPORT, NOT ISSUED BY FEDRAMP: samaydlette.com is NOT FedRAMP certified "
                "(proof of concept)")
REPORT_NOTICE = ("This is not a FedRAMP Certification Report. FedRAMP did not write it, has never seen it, and has "
                 "certified nothing. A Python function in scripts/submit-package.py wrote it in response to a "
                 "simulated package submission, so the path that publishes FedRAMP Certification Reports unmodified "
                 "within two weeks (CDS-CSO-FRC) runs end to end. This system is not certified.")
ANNUAL_DAYS = 365


def reported_scns(entries):
    """Every SCN id an earlier certification report already covered."""
    return {s for e in entries for s in ((e.get("certificationReport") or {}).get("scnsCovered") or [])}


def report_due(entries, scn_rows, today):
    """Why the simulated FedRAMP owes a certification report for a submission
    made today, or None: the first one, after an adaptive or transformative SCN
    no earlier report covered, and annually."""
    reports = [e["certificationReport"] for e in entries if e.get("certificationReport")]
    if not reports:
        return "initial certification report (first package submission)"
    new = sorted(r["scn_id"] for r in scn_rows if r.get("scn_type") in _scn.RECORD_TYPES
                 and r.get("scn_id") not in reported_scns(entries))
    if new:
        return "after " + ", ".join(new) + " (adaptive or transformative Significant Change Notification)"
    last = max(date.fromisoformat(r["receivedOn"]) for r in reports)
    if today >= last + timedelta(days=ANNUAL_DAYS):
        return f"annual certification report (the last was received {last.isoformat()})"
    return None


def report_bytes(report):
    """The report exactly as received and published (CDS-CSO-FRC: unmodified)."""
    return (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def simulated_fedramp_certification_report(entry, trigger, fedramp_id, today, scn_rows):
    """The simulated counterparty issues a stand-in report in response to a
    submission. It is obviously fake, and says so first."""
    receipt = entry["receipt"]["receiptId"]
    report = {
        "title": REPORT_TITLE,
        "notice": REPORT_NOTICE,
        "simulated": True,
        "notIssuedByFedRAMP": True,
        "certificationStatus": NOT_CERTIFIED,
        "issuer": "FedRAMP (simulated): a Python function in this repository, with no authority whatsoever.",
        "cloudServiceOffering": "samaydlette.com",
        "fedRampId": fedramp_id,
        "received": today.isoformat(),
        "inResponseTo": {"receiptId": receipt, "submittedAt": entry["submittedAt"],
                         "packageSha256": entry["manifest"]["packageSha256"]},
        "trigger": trigger,
        "determination": "None. No certification decision has been made, and none will be: nothing was ever "
                         "submitted to FedRAMP.",
        "findings": [],
        "noteToAgencies": "If you came here hoping for a FedRAMP certification, sorry: this one is pretend. Hit me "
                          "up on LinkedIn: https://www.linkedin.com/in/sa2/",
    }
    _engagement.require_none(report, "the simulated certification report")
    return {"file": f"{today.isoformat()}-{receipt.lower()}-simulated-certification-report.json",
            "receivedOn": today.isoformat(), "from": "FedRAMP (simulated)", "trigger": trigger,
            "scnsCovered": sorted(r["scn_id"] for r in scn_rows if r.get("scn_type") in _scn.RECORD_TYPES),
            "sha256": hashlib.sha256(report_bytes(report)).hexdigest(), "report": report}


PROGRAM = "20x"  # FRC-CSO-POP: one program sought (DEC-107)


# CPO-CSO-OVR content the schema leaves optional but the rules require here:
# the trust center and secure configuration guidance (CDS-CSO-PUB), the
# third-party resources (MAS-CSO-TPR) and the assessor's overall summary
# (CPO-CSO-OSA).
CPO_REQUIRED = (("serviceProperties", "trustCenter"), ("serviceProperties", "secureConfigurationGuidance"),
                ("thirdPartyInformationResources",),
                ("providerExtensions", "independentAssessment", "overallSummary"))


def cpo_gaps(cpo):
    out = []
    for path in CPO_REQUIRED:
        node = cpo
        for k in path:
            node = node.get(k) if isinstance(node, dict) else None
        if not node:
            out.append(".".join(path))
    return out


def check_components(docs, applicable, fedramp_id):
    for kind, doc in docs.items():
        errs = fs.validate(doc, kind)
        if errs:
            _fail(f"the {kind.upper()} does not validate against FedRAMP's schema: {errs[0]}")
    missing = cpo_gaps(docs["cpo"])
    if missing:
        _fail(f"the CPO is incomplete (CPO-CSO-OVR): no {', '.join(missing)}")
    if docs["cpo"]["serviceIdentification"]["certificationType"] != PROGRAM:
        _fail(f"the CPO's certificationType is not {PROGRAM}: this offering seeks one program only (FRC-CSO-POP)")
    ids = [r["frrID"] for r in docs["sdr"]["fedRampRequirements"]]
    if sorted(ids) != sorted(applicable) or len(ids) != len(set(ids)):
        _fail("the SDR does not list every applicable FedRAMP rule exactly once (SDR-CSO-FRR)")
    got = {"cpo": docs["cpo"]["serviceIdentification"]["fedRampPackageId"],
           "sdr": (docs["sdr"].get("providerExtensions") or {}).get("fedRampId"),
           "ocr": (docs["ocr"].get("providerExtensions") or {}).get("fedRampId")}
    wrong = sorted(k for k, v in got.items() if v != fedramp_id)
    if wrong:
        _fail(f"{', '.join(wrong)} carry a FedRAMP ID other than the offering's (CDS-CSO-FID)")
    for kind in ("cpo", "sdr"):
        cert = (docs[kind].get("providerExtensions") or {}).get("certification")
        if not isinstance(cert, dict) or cert.get("status") != NOT_CERTIFIED:
            _fail(f"the {kind.upper()} does not state providerExtensions.certification.status {NOT_CERTIFIED!r}: "
                  "this proof of concept never presents itself as certified")


def manifest_for(docs, paths, commit):
    """Each report's bytes (sha256) and content (its contentSha256, which leaves
    out the timestamp): the log gains an entry when the content changes."""
    comps = []
    for kind, rule, name in (("cpo", "CPO-CSO-OVR", "certification-package-overview.json"),
                             ("sdr", "SDR-CSO-FRR", "security-decision-record.json"),
                             ("ocr", "CCM-OCR-AVL", "ongoing-certification-report.json")):
        raw = Path(paths[kind]).read_bytes()
        content = (docs[kind].get("providerExtensions") or {}).get("contentSha256")
        if not content:
            _fail(f"the {kind.upper()} carries no contentSha256")
        comps.append({"component": kind.upper(), "rule": rule, "url": BASE + name,
                      "sha256": hashlib.sha256(raw).hexdigest(), "contentSha256": content,
                      "version": (docs[kind].get("metadata") or {}).get("version")})
    digest = hashlib.sha256("".join(c["contentSha256"] for c in comps).encode()).hexdigest()
    return {"components": comps, "packageSha256": digest, "commit": commit}


def build(docs, paths, previous, now, commit, applicable, fedramp_id, scn_rows=(), offering=None):
    check_components(docs, applicable, fedramp_id)
    entries = list((previous or {}).get("entries") or [])
    for e in entries:
        if not isinstance(e, dict) or not {"submittedAt", "manifest", "receipt"} <= set(e):
            _fail("the previous log has a malformed entry; earlier entries are carried over unchanged")
    manifest = manifest_for(docs, paths, commit)
    receipt = simulated_fedramp_intake(manifest)
    if receipt.get("packageSha256") != manifest["packageSha256"]:
        _fail("the simulated intake's receipt does not echo the package digest")
    due = report_due(entries, scn_rows, now.date())
    if due or not entries or entries[-1]["manifest"]["packageSha256"] != manifest["packageSha256"]:
        entry = {"submittedAt": now.isoformat(), "manifest": manifest, "receipt": receipt}
        if due:
            entry["certificationReport"] = simulated_fedramp_certification_report(
                entry, due, fedramp_id, now.date(), scn_rows)
        entries.append(entry)
    log = {"schema": "package-submission-log/1", "generated_at": now.isoformat(), "fedRampId": fedramp_id,
           "certificationPackageOverviewUri": fs.CPO_URI, "nothingSent": True,
           "simulated": {"counterparty": "fedramp", "how": SIMULATION}, "entries": entries}
    if offering is not None:
        notices, problems = fsi_notice.file_notices(offering, (previous or {}).get("changeNotices"), now.date(),
                                                    simulated_fedramp_notice_intake)
        if problems:
            _fail("FedRAMP Security Inbox change notice (AFC-CSO-NOC): " + "; ".join(problems))
        log["changeNotices"] = notices
    return log


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cpo", default="certification-package-overview.json")
    ap.add_argument("--sdr", default="security-decision-record.json")
    ap.add_argument("--ocr", default="ongoing-certification-report.json")
    ap.add_argument("--previous", default=None)
    ap.add_argument("--output", default="package-submission-log.json")
    ap.add_argument("--commit", default="")
    ap.add_argument("--scn-register", default=str(_scn.REGISTER))
    ap.add_argument("--offering", default=str(_offering.OFFERING_PATH))
    a = ap.parse_args(argv)
    paths = {"cpo": a.cpo, "sdr": a.sdr, "ocr": a.ocr}
    docs = {}
    for k, p in paths.items():
        try:
            docs[k] = json.loads(Path(p).read_text())
        except (OSError, ValueError) as exc:
            _fail(f"cannot read the {k.upper()} ({p}): {exc}")
    prev = {}
    if a.previous and Path(a.previous).exists():
        try:
            prev = json.loads(Path(a.previous).read_text())
        except ValueError:
            _fail("the previously published log is not JSON; refusing to start a new log over it")
        if prev and prev.get("schema") != "package-submission-log/1":
            _fail("the previously published log is not a package-submission-log/1 document")
    _, scn_rows = _scn.read_register(a.scn_register)
    offering = json.loads(Path(a.offering).read_text())
    log = build(docs, paths, prev, datetime.now(timezone.utc), a.commit, _rules.applicable_provider_rules(),
                _offering.fedramp_id(), scn_rows, offering)
    Path(a.output).write_text(json.dumps(log, indent=2) + "\n")
    last = log["entries"][-1]
    print(f"package-submission-log: {len(log['entries'])} entr(ies); latest {last['receipt']['receiptId']} "
          "(simulated FedRAMP; nothing sent)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
