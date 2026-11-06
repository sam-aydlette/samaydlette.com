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
   the package changed since the last entry; earlier entries must be carried
   over unchanged.

NOTHING IS SENT. There is no network call: FedRAMP is simulated, and the
"submission" is this log entry. Any unexpected outcome fails the deploy.

  submit-package.py --cpo certification-package-overview.json \
      --sdr security-decision-record.json --ocr ongoing-certification-report.json \
      --previous prev-log.json --output package-submission-log.json --commit SHA
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fedramp_schema as fs  # noqa: E402
import _offering  # noqa: E402
import _rules  # noqa: E402

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


def build(docs, paths, previous, now, commit, applicable, fedramp_id):
    check_components(docs, applicable, fedramp_id)
    entries = list((previous or {}).get("entries") or [])
    for e in entries:
        if not isinstance(e, dict) or not {"submittedAt", "manifest", "receipt"} <= set(e):
            _fail("the previous log has a malformed entry; earlier entries are carried over unchanged")
    manifest = manifest_for(docs, paths, commit)
    receipt = simulated_fedramp_intake(manifest)
    if receipt.get("packageSha256") != manifest["packageSha256"]:
        _fail("the simulated intake's receipt does not echo the package digest")
    if not entries or entries[-1]["manifest"]["packageSha256"] != manifest["packageSha256"]:
        entries.append({"submittedAt": now.isoformat(), "manifest": manifest, "receipt": receipt})
    return {"schema": "package-submission-log/1", "generated_at": now.isoformat(), "fedRampId": fedramp_id,
            "certificationPackageOverviewUri": fs.CPO_URI, "nothingSent": True,
            "simulated": {"counterparty": "fedramp", "how": SIMULATION}, "entries": entries}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cpo", default="certification-package-overview.json")
    ap.add_argument("--sdr", default="security-decision-record.json")
    ap.add_argument("--ocr", default="ongoing-certification-report.json")
    ap.add_argument("--previous", default=None)
    ap.add_argument("--output", default="package-submission-log.json")
    ap.add_argument("--commit", default="")
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
    log = build(docs, paths, prev, datetime.now(timezone.utc), a.commit, _rules.applicable_provider_rules(),
                _offering.fedramp_id())
    Path(a.output).write_text(json.dumps(log, indent=2) + "\n")
    last = log["entries"][-1]
    print(f"package-submission-log: {len(log['entries'])} entr(ies); latest {last['receipt']['receiptId']} "
          "(simulated FedRAMP; nothing sent)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
