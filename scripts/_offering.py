"""The offering's declared identity (data/cds/offering.json), shared by every report.

CDS-CSO-FID: every FedRAMP report this repository publishes carries the same
FedRAMP ID, read here and nowhere else, under providerExtensions.fedRampId
(FedRAMP's report schemas other than the CPO have no field for it; the CPO
carries it in serviceIdentification.fedRampPackageId). No ID has been
assigned, so the value is FedRAMP's own fallback, the provider name and
acronym, marked as not real; scripts/check-fedramp-id.py fails the deploy if a
report it publishes carries none or another.

Also the semver content-hash version the CPO and OCR share with the SDR.
"""

import hashlib
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OFFERING_PATH = REPO / "data" / "cds" / "offering.json"
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
NOT_REAL = "NOT-A-REAL"


def _fail(msg):
    raise SystemExit(f"::error::offering: {msg} (fail-closed)")


def load(path=OFFERING_PATH):
    try:
        off = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        _fail(f"cannot read {path}: {exc}")
    for k in ("provider_name", "service_acronym", "fedramp_id"):
        if not isinstance(off.get(k), str) or not off[k].strip():
            _fail(f"{k} is missing")
    fid = off["fedramp_id"]
    # Until FedRAMP assigns one, FedRAMP's fallback: the provider's name and acronym.
    if off["provider_name"] not in fid or off["service_acronym"] not in fid:
        _fail("fedramp_id must carry the provider name and acronym (FedRAMP's fallback) until one is assigned")
    if NOT_REAL in fid and not off.get("fedramp_id_simulated"):
        _fail("a placeholder FedRAMP ID must say why (fedramp_id_simulated)")
    return off


def fedramp_id(path=OFFERING_PATH):
    return load(path)["fedramp_id"]


# The certification this offering seeks, and the fact that it does not hold it.
# The one place the CPO, the SDR, the simulated certification report and its
# index read it from, so the published wording cannot drift: this proof of
# concept is not certified, and every published statement of the program says so.
CERTIFICATION_PROGRAM = "FedRAMP 20x, Program path, Class C"
CERTIFICATION_STATUS = "not certified (proof of concept)"


def certification():
    """providerExtensions.certification, as the CPO and the SDR publish it."""
    return {"program": CERTIFICATION_PROGRAM, "status": CERTIFICATION_STATUS}


FEDRAMP_SCHEMA_BASES = ("https://fedramp.gov/schemas/", "https://www.fedramp.gov/schemas/")


def stamp_fedramp_id(doc, path=OFFERING_PATH):
    """`doc` carrying the offering's FedRAMP ID (CDS-CSO-FID): under
    providerExtensions.fedRampId on a report in a FedRAMP schema, otherwise as
    a top-level `fedRampId` placed first (after any $schema). Returns the
    document to write."""
    fid = fedramp_id(path)
    if str(doc.get("$schema", "")).startswith(FEDRAMP_SCHEMA_BASES):
        doc.setdefault("providerExtensions", {})["fedRampId"] = fid
        return doc
    rest = {k: v for k, v in doc.items() if k != "fedRampId"}
    if "$schema" in rest:  # keep $schema first
        return {"$schema": rest.pop("$schema"), "fedRampId": fid, **rest}
    return {"fedRampId": fid, **rest}


# --- versioning (CPO-CSO-MTD, and the OCR alike) --------------------------------------

def content_hash(doc, volatile=("metadata",), volatile_ext=("contentSha256",)):
    """sha256 of what the version tracks: the document without its version,
    timestamp and update source, the hash itself, and any providerExtensions field named volatile."""
    body = {k: v for k, v in doc.items() if k not in (*volatile, "providerExtensions")}
    body["metadata"] = {k: v for k, v in (doc.get("metadata") or {}).items()
                        if k not in ("version", "lastUpdated", "updateSource")}
    pe = {k: v for k, v in (doc.get("providerExtensions") or {}).items() if k not in volatile_ext}
    raw = json.dumps({"body": body, "pe": pe}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def next_version(prev, digest):
    """Unchanged content keeps the previous version, changed content bumps the
    patch, and a previous document without a semver starts at 1.0.0."""
    v = ((prev or {}).get("metadata") or {}).get("version", "")
    m = SEMVER.match(v or "")
    if not m:
        return "1.0.0"
    if ((prev or {}).get("providerExtensions") or {}).get("contentSha256") == digest:
        return v
    return f"{m.group(1)}.{m.group(2)}.{int(m.group(3)) + 1}"


def stamp_version(doc, prev, now, source, volatile_ext=("contentSha256",)):
    """Set providerExtensions.contentSha256 and metadata {version, lastUpdated, updateSource}."""
    digest = content_hash(doc, volatile_ext=volatile_ext)
    doc.setdefault("providerExtensions", {})["contentSha256"] = digest
    doc["metadata"] = {"version": next_version(prev, digest), "lastUpdated": now.isoformat(),
                       "updateSource": source, **{k: v for k, v in (doc.get("metadata") or {}).items()
                                                  if k not in ("version", "lastUpdated", "updateSource")}}
    return doc
