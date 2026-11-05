"""Assessor records: the signed input port (REQ-ASR-1; Appendix B T74).

An assessor's findings, summaries and comments enter the pipeline only as JSON
records the assessor signs (infrastructure/schemas/assessor-record.schema.json).
A record is accepted only when:

  * it carries every required field of the published format;
  * the pinned assessor identity (infrastructure/keys/assessor-identity.json)
    exists, and its recorded sha256 matches its public key;
  * the record names that identity (organization and key_id); and
  * its ECDSA P-256 / SHA-256 signature verifies over the canonical form:
    the record without "signature", sorted keys, compact separators, UTF-8.

Any record that fails any of these fails the build. The provider never edits a
record's text: outputs carry it verbatim with the signature, and
verify_output() fails the build when an output differs from the signed record.

With no records there is nothing to verify and no identity is needed; the SDR
states "no assessor record".
"""
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RECORDS_DIR = REPO / "data" / "assessor-records"
IDENTITY_PATH = REPO / "infrastructure" / "keys" / "assessor-identity.json"

ALGORITHM = "ECDSA_P256_SHA256"
KINDS = ("finding", "summary", "comment")
REQUIRED = ("record_type", "schema_version", "record_id", "assessor", "issued_at", "kind", "text", "signature")
# What an output carries for each record: the signed fields, verbatim, plus the signature.
CARRIED = ("record_id", "kind", "issued_at", "assessor", "text", "signature")
NO_RECORD = "no assessor record"


def _fail(msg):
    raise SystemExit(f"::error::assessor record: {msg}")


def canonical(record):
    body = copy.deepcopy(record)
    body.pop("signature", None)
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _shape(rec, name):
    if not isinstance(rec, dict):
        _fail(f"{name} is not a JSON object")
    missing = [k for k in REQUIRED if k not in rec]
    if missing:
        _fail(f"{name} is missing {', '.join(missing)} (an unsigned record is refused)")
    if rec["record_type"] != "assessor-record" or rec["schema_version"] != "1":
        _fail(f"{name} is not an assessor-record, schema version 1")
    if rec["kind"] not in KINDS:
        _fail(f"{name} kind {rec['kind']!r} is not one of {', '.join(KINDS)}")
    a, s = rec["assessor"], rec["signature"]
    if not isinstance(a, dict) or not a.get("organization") or not a.get("key_id"):
        _fail(f"{name} does not name its assessor (organization and key_id)")
    if not isinstance(s, dict) or s.get("algorithm") != ALGORITHM or not s.get("value"):
        _fail(f"{name} carries no {ALGORITHM} signature")
    for k in ("record_id", "issued_at", "text"):
        if not isinstance(rec[k], str) or not rec[k].strip():
            _fail(f"{name} has an empty {k}")
    if "rule_id" in rec and (not isinstance(rec["rule_id"], str) or not rec["rule_id"]):
        _fail(f"{name} has an empty rule_id")


def _load_identity(path):
    p = Path(path)
    if not p.exists():
        _fail(f"records are present but no assessor identity is pinned at {p}")
    try:
        ident = json.loads(p.read_text())
        pem = ident["public_key_pem"].encode("ascii")
    except (json.JSONDecodeError, KeyError, AttributeError, UnicodeEncodeError) as exc:
        _fail(f"pinned identity {p} is unreadable ({type(exc).__name__})")
    if hashlib.sha256(pem).hexdigest() != ident.get("public_key_sha256"):
        _fail(f"pinned identity {p} does not match its recorded sha256")
    if not ident.get("assessor") or not ident.get("key_id"):
        _fail(f"pinned identity {p} does not name the assessor and key_id")
    return ident, pem


def _verify(rec, name, ident, pem):
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        _fail("the cryptography package is not installed; records cannot be verified")
    a = rec["assessor"]
    if a["organization"] != ident["assessor"] or a["key_id"] != ident["key_id"]:
        _fail(f"{name} names {a['organization']!r} / {a['key_id']!r}, not the pinned assessor identity")
    try:
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
            _fail("the pinned identity is not a P-256 key")
        key.verify(base64.b64decode(rec["signature"]["value"], validate=True), canonical(rec),
                   ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError) as exc:
        _fail(f"{name} signature does not verify against the pinned identity ({type(exc).__name__})")


def load_records(records_dir=RECORDS_DIR, identity_path=IDENTITY_PATH):
    """Every record in records_dir, verified; [] when there are none. Fails closed."""
    d = Path(records_dir)
    files = sorted(d.glob("*.json")) if d.is_dir() else []
    if not files:
        return []
    ident, pem = _load_identity(identity_path)
    records, seen = [], set()
    for f in files:
        try:
            rec = json.loads(f.read_text())
        except json.JSONDecodeError:
            _fail(f"{f.name} is not valid JSON")
        _shape(rec, f.name)
        _verify(rec, f.name, ident, pem)
        if rec["record_id"] in seen:
            _fail(f"record_id {rec['record_id']} appears twice")
        seen.add(rec["record_id"])
        records.append(rec)
    return records


def _carried(rec):
    return {k: copy.deepcopy(rec[k]) for k in CARRIED}


def attach(rule_records, records):
    """Attach each verified record verbatim. A record naming a rule goes on that
    rule's assessor_comment_responses; others go in the returned block. A record
    naming a rule the SDR does not have fails the build."""
    by_rule = {r["rule_id"]: r for r in rule_records}
    unattached = []
    for rec in sorted(records, key=lambda r: r["record_id"]):
        rid = rec.get("rule_id")
        if rid is None:
            unattached.append(_carried(rec))
        elif rid in by_rule:
            by_rule[rid]["assessor_comment_responses"].append(_carried(rec))
        else:
            _fail(f"{rec['record_id']} names rule {rid}, which is not in the SDR")
    n = len(records)
    status = NO_RECORD if n == 0 else f"{n} verified assessor record{'s' if n != 1 else ''}"
    return {"status": status, "records": unattached}


def verify_output(sdr, records):
    """T74: every assessor entry in the output equals its signed record, and every
    signed record is carried. Fails the build otherwise."""
    signed = {r["record_id"]: _carried(r) for r in records}
    carried = []
    pe = sdr.get("providerExtensions")
    if isinstance(pe, dict):
        # The SDR in FedRAMP's schema keeps them under providerExtensions.
        for entries in (pe.get("assessorCommentResponses") or {}).values():
            carried += entries or []
        carried += (pe.get("assessorRecords") or {}).get("records", []) or []
    for rr in sdr.get("rule_records", []):
        carried += rr.get("assessor_comment_responses", []) or []
    carried += (sdr.get("assessor_records") or {}).get("records", []) or []
    seen = set()
    for entry in carried:
        rid = entry.get("record_id") if isinstance(entry, dict) else None
        if rid not in signed:
            _fail(f"output carries assessor entry {rid!r} with no signed record")
        if entry != signed[rid]:
            _fail(f"output text for {rid} differs from the assessor's signed record")
        seen.add(rid)
    dropped = sorted(set(signed) - seen)
    if dropped:
        _fail(f"output omits signed record(s) {', '.join(dropped)}")


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Verify assessor records, and that an SDR carries them verbatim (T74).")
    ap.add_argument("--records", default=str(RECORDS_DIR))
    ap.add_argument("--identity", default=str(IDENTITY_PATH))
    ap.add_argument("--sdr", default=None, help="a built security-decision-record.json to check")
    a = ap.parse_args(argv)
    records = load_records(a.records, a.identity)
    if a.sdr:
        verify_output(json.loads(Path(a.sdr).read_text()), records)
    print(f"assessor records: {len(records)} verified" + ("; SDR carries them verbatim" if a.sdr else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
