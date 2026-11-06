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

Keyless set (load_assessment): an assessor that signs with Sigstore instead of a
key it holds signs one set file holding all its records. The pinned identity
then names the signing workflow's certificate identity and OIDC issuer
(algorithm SIGSTORE_KEYLESS). The set is accepted only when cosign verifies its
bundle against exactly that identity, and each record in it is accepted only
when it names the pinned assessor and its signature value is the sha256 of its
canonical form (algorithm SIGSTORE_KEYLESS_SET), so a record is bound to the
signed set and cannot be altered alone. The set and its bundle are published,
so anyone can repeat the check. This is how the simulated assessor
(tools/simulated-assessor/, .github/workflows/simulated-assessor.yml) signs.

Binding: a set states what it covered (subject.commit, the commit whose
repository it verified, and subject.signal_id, the published KSI signal it
validated). The caller states the commit and signal it expects, and
load_assessment refuses a set covering anything else.
"""
import base64
import copy
import hashlib
import json
import subprocess  # nosec B404: runs cosign with a fixed argument list
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RECORDS_DIR = REPO / "data" / "assessor-records"
IDENTITY_PATH = REPO / "infrastructure" / "keys" / "assessor-identity.json"

ALGORITHM = "ECDSA_P256_SHA256"
KEYLESS = "SIGSTORE_KEYLESS"           # the pinned identity of a keyless assessor
SET_ALGORITHM = "SIGSTORE_KEYLESS_SET"  # a record bound to a keyless-signed set
SET_TYPE = "simulated-independent-assessment"
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
    if not isinstance(s, dict) or s.get("algorithm") not in (ALGORITHM, SET_ALGORITHM) or not s.get("value"):
        _fail(f"{name} carries no {ALGORITHM} or {SET_ALGORITHM} signature")
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
        if ident.get("algorithm") == KEYLESS:
            _fail(f"the pinned identity {p} is keyless: its records arrive only as a signed set "
                  "(load_assessment), never as loose files")
        pem = ident["public_key_pem"].encode("ascii")
    except (json.JSONDecodeError, KeyError, AttributeError, UnicodeEncodeError) as exc:
        _fail(f"pinned identity {p} is unreadable ({type(exc).__name__})")
    if hashlib.sha256(pem).hexdigest() != ident.get("public_key_sha256"):
        _fail(f"pinned identity {p} does not match its recorded sha256")
    if not ident.get("assessor") or not ident.get("key_id"):
        _fail(f"pinned identity {p} does not name the assessor and key_id")
    return ident, pem


def _verify(rec, name, ident, pem):
    if rec["signature"]["algorithm"] != ALGORITHM:
        _fail(f"{name} is not signed with {ALGORITHM}")
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


# --- keyless set ------------------------------------------------------------------------

def load_keyless_identity(path=IDENTITY_PATH):
    p = Path(path)
    try:
        ident = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"no readable keyless assessor identity at {p} ({type(exc).__name__})")
    if not isinstance(ident, dict) or ident.get("algorithm") != KEYLESS:
        _fail(f"the identity pinned at {p} is not a {KEYLESS} identity")
    for k in ("assessor", "key_id", "certificate_identity", "certificate_oidc_issuer"):
        if not isinstance(ident.get(k), str) or not ident[k]:
            _fail(f"the identity pinned at {p} does not name its {k}")
    return ident


def cosign_verify(set_path, bundle_path, ident):
    """True when cosign verifies the bundle over the set file against exactly the
    pinned certificate identity and issuer (no regular expression)."""
    r = subprocess.run(["cosign", "verify-blob", "--bundle", str(bundle_path),
                        "--certificate-identity", ident["certificate_identity"],
                        "--certificate-oidc-issuer", ident["certificate_oidc_issuer"], str(set_path)],
                       capture_output=True, text=True, check=False)  # nosec B603: fixed argv
    return r.returncode == 0


def load_assessment(set_path, bundle_path, identity_path=IDENTITY_PATH, verifier=None, *,
                    expect_commit, expect_signal_id):
    """Every record in a keyless-signed assessment set, verified. Fails closed when
    the set or its bundle is missing: the deploy depends on the assessment."""
    return load_assessment_with_subject(set_path, bundle_path, identity_path, verifier,
                                        expect_commit=expect_commit, expect_signal_id=expect_signal_id)[0]


def bind(doc, name, expect_commit, expect_signal_id):
    """The set's subject, when it covers exactly the commit and published KSI
    signal the caller states. A validly signed set for any other state fails:
    an assessment is evidence only for what it assessed."""
    if not expect_commit or not expect_signal_id:
        _fail("no commit or signal_id was stated for the assessment to cover; an unbound assessment is refused")
    subj = doc.get("subject")
    if not isinstance(subj, dict):
        _fail(f"{name} names no subject (the commit and KSI signal it covered)")
    if subj.get("commit") != expect_commit:
        _fail(f"{name} covers commit {subj.get('commit')!r}, not the stated commit {expect_commit!r}")
    if subj.get("signal_id") != expect_signal_id:
        _fail(f"{name} covers KSI signal {subj.get('signal_id')!r}, not the stated signal {expect_signal_id!r}")
    return copy.deepcopy(subj)


def load_assessment_with_subject(set_path, bundle_path, identity_path=IDENTITY_PATH, verifier=None, *,
                                 expect_commit, expect_signal_id):
    """(records, subject): load_assessment, plus the set's subject (the commit,
    KSI signal and phase it covered), checked against the stated ones."""
    sp, bp = Path(set_path), Path(bundle_path)
    for f, what in ((sp, "assessment set"), (bp, "assessment bundle")):
        if not f.is_file() or f.stat().st_size == 0:
            _fail(f"the {what} {f} is missing: the deploy depends on the assessor's signed record")
    ident = load_keyless_identity(identity_path)
    if not (verifier or cosign_verify)(sp, bp, ident):
        _fail(f"{sp.name} signature does not verify against the pinned assessor identity")
    try:
        doc = json.loads(sp.read_text())
    except json.JSONDecodeError:
        _fail(f"{sp.name} is not valid JSON")
    if not isinstance(doc, dict) or doc.get("assessment_type") != SET_TYPE or doc.get("schema_version") != "1":
        _fail(f"{sp.name} is not a {SET_TYPE} set, schema version 1")
    subject = bind(doc, sp.name, expect_commit, expect_signal_id)
    a = doc.get("assessor") or {}
    if a.get("organization") != ident["assessor"] or a.get("key_id") != ident["key_id"]:
        _fail(f"{sp.name} names {a.get('organization')!r}, not the pinned assessor identity")
    recs = doc.get("records")
    if not isinstance(recs, list) or not recs:
        _fail(f"{sp.name} holds no records")
    seen, out = set(), []
    for i, rec in enumerate(recs):
        name = f"{sp.name} record {i}"
        _shape(rec, name)
        ra, sig = rec["assessor"], rec["signature"]
        if ra["organization"] != ident["assessor"] or ra["key_id"] != ident["key_id"]:
            _fail(f"{name} names {ra['organization']!r} / {ra['key_id']!r}, not the pinned assessor identity")
        if sig["algorithm"] != SET_ALGORITHM or sig.get("signed_set") != sp.name:
            _fail(f"{name} is not bound to the signed set {sp.name}")
        if sig["value"] != hashlib.sha256(canonical(rec)).hexdigest():
            _fail(f"{name} ({rec['record_id']}) differs from the record the assessor signed")
        if rec["record_id"] in seen:
            _fail(f"record_id {rec['record_id']} appears twice")
        seen.add(rec["record_id"])
        out.append(rec)
    if not any(r["kind"] == "summary" and "rule_id" not in r for r in out):
        _fail(f"{sp.name} has no overall summary (IVV-IAS-OSA)")
    return out, subject


def overall_summary(records):
    """The assessor's overall summary record (IVV-IAS-OSA), carried verbatim, or
    None. The CPO quotes it (CPO-CSO-OSA)."""
    sums = [r for r in records if r["kind"] == "summary" and "rule_id" not in r]
    if len(sums) > 1:
        _fail("more than one overall summary record")
    return _carried(sums[0]) if sums else None


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
    ap.add_argument("--assessment", default=None, help="a keyless-signed assessment set")
    ap.add_argument("--assessment-bundle", default=None)
    # The state the set must cover: an assessment of any other commit or KSI
    # signal is refused, however validly signed.
    ap.add_argument("--assessment-commit", default=None)
    ap.add_argument("--assessment-signal-id", default=None)
    a = ap.parse_args(argv)
    if a.assessment:
        records = load_assessment(a.assessment, a.assessment_bundle or a.assessment[:-5] + ".bundle", a.identity,
                                  expect_commit=a.assessment_commit, expect_signal_id=a.assessment_signal_id)
    else:
        records = load_records(a.records, a.identity)
    if a.sdr:
        verify_output(json.loads(Path(a.sdr).read_text()), records)
    print(f"assessor records: {len(records)} verified" + ("; SDR carries them verbatim" if a.sdr else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
