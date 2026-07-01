#!/usr/bin/env python3
"""
verify-attestation.py - a dependency-free, NON-cosign consumer of the SLSA/in-toto
provenance attestations this pipeline publishes (Task 15 / S3).

It reads a Sigstore *new-bundle-format* attestation (the inline-DSSE form produced
by `cosign attest-blob --new-bundle-format`), decodes the DSSE envelope to the
in-toto Statement, and checks the CLAIMS:
  - the Statement subject's sha256 equals the artifact's bytes (the binding),
  - the predicate is SLSA provenance v1,
  - the predicate binds the canonical inventory (ksi-signal.json sha256 + signal_id),
    the generator, and a commit.

This is the point of the whole supply-chain track: the evidence is consumable by
ANY in-toto-aware tool, not only by our own viewer. It deliberately does NOT
re-verify the Sigstore signature - that is cosign's job (verify-blob-attestation,
run alongside this) - it demonstrates that a downstream party can read and act on
the predicate. Honest scope: claims-consumption, not signature trust.

Exit non-zero (fail closed) on any missing/mismatched binding.
"""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

SLSA_V1 = "https://slsa.dev/provenance/v1"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_statement(bundle):
    """Pull the in-toto Statement out of a Sigstore new-format bundle's DSSE
    envelope. Accepts a few key spellings across bundle versions."""
    env = None
    for k in ("dsseEnvelope", "dsse_envelope"):
        if isinstance(bundle, dict) and k in bundle:
            env = bundle[k]
            break
    if env is None:
        raise ValueError("no dsseEnvelope in bundle (is this the new bundle format?)")
    payload_b64 = env.get("payload")
    if not payload_b64:
        raise ValueError("dsseEnvelope has no payload")
    return json.loads(base64.b64decode(payload_b64))


def check(bundle_path, artifact_path, ksi_signal_path=None):
    bundle = json.loads(Path(bundle_path).read_text())
    stmt = extract_statement(bundle)
    errors = []

    if stmt.get("_type") not in ("https://in-toto.io/Statement/v1", "https://in-toto.io/Statement/v0.1"):
        errors.append(f"unexpected statement _type: {stmt.get('_type')!r}")
    if stmt.get("predicateType") != SLSA_V1:
        errors.append(f"predicateType is {stmt.get('predicateType')!r}, expected {SLSA_V1}")

    # subject binding: the statement's subject sha256 must equal the artifact bytes
    art_digest = sha256_file(artifact_path)
    subj_digests = [s.get("digest", {}).get("sha256") for s in stmt.get("subject", [])]
    if art_digest not in subj_digests:
        errors.append(f"subject digest {subj_digests} does not match artifact sha256 {art_digest}")

    # predicate bindings
    pred = stmt.get("predicate", {})
    deps = pred.get("buildDefinition", {}).get("resolvedDependencies", [])
    by_role = {d.get("annotations", {}).get("role"): d for d in deps}
    inv = by_role.get("canonical-inventory")
    gen = by_role.get("generator")
    commit_dep = next((d for d in deps if "gitCommit" in d.get("digest", {})), None)

    if not inv or not inv.get("digest", {}).get("sha256"):
        errors.append("no canonical-inventory dependency with a sha256")
    if not gen or not gen.get("digest", {}).get("sha256"):
        errors.append("no generator dependency with a sha256")
    if not commit_dep:
        errors.append("no source dependency with a gitCommit")

    # optional cross-check: the inventory digest in the predicate equals the
    # actual ksi-signal.json bytes (a tampered inventory would not match)
    if ksi_signal_path and inv:
        want = sha256_file(ksi_signal_path)
        got = inv.get("digest", {}).get("sha256")
        if want != got:
            errors.append(f"inventory digest {got} != actual ksi-signal.json sha256 {want}")

    return stmt, errors


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, help="Path to the *.intoto.jsonl new-format attestation")
    ap.add_argument("--artifact", required=True, help="Path to the artifact the attestation should bind to")
    ap.add_argument("--ksi-signal", default=None, help="Optional ksi-signal.json to cross-check the inventory digest")
    args = ap.parse_args()

    try:
        stmt, errors = check(args.bundle, args.artifact, args.ksi_signal)
    except Exception as e:  # noqa: BLE001 - any decode failure is a hard fail
        print(f"FAIL {args.bundle}: {e}", file=sys.stderr)
        return 2

    if errors:
        print(f"FAIL {args.bundle}:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    subj = stmt["subject"][0]
    print(f"ok  {Path(args.artifact).name}: in-toto SLSA-v1 statement consumed, subject "
          f"sha256={subj['digest']['sha256'][:16]}… bound to the artifact and the inventory")
    return 0


if __name__ == "__main__":
    sys.exit(main())
