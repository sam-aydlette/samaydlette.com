#!/usr/bin/env python3
"""
build-provenance.py - emit a SLSA v1 in-toto provenance PREDICATE for one
published compliance artifact (Task 14 / S2).

It binds the artifact to:
  - the canonical inventory: ksi-signal.json content sha256 + its signal_id,
  - the generator that produced it (scripts/build-*.py, by content sha256),
  - this commit (git+repo@ref with gitCommit), and
  - the CI run (builder id + invocationId).

The builder.id and commit are taken from build-ksi-signal.py's build_provenance()
so there is ONE source of truth for the pinned identity (derived from
GITHUB_WORKFLOW_REF, the Fulcio SAN - never the spaced display name); that logic
is covered by tests/test_provenance.py.

cosign attest-blob --type slsaprovenance1 --predicate <this output> <artifact>
wraps it into a DSSE-signed in-toto Statement whose subject is the artifact's
own sha256, so the binding cannot be forged by editing this file. This is the
cryptographic form of reconciliation invariant (e) (one-inventory binding) plus
the publish-freshness commit check, consumable by any in-toto-aware verifier.

Honesty note: the builder is this repo's self-hosted GitHub Actions identity
(Sigstore keyless, public Rekor log) - NOT a managed SLSA L3 build service, and
this strengthens the evidence mechanism, not its authorization.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

# Reuse the signal builder's provenance logic so builder.id is single-sourced.
_KSI_PATH = Path(__file__).resolve().parent / "build-ksi-signal.py"
_spec = importlib.util.spec_from_file_location("ksi_builder", _KSI_PATH)
_ksi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ksi)

# Fallback identity if GITHUB_WORKFLOW_REF is absent (e.g. local dry-run).
BUILDER_ID_FALLBACK = (
    "https://github.com/sam-aydlette/samaydlette.com/"
    ".github/workflows/deploy-with-opa.yml@refs/heads/main"
)
BUILD_TYPE = "https://samaydlette.com/buildtypes/compliance-artifact/v1"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_predicate(ksi_signal_path, generator_path):
    ksi_path = Path(ksi_signal_path)
    signal = json.loads(ksi_path.read_text())
    signal_id = signal.get("signal_id", "unknown")
    ksi_hash = sha256_file(ksi_path)

    gen_path = Path(generator_path)
    gen_hash = sha256_file(gen_path)
    gen_name = "scripts/" + gen_path.name

    prov = _ksi.build_provenance() or {}
    builder_id = (prov.get("builder") or {}).get("id") or BUILDER_ID_FALLBACK
    source = prov.get("source") or {}
    commit = source.get("commit") or os.environ.get("GITHUB_SHA", "unknown")
    ref = source.get("ref") or "refs/heads/main"
    repo_url = source.get("repository") or "https://github.com/sam-aydlette/samaydlette.com"
    run_id = os.environ.get("GITHUB_RUN_ID", "unknown")

    return {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "workflow": {
                    "ref": ref,
                    "repository": repo_url,
                    "path": ".github/workflows/deploy-with-opa.yml",
                }
            },
            "internalParameters": {
                "inventory_signal_id": signal_id,
            },
            "resolvedDependencies": [
                {
                    "uri": f"{repo_url.replace('https://', 'git+https://')}@{ref}",
                    "digest": {"gitCommit": commit},
                },
                {
                    "uri": "ksi-signal.json",
                    "digest": {"sha256": ksi_hash},
                    "annotations": {
                        "signal_id": signal_id,
                        "role": "canonical-inventory",
                    },
                },
                {
                    "uri": gen_name,
                    "digest": {"sha256": gen_hash},
                    "annotations": {"role": "generator"},
                },
            ],
        },
        "runDetails": {
            "builder": {"id": builder_id},
            "metadata": {
                "invocationId": f"{repo_url}/actions/runs/{run_id}",
            },
        },
    }


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--ksi-signal",
        default="ksi-signal.json",
        help="Path to the canonical inventory whose content sha256 + signal_id anchor the binding",
    )
    ap.add_argument(
        "--generator",
        required=True,
        help="Path to the scripts/build-*.py that produced the artifact being attested",
    )
    ap.add_argument("--output", default="-", help="Output path for the predicate JSON ('-' = stdout)")
    args = ap.parse_args()

    predicate = build_predicate(args.ksi_signal, args.generator)
    out = json.dumps(predicate, indent=2)
    if args.output == "-":
        print(out)
    else:
        Path(args.output).write_text(out + "\n")
        print(f"provenance predicate written: {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
