#!/usr/bin/env python3
"""The files one publisher puts under /.well-known/, from the governed config.

infrastructure/schemas/freshness-config.json lists every published artifact.
Its `published_by` says which workflow uploads each one, `signature`,
`markdown` and `json_schema` name the files published beside it, and
`optional` marks the one artifact a run may not produce (the operator-run
corroboration). This script turns that list into what a workflow acts on, so
the redaction gate, the upload and the round-trip check cannot drift apart:

    published-set.py scan   --by deploy   # files the redaction gate scans
    published-set.py upload --by deploy   # file, key, content type, cache control
    published-set.py served --by deploy   # file, key: every object to compare after upload
    published-set.py signed               # artifact, signature, kind, signers, required|optional

Columns are tab-separated. `upload` leaves out the in-toto attestations, which
the attest step publishes after the upload; `served` includes them, because the
round-trip check runs after both. `scan` leaves out signatures, attestations and
the compiled policy archive, which are not our text (see
check-published-redaction.py).

`signed` is for a verifier rather than a publisher: every artifact a workflow
signs, with its Sigstore bundle (kind `bundle`) or in-toto attestation (kind
`dsse`), and the workflows whose identity may have signed it, from
`published_by`. An artifact both workflows publish carries whichever signed it
last. The runtime signal is left out: the runtime Lambda signs it with a KMS
key, which is checked separately.

Paths are relative to --root (default: the working directory), where the
workflow built the artifacts. A required file that is absent fails the run
(exit 1) and names every missing file; an absent optional artifact is left out
along with its companions. Stdlib only, fail-closed.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _freshness  # noqa: E402

ATTESTATION = ".intoto.jsonl"
NOT_SCANNED = (".bundle", ".tar.gz", ATTESTATION)
SHORT_CACHE = "public, max-age=300"
SCHEMA_CACHE = "public, max-age=3600"
SIGNERS = ("deploy", "nightly")


def content_type(name):
    if name.endswith(".schema.json"):
        return "application/schema+json"
    if name.endswith((".json", ".bundle", ATTESTATION)):
        return "application/json"
    if name.endswith(".md"):
        return "text/markdown; charset=utf-8"
    if name.endswith(".csv"):
        return "text/csv"
    if name.endswith(".tar.gz"):
        return "application/gzip"
    raise SystemExit(f"::error::published-set: no content type for {name} (fail-closed)")


def objects(cfg, by):
    """[(artifact, local_file, key)] in config order, for every file `by` publishes."""
    out = []
    for a in cfg["artifacts"]:
        if by not in a["published_by"]:
            continue
        name = a["path"].rsplit("/", 1)[-1]
        files = [(name, a["path"])]
        if "signature" in a:
            files.append((a["signature"].rsplit("/", 1)[-1], a["signature"]))
        if a.get("markdown"):
            md = name.removesuffix(".json") + ".md"
            files.append((md, f".well-known/{md}"))
        if "json_schema" in a:
            files.append((a["json_schema"], ".well-known/" + a["json_schema"].rsplit("/", 1)[-1]))
        out += [(a, f, k) for f, k in files]
    return out


def signed(cfg):
    """[(artifact, signature, kind, signers, optional)] for every workflow-signed artifact."""
    out = []
    for a in cfg["artifacts"]:
        signers = [s for s in SIGNERS if s in a["published_by"]]
        if not a["signed"] or not signers:
            continue
        name = a["path"].rsplit("/", 1)[-1]
        if name.endswith(ATTESTATION):
            out.append((name.removesuffix(ATTESTATION), name, "dsse", signers, bool(a.get("optional"))))
        elif "signature" in a:
            out.append((name, a["signature"].rsplit("/", 1)[-1], "bundle", signers, bool(a.get("optional"))))
        else:
            raise SystemExit(f"::error::published-set: {a['path']} is signed but names no signature (fail-closed)")
    return out


def select(cfg, by, mode, root):
    rows, missing = [], []
    for a, f, key in objects(cfg, by):
        name = a["path"].rsplit("/", 1)[-1]
        if a.get("optional") and not (root / name).is_file():
            continue
        if mode == "upload" and name.endswith(ATTESTATION):
            continue
        if mode == "scan" and f.endswith(NOT_SCANNED):
            continue
        if not (root / f).is_file():
            missing.append(f)
            continue
        rows.append((f, key))
    if missing:
        raise SystemExit(f"::error::published-set: {by} publishes files that were not built: {missing} (fail-closed)")
    if not rows:
        raise SystemExit(f"::error::published-set: nothing for {by} to {mode} under {root} (fail-closed)")
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mode", choices=("scan", "upload", "served", "signed"))
    ap.add_argument("--by", choices=sorted(_freshness.PUBLISHERS))
    ap.add_argument("--root", default=".", help="directory the artifacts were built in")
    ap.add_argument("--config", default=None, help="governed freshness config")
    args = ap.parse_args(argv)
    cfg = _freshness.load_freshness_config(args.config)
    if args.mode == "signed":
        for art, sig, kind, signers, optional in signed(cfg):
            print(f"{art}\t{sig}\t{kind}\t{','.join(signers)}\t{'optional' if optional else 'required'}")
        return 0
    if not args.by:
        ap.error(f"{args.mode} needs --by")
    rows = select(cfg, args.by, args.mode, Path(args.root))
    for f, key in rows:
        if args.mode == "scan":
            print(f)
        elif args.mode == "upload":
            cache = SCHEMA_CACHE if f.endswith(".schema.json") else SHORT_CACHE
            print(f"{f}\t{key}\t{content_type(f)}\t{cache}")
        else:
            print(f"{f}\t{key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
