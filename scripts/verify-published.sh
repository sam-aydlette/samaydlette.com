#!/usr/bin/env bash
# =============================================================================
# verify-published.sh — reproduce samaydlette.com's compliance verification
# from the public internet, with NO repo secrets and NO AWS access.
# =============================================================================
# This is the reciprocity handshake: a third party should be able to take the
# evidence we publish under /.well-known/ and independently reach the same
# verdict we do. Run it from a clone of this public repo:
#
#     scripts/verify-published.sh                       # verify the live site
#     scripts/verify-published.sh https://host/.well-known   # or another base
#
# What it checks, and how independent each layer is:
#   1. Signatures / provenance — FULLY INDEPENDENT. cosign confirms each artifact
#      was produced by THIS repo's pinned GitHub Actions workflow on `main`, via
#      the public Sigstore/Rekor transparency log. The trust roots are Sigstore
#      and a pinned public identity — not us, and not this script.
#   2. Provenance claims — dependency-free. verify-attestation.py reads the
#      in-toto predicate and checks it binds each artifact to the canonical
#      inventory (sha256 + signal_id), the generator, and a commit.
#   3. Cross-artifact consistency — AWS-free. reconcile.py (without --live) checks
#      the published set is internally consistent and bound to one inventory and
#      one commit (invariants b–h).
#
# Honest scope: the live-state invariants — (a) live-resource completeness and
# (i) live-tag reconciliation — require AWS credentials and CANNOT be reproduced
# by an external party. Those are the provider's to run; everything else here a
# stranger can reproduce. This script says so rather than implying otherwise.
# =============================================================================
set -euo pipefail

BASE="${1:-https://samaydlette.com/.well-known}"
IDENTITY='https://github.com/sam-aydlette/samaydlette.com/.github/workflows/deploy-with-opa.yml@refs/heads/main'
ISSUER='https://token.actions.githubusercontent.com'
SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for t in curl cosign jq python3; do
  command -v "$t" >/dev/null 2>&1 || { echo "verify-published: missing required tool: $t" >&2; exit 2; }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0
ok()  { echo "  PASS  $1"; }
bad() { echo "  FAIL  $1"; fail=1; }

echo "== Fetching published evidence from $BASE =="
for f in ksi-signal.json ksi-signal.bundle \
         oscal-ssp.json oscal-ssp.json.intoto.jsonl \
         oscal-poam.json \
         scuba-bundle.json scuba-bundle.bundle \
         vdr-report.json vdr-report.json.intoto.jsonl; do
  if curl -fsS --max-time 30 -o "$work/$f" "$BASE/$f"; then
    echo "  got  $f ($(wc -c < "$work/$f") bytes)"
  else
    echo "verify-published: could not fetch $BASE/$f" >&2; exit 1
  fi
done

echo ""
echo "== 1. Signatures + provenance (independent: Sigstore + pinned workflow identity) =="
if cosign verify-blob --bundle "$work/ksi-signal.bundle" \
     --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
     "$work/ksi-signal.json" >/dev/null 2>&1; then
  ok "ksi-signal.json signed by the pinned workflow on main"
else
  bad "ksi-signal.json signature"
fi

if cosign verify-blob --bundle "$work/scuba-bundle.bundle" \
     --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
     "$work/scuba-bundle.json" >/dev/null 2>&1; then
  ok "scuba-bundle.json signed by the pinned workflow on main"
else
  bad "scuba-bundle.json signature"
fi
for art in oscal-ssp.json vdr-report.json; do
  if cosign verify-blob-attestation --new-bundle-format --type slsaprovenance1 \
       --bundle "$work/$art.intoto.jsonl" \
       --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
       "$work/$art" >/dev/null 2>&1; then
    ok "$art attestation signed by the pinned workflow on main"
  else
    bad "$art attestation signature"
  fi
done

echo ""
echo "== 2. Provenance claims (dependency-free consumer) =="
for art in oscal-ssp.json vdr-report.json; do
  if python3 "$SCRIPTS/verify-attestation.py" \
       --bundle "$work/$art.intoto.jsonl" --artifact "$work/$art" \
       --ksi-signal "$work/ksi-signal.json" >/dev/null 2>&1; then
    ok "$art predicate binds the canonical inventory + commit"
  else
    bad "$art predicate binding"
  fi
done

echo ""
echo "== 3. Cross-artifact consistency (AWS-free reconciliation, invariants b–h) =="
if python3 "$SCRIPTS/reconcile.py" --artifacts-dir "$work" >/dev/null 2>&1; then
  ok "published set reconciles: one inventory, one commit, POA&M/VDR coherent"
else
  bad "cross-artifact reconciliation"
fi

echo ""
echo "== Scope =="
echo "  Independently verified   : signatures + provenance (Sigstore + pinned identity)."
echo "  Verified via public code : cross-artifact reconciliation (this repo, invariants b–h)."
echo "  NOT externally verifiable: live-state invariants (a completeness, i tag-match) need AWS."

echo ""
if [ "$fail" -eq 0 ]; then
  echo "RESULT: PASS — the published evidence is authentic (pinned-workflow-signed) and internally consistent."
else
  echo "RESULT: FAIL — see the FAIL lines above."
  exit 1
fi
