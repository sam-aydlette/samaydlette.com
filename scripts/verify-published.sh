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
#      one commit, and every VDR finding resolves to the decision register at
#      that commit (invariants b–j).
#
# Honest scope: the live-state invariants — (a) live-resource completeness and
# (i) live-tag reconciliation — require AWS credentials and CANNOT be reproduced
# by an external party. Those are the provider's to run; everything else here a
# stranger can reproduce. This script says so rather than implying otherwise.
# =============================================================================
set -euo pipefail

BASE="${1:-https://samaydlette.com/.well-known}"
IDENTITY='https://github.com/sam-aydlette/samaydlette.com/.github/workflows/deploy-with-opa.yml@refs/heads/main'
# The VDR — and only the VDR — has a second legitimate publisher. The deploy
# workflow cannot run unattended (it applies Terraform and is bound to a
# reviewed environment), so the nightly refresh that keeps the vulnerability
# report inside its 24-hour freshness policy runs as its own workflow and signs
# with its own identity. A verifier that pinned one identity would report the
# published evidence as unauthentic for most of its life, which would be a
# verifier bug, not a finding.
#
# Both identities are workflows in THIS repository, on `main`, so the trust
# claim is unchanged: the evidence was produced by this repo's pinned CI, not by
# a person with a key. Everything else — the canonical inventory, the SDR —
# still verifies against the deploy identity alone.
NIGHTLY_IDENTITY='https://github.com/sam-aydlette/samaydlette.com/.github/workflows/evidence-nightly.yml@refs/heads/main'
ISSUER='https://token.actions.githubusercontent.com'
SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Verify a blob signature against any of the accepted publisher identities.
# Fails only if NO accepted identity validates it.
verify_blob_any_identity() {
  local bundle="$1" artifact="$2"; shift 2
  local id
  for id in "$@"; do
    if cosign verify-blob --bundle "$bundle" \
         --certificate-identity "$id" --certificate-oidc-issuer "$ISSUER" \
         "$artifact" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

verify_attestation_any_identity() {
  local bundle="$1" artifact="$2"; shift 2
  local id
  for id in "$@"; do
    if cosign verify-blob-attestation --new-bundle-format --type slsaprovenance1 \
         --bundle "$bundle" \
         --certificate-identity "$id" --certificate-oidc-issuer "$ISSUER" \
         "$artifact" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

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
         security-decision-record.json security-decision-record.bundle \
         security-decision-record.json.intoto.jsonl \
         certification-package-overview.json certification-package-overview.bundle \
         vdr-report.json vdr-report.json.intoto.jsonl \
         vdr-status.json vdr-status.bundle \
         vdr-detail-report.json vdr-detail-report.bundle \
         vdr-accepted-vulnerabilities.json vdr-accepted-vulnerabilities.bundle \
         vdr-history.json vdr-history.bundle \
         boundary-map.json boundary-map.bundle \
         reconcile-report.json reconcile-report.bundle \
         trust-center.json trust-center.bundle; do
  if curl -fsS --max-time 30 -o "$work/$f" "$BASE/$f"; then
    echo "  got  $f ($(wc -c < "$work/$f") bytes)"
  else
    echo "verify-published: could not fetch $BASE/$f" >&2; exit 1
  fi
done

echo ""
echo "== 1. Signatures + provenance (independent: Sigstore + pinned workflow identity) =="
if verify_blob_any_identity "$work/ksi-signal.bundle" "$work/ksi-signal.json" "$IDENTITY"; then
  ok "ksi-signal.json signed by the pinned workflow on main"
else
  bad "ksi-signal.json signature"
fi

if verify_attestation_any_identity "$work/security-decision-record.json.intoto.jsonl" \
     "$work/security-decision-record.json" "$IDENTITY"; then
  ok "security-decision-record.json attestation signed by the pinned workflow on main"
else
  bad "security-decision-record.json attestation signature"
fi

# The CR26 record (SDR, CPO) and the trust center's own data: the generated
# boundary map, the gate's report and the trust center itself.
for art in security-decision-record certification-package-overview boundary-map reconcile-report trust-center; do
  if verify_blob_any_identity "$work/$art.bundle" "$work/$art.json" "$IDENTITY"; then
    ok "$art.json signed by the pinned workflow on main"
  else
    bad "$art.json signature"
  fi
  if [ "$(jq -r .ksi_signal_id "$work/$art.json")" = "$(jq -r .signal_id "$work/ksi-signal.json")" ]; then
    ok "$art.json is bound to the published inventory"
  else
    bad "$art.json names a different inventory than ksi-signal.json"
  fi
done

# The independent corroboration (RAMPART on TAP) is optional, run by the operator
# and published as committed. It names the inventory it was compared against,
# which may be an earlier one, so only its signature is checked here.
if curl -fsS --max-time 30 -o "$work/boundary-corroboration.json" "$BASE/boundary-corroboration.json" \
   && curl -fsS --max-time 30 -o "$work/boundary-corroboration.bundle" "$BASE/boundary-corroboration.bundle"; then
  if verify_blob_any_identity "$work/boundary-corroboration.bundle" "$work/boundary-corroboration.json" "$IDENTITY"; then
    ok "boundary-corroboration.json signed by the pinned workflow on main"
  else
    bad "boundary-corroboration.json signature"
  fi
else
  echo "  SKIP  boundary-corroboration.json (not published)"
fi

# The nightly beacon earns KSI credit, so only the nightly's identity may sign it.
if verify_blob_any_identity "$work/vdr-status.bundle" "$work/vdr-status.json" "$NIGHTLY_IDENTITY"; then
  ok "vdr-status.json signed by the pinned nightly workflow on main"
else
  bad "vdr-status.json signature"
fi

# The VDR is refreshed nightly, so either publisher identity is accepted here.
if verify_attestation_any_identity "$work/vdr-report.json.intoto.jsonl" "$work/vdr-report.json" \
     "$IDENTITY" "$NIGHTLY_IDENTITY"; then
  ok "vdr-report.json attestation signed by a pinned workflow on main"
else
  bad "vdr-report.json attestation signature"
fi

# The CR26 vulnerability reports are rebuilt with the VDR, so either identity too.
for art in vdr-detail-report vdr-accepted-vulnerabilities vdr-history; do
  if verify_blob_any_identity "$work/$art.bundle" "$work/$art.json" "$IDENTITY" "$NIGHTLY_IDENTITY"; then
    ok "$art.json signed by a pinned workflow on main"
  else
    bad "$art.json signature"
  fi
done

echo ""
echo "== 2. Provenance claims (dependency-free consumer) =="
for art in security-decision-record.json vdr-report.json; do
  if python3 "$SCRIPTS/verify-attestation.py" \
       --bundle "$work/$art.intoto.jsonl" --artifact "$work/$art" \
       --ksi-signal "$work/ksi-signal.json" >/dev/null 2>&1; then
    ok "$art predicate binds the canonical inventory + commit"
  else
    bad "$art predicate binding"
  fi
done

echo ""
echo "== 3. Cross-artifact consistency (AWS-free reconciliation, invariants b–j and l) =="
# The decision register is not a published artifact; it is data/decisions.json
# at the commit the (signature-verified) inventory names. Read it from this
# clone at that commit, never from the working copy, which may be any version.
commit=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["provenance"]["source"]["commit"])' "$work/ksi-signal.json" 2>/dev/null || true)
if ! printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}$'; then
  bad "the published inventory names no source commit"
elif ! git -C "$SCRIPTS/.." show "$commit:data/decisions.json" > "$work/decisions.json" 2>/dev/null; then
  bad "decision register at the published commit $commit is not in this clone (git fetch origin main)"
elif python3 "$SCRIPTS/reconcile.py" --artifacts-dir "$work" --decisions "$work/decisions.json" >/dev/null 2>&1; then
  ok "published set reconciles: one inventory, one commit, VDR, SDR, CPO and decision register coherent"
else
  bad "cross-artifact reconciliation"
fi

echo ""
echo "== 4. CR26 schema conformance (FedRAMP 2026-06-24 schemas, vendored by sha256) =="
for pair in vdr-detail-report:vdt vdr-accepted-vulnerabilities:avi vdr-history:mrh; do
  art="${pair%%:*}"; kind="${pair##*:}"
  if python3 -c 'import json,sys; sys.path.insert(0,sys.argv[1]); import _fedramp_schema as fs
errs = fs.validate(json.load(open(sys.argv[2])), sys.argv[3])
[print("        " + e) for e in errs[:5]]
sys.exit(1 if errs else 0)' "$SCRIPTS" "$work/$art.json" "$kind"; then
    ok "$art.json validates against its FedRAMP schema and names it"
  else
    bad "$art.json does not validate against its FedRAMP schema"
  fi
done
# The VDT and AVI must describe the published VDR, not an earlier one.
vdr_id=$(jq -r .report_id "$work/vdr-report.json")
for art in vdr-detail-report vdr-accepted-vulnerabilities; do
  if [ "$(jq -r .providerExtensions.vdrReportId "$work/$art.json")" = "$vdr_id" ]; then
    ok "$art.json was built from the published vdr-report.json"
  else
    bad "$art.json names a different VDR report than vdr-report.json"
  fi
done

echo ""
echo "== 5. No AWS account ID in anything published =="
# Every artifact the governed freshness config lists, plus its Markdown
# rendering, fetched fresh and scanned by the same gate the deploy runs before
# it uploads. A listed artifact that is not published (the operator-run
# corroboration, say) is skipped here, never passed.
mkdir -p "$work/scan"
for f in $(python3 -c 'import json,sys
for a in json.load(open(sys.argv[1]))["artifacts"]:
    n = a["path"].rsplit("/", 1)[-1]
    if n.endswith((".intoto.jsonl", ".bundle", ".tar.gz")): continue
    print(n)
    if n.endswith(".json"): print(n[:-5] + ".md")' "$SCRIPTS/../infrastructure/schemas/freshness-config.json"); do
  curl -fsS --max-time 30 -o "$work/scan/$f" "$BASE/$f" 2>/dev/null || rm -f "$work/scan/$f"
done
if python3 "$SCRIPTS/check-published-redaction.py" --root "$work/scan" >/dev/null 2>&1; then
  ok "no published artifact carries an AWS account ID ($(ls "$work/scan" | wc -l) files scanned)"
else
  bad "a published artifact carries an AWS account ID (run scripts/check-published-redaction.py --root on them for the masked detail)"
fi

echo ""
echo "== Scope =="
echo "  Independently verified   : signatures + provenance (Sigstore + pinned identity); CR26 schema conformance; no AWS account ID published."
echo "  Verified via public code : cross-artifact reconciliation (this repo, invariants b–j and l)."
echo "  NOT externally verifiable: live-state invariants (a completeness, i tag-match) need AWS."

echo ""
if [ "$fail" -eq 0 ]; then
  echo "RESULT: PASS — the published evidence is authentic (pinned-workflow-signed) and internally consistent."
else
  echo "RESULT: FAIL — see the FAIL lines above."
  exit 1
fi
