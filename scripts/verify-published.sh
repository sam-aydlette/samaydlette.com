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
#   1. Signatures / provenance — FULLY INDEPENDENT. cosign confirms every signed
#      artifact in the governed publish list was produced by THIS repo's pinned
#      GitHub Actions workflow on `main` (the one that publishes it), via
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
# Every artifact a workflow signs, with its signature or attestation and the
# workflows that may have signed it: the governed list the deploy publishes
# from (infrastructure/schemas/freshness-config.json, via published-set.py).
signed=$(python3 "$SCRIPTS/published-set.py" signed) \
  || { echo "verify-published: could not read the governed publish list" >&2; exit 2; }
skipped=" "
while IFS=$'\t' read -r art sig _kind _signers need; do
  for f in "$art" "$sig"; do
    [ -f "$work/$f" ] && continue
    if curl -fsS --max-time 30 -o "$work/$f" "$BASE/$f" </dev/null; then
      echo "  got  $f ($(wc -c < "$work/$f") bytes)"
    elif [ "$need" = optional ]; then
      rm -f "$work/$art" "$work/$sig"; skipped="$skipped$art "; break
    else
      echo "verify-published: could not fetch $BASE/$f" >&2; exit 1
    fi
  done
done <<< "$signed"

echo ""
echo "== 1. Signatures + provenance (independent: Sigstore + pinned workflow identity) =="
# Each artifact must verify under an identity of a workflow that publishes it.
# The deploy re-signs the VDR family that the nightly refreshes, so those
# accept either workflow; everything else accepts exactly one. The nightly's
# beacon earns KSI credit, so only the nightly may sign it.
while IFS=$'\t' read -r art sig kind signers _need; do
  case "$skipped" in *" $art "*) echo "  SKIP  $art (not published)"; continue ;; esac
  ids=()
  for s in ${signers//,/ }; do
    case "$s" in
      deploy) ids+=("$IDENTITY") ;;
      nightly) ids+=("$NIGHTLY_IDENTITY") ;;
    esac
  done
  who="the pinned ${signers//,/ or } workflow on main"
  if [ "${#ids[@]}" -eq 0 ]; then
    bad "$art names no workflow that may sign it"
  elif [ "$kind" = dsse ]; then
    if verify_attestation_any_identity "$work/$sig" "$work/$art" "${ids[@]}" </dev/null; then
      ok "$art attestation signed by $who"
    else
      bad "$art attestation signature"
    fi
  elif verify_blob_any_identity "$work/$sig" "$work/$art" "${ids[@]}" </dev/null; then
    ok "$art signed by $who"
  else
    bad "$art signature"
  fi
done <<< "$signed"

# The CR26 record (SDR, CPO) and the trust center's own data: the generated
# boundary map, the gate's report and the trust center itself, each bound to
# the published inventory. The operator-run corroboration names the inventory
# it was compared against, which may be an earlier one, so it is not here.
for art in security-decision-record certification-package-overview boundary-map reconcile-report trust-center; do
  if [ "$(jq -r .ksi_signal_id "$work/$art.json")" = "$(jq -r .signal_id "$work/ksi-signal.json")" ]; then
    ok "$art.json is bound to the published inventory"
  else
    bad "$art.json names a different inventory than ksi-signal.json"
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
