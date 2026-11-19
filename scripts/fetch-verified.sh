#!/usr/bin/env bash
# Fetch a published artifact and keep it only when its Sigstore bundle verifies.
#
#   fetch-verified.sh NAME OUT IDENTITY...
#
# Fetches ${SITE_ORIGIN}/.well-known/NAME.json to OUT and NAME.bundle beside it,
# and verifies the bundle against each IDENTITY in turn (a workflow on main); an
# artifact both workflows publish carries whichever signed it last.
#
#   exit 0, OUT present  the artifact verified against one of the identities
#   exit 0, OUT absent   it is not published yet (HTTP 404, and only 404)
#   exit 1               any other status, a missing bundle, or no identity verifies
#
# Fail-closed: an artifact that cannot be verified is not evidence and is never
# left at OUT.
set -uo pipefail

[ "$#" -ge 3 ] || { echo "usage: fetch-verified.sh NAME OUT IDENTITY..." >&2; exit 2; }
name=$1 out=$2
shift 2
origin="${SITE_ORIGIN:-https://samaydlette.com}"
issuer="${CERT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
bundle="$out.bundle"
rm -f "$out" "$bundle"

code=$(curl -sS --retry 3 --retry-delay 5 -o "$out" -w '%{http_code}' "$origin/.well-known/$name.json") || code=000
if [ "$code" = 404 ]; then
  rm -f "$out"
  echo "No published $name yet."
  exit 0
fi
if [ "$code" != 200 ]; then
  rm -f "$out"
  echo "::error::fetching the published $name returned HTTP $code (fail-closed)" >&2
  exit 1
fi
if ! curl -fsS --retry 3 --retry-delay 5 -o "$bundle" "$origin/.well-known/$name.bundle"; then
  rm -f "$out" "$bundle"
  echo "::error::the published $name has no signature bundle (fail-closed)" >&2
  exit 1
fi
for id in "$@"; do
  if cosign verify-blob --bundle "$bundle" --certificate-identity "$id" \
      --certificate-oidc-issuer "$issuer" "$out" >/dev/null 2>&1; then
    rm -f "$bundle"
    echo "Published $name verified (signed by $id)."
    exit 0
  fi
done
rm -f "$out" "$bundle"
echo "::error::the published $name does not verify against its publishers (fail-closed)" >&2
exit 1
