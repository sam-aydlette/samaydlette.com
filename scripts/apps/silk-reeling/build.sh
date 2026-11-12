#!/usr/bin/env bash
# Build Silk Reeling from its source, checked out at the manifest's pin.
#
# Usage (from infrastructure/, through scripts/build-apps.sh): build.sh full|deps SRC
#
#   deps  Resolve the dependency trees the SCA scans (data/apps.json): the SPA's
#         npm tree in SRC/frontend and the Lambda's Python tree in _pkg.
#   full  deps, then build the SPA for /silk-reeling/, stage the backend and the
#         SPA into _pkg, and write the deterministic silk-reeling.zip that
#         Terraform deploys (silk_reeling_package_path). Needs
#         SILK_COGNITO_CLIENT_ID, the SPA's public Cognito app client ID.
#
# The deploy runs full and the nightly deps. Both resolve the trees through the
# same commands, so the nightly scans the dependency set production runs. No
# mode needs cloud credentials: the build runs third-party install scripts, so
# it runs where there are none (.github/workflows/app-build.yml).
set -euo pipefail

if [ "$#" -ne 2 ] || { [ "$1" != full ] && [ "$1" != deps ]; }; then
  echo "usage: $0 full|deps SRC" >&2
  exit 2
fi
mode="$1"
src="$2"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -d "$src/frontend" ] && [ -f "$src/backend/requirements-lambda.txt" ] || {
  echo "silk-reeling build: $src is not a Silk Reeling checkout" >&2
  exit 1
}
rm -rf _pkg silk-reeling.zip

( cd "$src/frontend" && npm ci )
mkdir -p _pkg
# Target the Lambda runtime (python3.13 / manylinux x86_64) explicitly so
# numpy/pydantic-core C-extension wheels match the runtime ABI regardless of the
# runner's own Python, and the scanned wheel set is the runtime's, not the
# runner's. --no-compile: .pyc files record build-time timestamps, so they
# changed the package hash every run; the runtime compiles what it imports.
python3 -m pip install --quiet --no-compile --target _pkg \
  --platform manylinux2014_x86_64 --python-version 3.13 \
  --implementation cp --only-binary=:all: \
  -r "$src/backend/requirements-lambda.txt"

if [ "$mode" = deps ]; then
  echo "silk-reeling: dependency trees resolved (no package built)"
  exit 0
fi

# The Cognito config wires the SPA's Hosted-UI login flow at build time. The
# client ID is read by the caller (the deploy's read-only plan job); without it
# the SPA's sign-in could not work, so stop rather than build it.
SILK_CLIENT_ID="${SILK_COGNITO_CLIENT_ID:-}"
if ! [[ "$SILK_CLIENT_ID" =~ ^[A-Za-z0-9_+]{1,128}$ ]]; then
  echo "silk-reeling build: SILK_COGNITO_CLIENT_ID is missing or malformed" >&2
  exit 1
fi
( cd "$src/frontend" && \
  VITE_API_BASE=/silk-reeling \
  VITE_COGNITO_DOMAIN="samaydlette-com-silk-reeling.auth.us-east-2.amazoncognito.com" \
  VITE_COGNITO_CLIENT_ID="$SILK_CLIENT_ID" \
  VITE_COGNITO_REDIRECT_URI="https://samaydlette.com/silk-reeling/" \
  npm run build -- --base=/silk-reeling/ )
cp -r "$src/backend" _pkg/backend
cp "$src/lambda_handler.py" _pkg/lambda_handler.py
cp -r "$src/reference_data" _pkg/reference_data
cp -r "$src/frontend/dist" _pkg/spa
rm -rf _pkg/backend/__pycache__
"$here/../../zip-deterministic.sh" _pkg silk-reeling.zip
echo "silk-reeling.zip size: $(du -h silk-reeling.zip | cut -f1)"
