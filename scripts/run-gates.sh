#!/usr/bin/env bash
# The detection gate and the VDR build, with the inputs every workflow passes.
#
# Usage (from infrastructure/):
#   run-gates.sh detection
#   run-gates.sh vdr [EXTRA BUILDER ARGS...]
#
# The deploy and the nightly gather the same detection inputs under the same
# names, so the argument lists live here once. The per-tree Grype files come
# from the app manifest (APPS_MANIFEST, default data/apps.json), the same list
# scripts/scan-sca.sh scanned. Each workflow adds only what differs: the deploy
# passes its OPA results to the VDR, the nightly the published inventory.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="${APPS_MANIFEST:-$here/../data/apps.json}"

if [ "$#" -lt 1 ]; then
  echo "usage: $0 detection | vdr [args...]" >&2
  exit 2
fi
cmd="$1"
shift

case "$cmd" in
  detection)
    [ "$#" -eq 0 ] || { echo "run-gates: detection takes no arguments" >&2; exit 2; }
    listed=$(python3 -I "$here/_apps.py" --manifest "$manifest" grype) || exit 1
    mapfile -t grype_files <<< "$listed"
    [ "${#grype_files[@]}" -gt 0 ] || { echo "::error::the app manifest lists no scan trees" >&2; exit 1; }
    python3 "$here/detection-gate.py" \
      --kev kev-catalog.json --epss epss-scores.csv.gz \
      --grype "${grype_files[@]}" \
      --dependabot dependabot-alerts.json --previous-vdr previous-vdr-report.json \
      --checkov checkov-results.sarif --tfsec tfsec-results.json \
      --output detection.json
    ;;
  vdr)
    python3 "$here/build-vdr-report.py" \
      --checkov checkov-results.sarif \
      --tfsec tfsec-results.json \
      --checkov-yaml ../.checkov.yaml \
      --previous-vdr previous-vdr-report.json \
      --dependabot dependabot-alerts.json \
      --grype grype.json \
      --zap zap-report.json \
      --kev kev-catalog.json \
      --epss epss-scores.csv.gz \
      --detection detection.json \
      --conformance conformance-results.json \
      --runtime-signal ksi-signal-runtime.json \
      --output vdr-report.json \
      "$@"
    ;;
  *)
    echo "run-gates: unknown command $cmd" >&2
    exit 2
    ;;
esac
