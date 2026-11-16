#!/usr/bin/env bash
# The detection gate and the VDR build, with the inputs every workflow passes.
#
# Usage:
#   run-gates.sh stage STAGE        (any directory; `make gates STAGE=...`)
#   run-gates.sh detection          (from infrastructure/)
#   run-gates.sh vdr [EXTRA BUILDER ARGS...]   (from infrastructure/)
#
# `stage` runs every gate the gate register (infrastructure/schemas/gate-modes.json)
# lists for STAGE with a `run` script, from infrastructure/ (where the workflows
# gather gate inputs), the same way locally and in CI. It runs them all, then
# fails if any failed. At pre-apply it skips checks also listed for pr, which the
# jobs the deploy needs already ran on the same commit. Covered checks and checks
# with no `run` yet are named on stderr.
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
  echo "usage: $0 stage STAGE | detection | vdr [args...]" >&2
  exit 2
fi
cmd="$1"
shift

case "$cmd" in
  stage)
    [ "$#" -eq 1 ] || { echo "run-gates: stage takes one argument (pr, pre-apply, post-apply, nightly)" >&2; exit 2; }
    py="${PYTHON:-python3}"
    # The gates run from infrastructure/: make a relative interpreter path absolute first.
    case "$py" in */*) py="$(cd "$(dirname "$py")" && pwd)/$(basename "$py")" ;; esac
    root="$here/.."
    listed=$("$py" "$here/_gates.py" stage "$1") || exit 1
    [ -n "$listed" ] || { echo "::error::the gate register lists no runnable gate for stage $1" >&2; exit 1; }
    failed=()
    while IFS= read -r run; do
      echo "== $run"
      read -r script sub <<< "$run"
      case "$script" in
        *.sh) (cd "$root/infrastructure" && bash "$root/$script" ${sub:+"$sub"}) || failed+=("$run") ;;
        *)    (cd "$root/infrastructure" && "$py" "$root/$script" ${sub:+"$sub"}) || failed+=("$run") ;;
      esac
    done <<< "$listed"
    if [ "${#failed[@]}" -gt 0 ]; then
      echo "::error::stage $1: ${#failed[@]} gate(s) failed: ${failed[*]}" >&2
      exit 1
    fi
    echo "stage $1: all gates passed"
    ;;
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
