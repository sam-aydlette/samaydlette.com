#!/usr/bin/env bash
# The gates and the VDR build, with the inputs every workflow passes.
#
# Usage:
#   run-gates.sh stage STAGE        (any directory; `make gates STAGE=...`)
#   run-gates.sh detection          (from infrastructure/)
#   run-gates.sh vdr [EXTRA BUILDER ARGS...]   (from infrastructure/)
#   run-gates.sh ksi | vuln | claims | reconcile | freshness   (from infrastructure/)
#   run-gates.sh redaction [FILES...]   (from infrastructure/)
#   run-gates.sh fedrampid [FILES...]   (from infrastructure/)
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
#
# ksi, vuln, claims and reconcile are the deploy's post-apply gates over the
# artifacts it built; redaction is its pre-publish gate over exactly what it
# uploads. reconcile expects the commit in EXPECT_COMMIT (the deploy passes its
# own), or HEAD locally. They run under PYTHON (default python3). redaction
# scans FILES when given (the nightly's own set), else what the deploy uploads.
# fedrampid is a pre-publish and nightly gate: every certification-data report
# built here carries the offering's FedRAMP ID (CDS-CSO-FID).
# freshness is the nightly's: the served VDR is the one this run built.
#
# When GATE_RESULTS_FILE is set, each gate run appends {run, result, at} to it
# as one JSON line; scripts/_gates.py status reads it into per-check results
# for the status beacon.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="${APPS_MANIFEST:-$here/../data/apps.json}"

if [ "$#" -lt 1 ]; then
  echo "usage: $0 stage STAGE | detection | vdr [args...] | ksi | vuln | claims | reconcile | redaction [files...] | fedrampid | freshness" >&2
  exit 2
fi
cmd="$1"
shift

# A gate's result, for the status beacon. The run is a fixed string from this
# script or the register, never user input.
record() {
  [ -n "${GATE_RESULTS_FILE:-}" ] || return 0
  local result=fail
  [ "$2" -eq 0 ] && result=pass
  printf '{"run": "%s", "result": "%s", "at": "%s"}\n' "$1" "$result" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >> "$GATE_RESULTS_FILE"
}
case "$cmd" in
  detection|ksi|vuln|claims|reconcile|redaction|fedrampid|freshness)
    trap 'record "scripts/run-gates.sh $cmd" $?' EXIT ;;
esac

case "$cmd" in
  stage)
    [ "$#" -eq 1 ] || { echo "run-gates: stage takes one argument (pr, pre-apply, post-apply, pre-publish, nightly)" >&2; exit 2; }
    py="${PYTHON:-python3}"
    # The gates run from infrastructure/: make a relative interpreter path absolute first.
    case "$py" in */*) py="$(cd "$(dirname "$py")" && pwd)/$(basename "$py")" ;; esac
    export PYTHON="$py"
    root="$here/.."
    listed=$("$py" "$here/_gates.py" stage "$1") || exit 1
    [ -n "$listed" ] || { echo "::error::the gate register lists no runnable gate for stage $1" >&2; exit 1; }
    failed=()
    while IFS= read -r run; do
      echo "== $run"
      read -r script sub <<< "$run"
      case "$script" in
        *.sh) (cd "$root/infrastructure" && bash "$root/$script" ${sub:+"$sub"}) || failed+=("$run") ;;
        *)    rc=0; (cd "$root/infrastructure" && "$py" "$root/$script" ${sub:+"$sub"}) || rc=$?
              record "$run" "$rc"; [ "$rc" -eq 0 ] || failed+=("$run") ;;
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
      --inspector inspector-findings.json --access-analyzer access-analyzer-findings.json \
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
      --inspector inspector-findings.json \
      --access-analyzer access-analyzer-findings.json \
      --kev kev-catalog.json \
      --epss epss-scores.csv.gz \
      --detection detection.json \
      --conformance conformance-results.json \
      --runtime-signal ksi-signal-runtime.json \
      --output vdr-report.json \
      "$@"
    ;;
  ksi)
    "${PYTHON:-python3}" "$here/validate-ksi-signal.py" ksi-signal.json
    ;;
  vuln)
    "${PYTHON:-python3}" "$here/vuln-gate.py" --vdr vdr-report.json --register "$here/../data/decisions.json"
    ;;
  claims)
    "${PYTHON:-python3}" "$here/_frr.py" --claims --ksi-short ksi-short.json
    ;;
  reconcile)
    commit="${EXPECT_COMMIT:-$(git rev-parse HEAD)}"
    "${PYTHON:-python3}" "$here/reconcile.py" --artifacts-dir . --live --expect-commit "$commit" \
      --report reconcile-report.json
    ;;
  redaction)
    if [ "$#" -gt 0 ]; then
      "${PYTHON:-python3}" "$here/check-published-redaction.py" "$@"
    else
      # Exactly the files the deploy's upload step publishes, from the same governed list.
      files=$("${PYTHON:-python3}" "$here/published-set.py" scan --by deploy)
      # shellcheck disable=SC2086  # a word list by design
      "${PYTHON:-python3}" "$here/check-published-redaction.py" $files
    fi
    ;;
  fedrampid)
    "${PYTHON:-python3}" "$here/check-fedramp-id.py" "$@"
    ;;
  freshness)
    built=$(sha256sum vdr-report.json | awk '{print $1}')
    "${PYTHON:-python3}" "$here/check-evidence-freshness.py" \
      --url "${SITE_ORIGIN:-https://samaydlette.com}/.well-known/vdr-report.json" \
      --expect-sha256 "$built" --retries 12 --retry-delay 20
    ;;
  *)
    echo "run-gates: unknown command $cmd" >&2
    exit 2
    ;;
esac
