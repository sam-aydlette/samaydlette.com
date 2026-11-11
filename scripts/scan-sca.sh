#!/usr/bin/env bash
# Software composition analysis of every tree in the app manifest.
#
# Usage (from infrastructure/): scan-sca.sh
# The manifest is APPS_MANIFEST, default data/apps.json.
#
# For each tree that scripts/_apps.py lists (each app's, then the platform's),
# Syft writes the tree's CycloneDX SBOM and Grype maps it to vulnerabilities.
# The per-tree Grype files go to the detection gate (scripts/run-gates.sh) and
# are merged into grype.json for the VDR. This step never fails on findings or
# on a failed scan: a missing or invalid result is left missing, never replaced
# by an empty stand-in, and the detection gate fails the run on it.
set -uo pipefail

# The scanner versions, declared once for every workflow. The install.sh each
# version is installed with is fetched from the same tag. Refresh together;
# source: https://github.com/anchore/syft/releases and
# https://github.com/anchore/grype/releases
SYFT_VERSION=v1.45.1
GRYPE_VERSION=v0.114.0

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="${APPS_MANIFEST:-$here/../data/apps.json}"

# Read the manifest before installing anything: a malformed one stops here.
if ! trees=$(python3 -I "$here/_apps.py" --manifest "$manifest" trees); then
  echo "::error::the app manifest is malformed; nothing was scanned"
  exit 1
fi

# In CI, always install the pinned versions and run them by absolute path, so
# nothing else on PATH can stand in for them. Locally, reuse an exact-version
# install already on PATH.
installed() { [ "$("$1" version 2>/dev/null | awk '$1 == "Version:" {print $2}')" = "${2#v}" ]; }
if [ -n "${CI:-}" ]; then
  SYFT=/usr/local/bin/syft GRYPE=/usr/local/bin/grype
else
  SYFT=syft GRYPE=grype
fi
for pair in "syft $SYFT_VERSION $SYFT" "grype $GRYPE_VERSION $GRYPE"; do
  read -r tool version bin <<< "$pair"
  if [ -n "${CI:-}" ] || ! installed "$bin" "$version"; then
    curl -sSfL "https://raw.githubusercontent.com/anchore/${tool}/${version}/install.sh" \
      | sh -s -- -b /usr/local/bin "${version}"
  fi
done
"$SYFT" version && "$GRYPE" version

grype_files=()
while IFS=$'\t' read -r dir cataloger sbom grype_out; do
  rm -f "$sbom" "$grype_out"
  grype_files+=("$grype_out")
  if [ ! -d "$dir" ]; then
    echo "::warning::$dir was not built; $grype_out is missing and the detection gate will fail"
    continue
  fi
  # --select-catalogers keeps each scan to the ecosystem that ships, so build
  # tools' embedded binaries (esbuild's Go runtime, for one) are not catalogued.
  "$SYFT" "dir:$dir" -o "cyclonedx-json=$sbom" --select-catalogers "$cataloger" \
    && "$GRYPE" "sbom:$sbom" -o json > "$grype_out" \
    || { rm -f "$grype_out"; echo "::warning::the scan of $dir did not complete"; }
done <<< "$trees"

# One grype.json (a single .matches[] array) for the VDR. No empty stand-in:
# if any scan is missing or invalid, the merge fails and grype.json is absent.
rm -f grype.json
if jq -s '{matches: (map(.matches) | add)}' "${grype_files[@]}" > grype.json 2>/dev/null; then
  echo "grype.json: $(jq '.matches | length' grype.json) match(es) across ${#grype_files[@]} trees"
else
  rm -f grype.json
  echo "::warning::At least one Grype scan did not complete; the detection gate will fail the run."
fi
exit 0
