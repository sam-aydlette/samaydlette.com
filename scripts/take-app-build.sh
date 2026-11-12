#!/usr/bin/env bash
# Take the expected files out of an app-build artifact.
#
# Usage (from infrastructure/): take-app-build.sh full|deps DIR [MANIFEST]
#
# The app-build artifact (.github/workflows/app-build.yml) comes from a job that
# ran third-party code, so the caller downloads it into DIR and takes only the
# names this repository's manifest (default data/apps.json) expects:
#   full  each built app's package (package_path), which must be there, and
#   both  each scan tree's SBOM and Grype result, plus the merged grype.json.
# A missing scan file stays missing, never replaced: the detection gate fails
# on it. Anything else in DIR, and DIR itself, is deleted, so nothing in the
# artifact can replace a file the caller built or reads.
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ] || { [ "$1" != full ] && [ "$1" != deps ]; }; then
  echo "usage: $0 full|deps DIR [MANIFEST]" >&2
  exit 2
fi
mode="$1"
dir="$2"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="${3:-$here/../data/apps.json}"
[ -d "$dir" ] && [ ! -L "$dir" ] || { echo "take-app-build: $dir is not a directory" >&2; exit 1; }

# The names come from the validated manifest, so each is a plain file name.
packages=$(python3 -I "$here/_apps.py" --manifest "$manifest" packages) || exit 1
scans=$(python3 -I "$here/_apps.py" --manifest "$manifest" trees | cut -f3,4 | tr '\t' '\n') || exit 1

present() { [ -f "$dir/$1" ] && [ ! -L "$dir/$1" ]; }

if [ "$mode" = full ]; then
  for f in $packages; do
    present "$f" || { echo "::error::the app build has no $f" >&2; exit 1; }
    cp -- "$dir/$f" "$f"
  done
fi
for f in $scans grype.json; do
  if present "$f"; then
    cp -- "$dir/$f" "$f"
  else
    rm -f -- "$f"
    echo "::warning::$f is missing from the app build; the detection gate will fail"
  fi
done
rm -rf -- "$dir"
echo "took the expected files from the app build ($mode)"
