#!/usr/bin/env bash
# Check out and build every app in the manifest that has a build.
#
# Usage (from infrastructure/): build-apps.sh full|deps [MANIFEST]
#
# The manifest (default data/apps.json) names each app's build script and the
# directory its source is checked out to. All checkouts run first, at each app's
# pinned commit (scripts/app-source.sh); then the repository token is dropped,
# and only then does any build run, because builds run third-party install
# scripts. Each build gets the mode: full (the deploy: the package Terraform
# ships) or deps (the nightly: only the dependency trees the SCA scans).
# Fail-closed: a bad manifest, checkout or build stops the run.
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || { [ "$1" != full ] && [ "$1" != deps ]; }; then
  echo "usage: $0 full|deps [MANIFEST]" >&2
  exit 2
fi
mode="$1"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="${2:-$here/../data/apps.json}"

listed=$(python3 -I "$here/_apps.py" --manifest "$manifest" builds) || exit 1
builds=()
[ -z "$listed" ] || mapfile -t builds <<< "$listed"

for line in "${builds[@]}"; do
  IFS=$'\t' read -r app _script src <<< "$line"
  rm -rf -- "$src"
  "$here/app-source.sh" "$app" "$src" "$manifest"
done

# Only the checkouts need the token.
unset APP_REPO_TOKEN

for line in "${builds[@]}"; do
  IFS=$'\t' read -r app script src <<< "$line"
  echo "building $app ($mode)"
  bash "$here/../$script" "$mode" "$src"
done
echo "built ${#builds[@]} app(s) ($mode)"
