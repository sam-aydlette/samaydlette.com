#!/usr/bin/env bash
# Run one kind of deploy hook for every app in the manifest that names one.
#
# Usage (from infrastructure/): app-hooks.sh import|runtime-check [MANIFEST]
#
#   import         adopt each app's live resources into an empty Terraform state
#                  (disaster recovery; the deploy runs it only when REBUILD_STATE=true)
#   runtime-check  after apply, ask each running app whether it matches Terraform
#
# The manifest (default data/apps.json) names each app's hooks, so the deploy
# workflow names no app. Fail-closed: a bad manifest or a failed hook stops the
# run, and no later app's hook runs.
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || { [ "$1" != import ] && [ "$1" != runtime-check ]; }; then
  echo "usage: $0 import|runtime-check [MANIFEST]" >&2
  exit 2
fi
kind="$1"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="${2:-$here/../data/apps.json}"

listed=$(python3 -I "$here/_apps.py" --manifest "$manifest" hooks "$kind") || exit 1
hooks=()
[ -z "$listed" ] || mapfile -t hooks <<< "$listed"

for line in "${hooks[@]}"; do
  IFS=$'\t' read -r app script <<< "$line"
  echo "$kind: $app"
  bash "$here/../$script"
done
echo "ran ${#hooks[@]} $kind hook(s)"
