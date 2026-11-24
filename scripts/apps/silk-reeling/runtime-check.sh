#!/usr/bin/env bash
# Silk Reeling's runtime check: the Cognito settings the running app reports
# must equal what Terraform declared (POAM-038), and its gateway must answer
# nothing without a token. Runs after apply, before any evidence is published,
# through app-hooks.sh.
#
# Usage (from infrastructure/): runtime-check.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# A separate assignment so a failing `terraform output` fails the check (set -e)
# rather than passing an empty string, which means "not deployed".
expected=$(terraform output -raw silk_reeling_auth_config_json)
function=$(terraform output -raw silk_reeling_function_name)
gateway=$(terraform output -raw silk_reeling_api_endpoint)
python3 "$here/../../check-silk-runtime-config.py" "$expected" --function "$function" --gateway "$gateway"
