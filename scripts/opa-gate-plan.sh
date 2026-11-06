#!/bin/bash
# =============================================================================
# THE OPA GATE OVER ONE TERRAFORM PLAN
# =============================================================================
# Usage: opa-gate-plan.sh PLAN_JSON OUT_NDJSON
#
# Evaluates a raw `terraform show -json` plan with the policy in
# infrastructure/policy, exactly as the deploy gate does, writes one line per
# resource to OUT_NDJSON (the validations.json entry shape the KSI signal
# emitter reads: kind / resource_type / resource_name / address / compliant /
# violations / policy_version), prints each result, and exits non-zero when
# the policy's overall verdict is anything but compliant.
#
# One script, two plans: scripts/terraform-plan.sh runs it over the per-deploy
# stack, and the deploy's "Plan the trust root" step runs it over the bootstrap
# stack, so the trust root faces the same rules with the same flags.
# =============================================================================

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 PLAN_JSON OUT_NDJSON" >&2
    exit 2
fi
PLAN_JSON=$1
OUT=$2
POLICY_DIR="$(cd "$(dirname "$0")/../infrastructure/policy" && pwd)"

WORK=$(mktemp -d)
trap 'rm -rf "${WORK:?}"' EXIT

# The evaluation timestamp rides in as DATA (data.runtime.evaluated_at), not
# input: the exceptions register checks expiry against it; without it no
# exception is active (fail-safe).
jq -n --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{runtime: {evaluated_at: $now}}' > "$WORK/eval-context.json"

# --strict-builtin-errors: a builtin failure fails the gate loudly instead of
# evaluating to undefined; a broken rule must never look like a passing one.
opa eval --strict-builtin-errors \
    -d "$POLICY_DIR" \
    -d "$WORK/eval-context.json" \
    -i "$PLAN_JSON" \
    "data.terraform.compliance.compliance_report" > "$WORK/opa-report.json"

opa eval --strict-builtin-errors \
    -d "$POLICY_DIR" \
    -d "$WORK/eval-context.json" \
    -i "$PLAN_JSON" \
    "data.terraform.compliance.resource_reports" > "$WORK/opa-resources.json"

jq -c '.result[0].expressions[0].value[]' "$WORK/opa-resources.json" > "$OUT"

while IFS= read -r entry; do
    if [ "$(echo "$entry" | jq -r '.compliant')" = "true" ]; then
        echo "✅ $(echo "$entry" | jq -r '"\(.resource_type).\(.resource_name)"') is compliant"
    else
        echo "❌ INFRASTRUCTURE VIOLATION in $(echo "$entry" | jq -r '"\(.resource_type).\(.resource_name)"'):"
        echo "$entry" | jq -r '.violations[]? | "  - \(.type): \(.message) (Severity: \(.severity))"'
        echo
    fi
done < "$OUT"

# The overall verdict is authoritative: it also covers violations that are not
# attributable to a single resource (e.g. input_error when the plan JSON is
# unreadable). Fail closed on anything other than an explicit "true".
if [ "$(jq -r '.result[0].expressions[0].value.compliant' "$WORK/opa-report.json")" != "true" ]; then
    echo "❌ Overall policy verdict: non-compliant"
    jq -r '.result[0].expressions[0].value.violations[]? | "  - \(.type): \(.message) (Severity: \(.severity))"' \
        "$WORK/opa-report.json"
    exit 1
fi
