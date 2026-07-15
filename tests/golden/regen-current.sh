#!/bin/bash
# Regenerate tests/golden/current/ — the post-refactor golden outputs.
#
# Every fixture is evaluated exactly as the gate evaluates it: one direct
# `opa eval --strict-builtin-errors` against infrastructure/policy (no
# pre-processing of any kind). Run from the repo root with the pinned OPA
# (>= 1.x) on PATH; commit the diff when a behavioral change is intentional.
# The frozen pre-refactor snapshot in tests/golden/baseline/ is never
# regenerated.
set -euo pipefail

cd "$(dirname "$0")/../.."
OUT=tests/golden/current
mkdir -p "$OUT"

evaluate() { # <input-file> <query>
    opa eval --strict-builtin-errors \
        -d infrastructure/policy \
        -i "$1" "$2" \
        | jq --sort-keys '.result[0].expressions[0].value'
}

for f in tests/fixtures/plans/*.json; do
    name=$(basename "$f" .json)
    jq -n \
        --arg fixture "tests/fixtures/plans/$name.json" \
        --argjson report "$(evaluate "$f" data.terraform.compliance.compliance_report)" \
        --argjson resources "$(evaluate "$f" data.terraform.compliance.resource_reports)" \
        '{fixture: $fixture, harness: "direct opa eval of the raw fixture (strict builtin errors)", report: $report, resource_reports: $resources}' \
        > "$OUT/plan-$name.json"
    echo "plan-$name"
done

for f in tests/fixtures/resources/*.json; do
    name=$(basename "$f" .json)
    jq -n \
        --arg fixture "tests/fixtures/resources/$name.json" \
        --argjson report "$(evaluate "$f" data.terraform.compliance.compliance_report)" \
        '{fixture: $fixture, harness: "direct opa eval (runtime Lambda input shape)", report: $report}' \
        > "$OUT/resource-$name.json"
    echo "resource-$name"
done

for f in tests/fixtures/a11y/*.json; do
    name=$(basename "$f" .json)
    jq -n \
        --arg fixture "tests/fixtures/a11y/$name.json" \
        --argjson report "$(evaluate "$f" data.terraform.compliance.compliance_report)" \
        --argjson pages "$(evaluate "$f" data.terraform.compliance.page_reports)" \
        '{fixture: $fixture, harness: "direct opa eval of scanner facts", report: $report, page_reports: $pages}' \
        > "$OUT/a11y-$name.json"
    echo "a11y-$name"
done

echo "current goldens regenerated in $OUT"
