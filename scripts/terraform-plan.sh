#!/bin/bash
# =============================================================================
# TERRAFORM PLAN WITH OPA COMPLIANCE CHECK + SECTION 508 ACCESSIBILITY
# =============================================================================
# This script is the deploy-time gate: it produces a Terraform plan and asks
# OPA whether the planned infrastructure (and the website content) complies
# with policy. If anything violates policy, deployment is blocked.
#
# The script is deliberately thin. All interpretation of the plan — iterating
# resource_changes, skipping deletes, joining provider >= 4.x S3
# sub-resources to their buckets — lives in the Rego policy itself
# (infrastructure/policy/), which consumes raw `terraform show -json`
# output directly. The shell's only jobs are:
#   1. Produce the plan JSON.
#   2. Run `opa eval` (once for infrastructure, once per HTML file).
#   3. Convert the policy's per-resource reports into validations.json for
#      the KSI signal emitter (scripts/build-ksi-signal.py).
#   4. Exit non-zero when the policy says non-compliant.
# =============================================================================

set -e # Stop immediately if any command fails

echo "=== Terraform Plan with OPA Compliance Check + Section 508 ==="

# =============================================================================
# CHECK THAT REQUIRED TOOLS ARE INSTALLED
# =============================================================================

if ! command -v opa &> /dev/null; then
    echo "Error: OPA is not installed. Please install OPA first:"
    echo "  curl -L -o opa https://openpolicyagent.org/downloads/v1.18.2/opa_linux_amd64_static"
    echo "  chmod 755 ./opa"
    echo "  sudo mv opa /usr/local/bin"
    exit 1
fi

if ! command -v terraform &> /dev/null; then
    echo "Error: Terraform is not installed."
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed."
    exit 1
fi

# =============================================================================
# CLEAN UP OLD FILES
# =============================================================================
rm -f tfplan tfplan.json

# =============================================================================
# PREPARE TERRAFORM AND PRODUCE THE PLAN JSON
# =============================================================================
echo "Initializing Terraform..."
terraform init

# Create a plan showing exactly what infrastructure will be created/changed.
# -lock-timeout: this script also runs in every PR's compliance check, where
# it can contend for the shared state lock with sibling PR checks or a
# main-branch deploy mid-apply; wait for the lock instead of failing.
echo "Generating Terraform plan..."
terraform plan -lock-timeout=300s -out=tfplan

echo "Converting plan to JSON..."
terraform show -json tfplan > tfplan.json

# =============================================================================
# RUN INFRASTRUCTURE SECURITY CHECKS — ONE EVAL OVER THE WHOLE PLAN
# =============================================================================
# The raw plan JSON is the policy input; there is no pre-processing layer to
# drift out of sync with the rules. --strict-builtin-errors makes any builtin
# failure (bad regex, type error) fail the gate loudly instead of silently
# evaluating to undefined — a broken rule must never look like a passing one.
# =============================================================================
echo "Running infrastructure compliance checks..."
VIOLATIONS_FOUND=false

# The evaluation timestamp rides in as DATA (data.runtime.evaluated_at), not
# input — the input stays the raw terraform plan. The exceptions register
# checks expiry against it; without it no exception is active (fail-safe).
jq -n --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{runtime: {evaluated_at: $now}}' > eval-context.json

opa eval --strict-builtin-errors \
    -d policy/ \
    -d eval-context.json \
    -i tfplan.json \
    "data.terraform.compliance.compliance_report" > opa-report.json

opa eval --strict-builtin-errors \
    -d policy/ \
    -d eval-context.json \
    -i tfplan.json \
    "data.terraform.compliance.resource_reports" > opa-resources.json

COMPLIANT=$(jq -r '.result[0].expressions[0].value.compliant' opa-report.json)

# Per-resource results. These become validations.json entries for the KSI
# signal emitter; the entry shape (kind / resource_type / resource_name /
# compliant / violations / policy_version) is a published contract — see the
# KSI signal schema.
jq -c '.result[0].expressions[0].value[]' opa-resources.json > validations.ndjson

while IFS= read -r entry; do
    R_COMPLIANT=$(echo "$entry" | jq -r '.compliant')
    R_TYPE=$(echo "$entry" | jq -r '.resource_type')
    R_NAME=$(echo "$entry" | jq -r '.resource_name')
    if [ "$R_COMPLIANT" = "true" ]; then
        echo "✅ $R_TYPE.$R_NAME is compliant"
    else
        VIOLATIONS_FOUND=true
        echo "❌ INFRASTRUCTURE VIOLATION in $R_TYPE.$R_NAME:"
        echo "$entry" | jq -r '.violations[]? | "  - \(.type): \(.message) (Severity: \(.severity))"'
        echo
    fi
done < validations.ndjson

# The overall verdict is authoritative: it also covers violations that are
# not attributable to a single resource (e.g. input_error when the plan JSON
# is unreadable). Fail closed on anything other than an explicit "true".
if [ "$COMPLIANT" != "true" ]; then
    VIOLATIONS_FOUND=true
    echo "❌ Overall policy verdict: non-compliant"
    jq -r '.result[0].expressions[0].value.violations[]? | "  - \(.type): \(.message) (Severity: \(.severity))"' opa-report.json
fi

# =============================================================================
# RUN SECTION 508 ACCESSIBILITY CHECKS — SCANNER PRODUCES FACTS, OPA DECIDES
# =============================================================================
# pa11y (tools/a11y/scan.js) renders every page under website/ in headless
# Chromium (WCAG 2 AA) and emits ONE JSON facts document. The policy
# (policy.accessibility) decides which issue types fail the gate; accepted
# findings flow through the exceptions register and stay visible in the
# report under `excepted`.
# =============================================================================
echo "Running Section 508 accessibility checks..."

# Find the website directory (check common locations)
WEBSITE_DIR=""
if [ -d "../website" ]; then
    WEBSITE_DIR="../website"
elif [ -d "website" ]; then
    WEBSITE_DIR="website"
fi

A11Y_TOOL_DIR="../tools/a11y"
if [ ! -d "$A11Y_TOOL_DIR" ]; then
    A11Y_TOOL_DIR="tools/a11y"
fi

if [ -z "$WEBSITE_DIR" ]; then
    echo "Warning: Could not find website directory, skipping accessibility checks"
elif [ "$SKIP_A11Y" = "1" ]; then
    echo "Warning: SKIP_A11Y=1 — accessibility checks skipped by explicit request (local use only; CI never sets this)"
elif ! command -v node > /dev/null 2>&1 || [ ! -d "$A11Y_TOOL_DIR/node_modules" ]; then
    # Fail closed: an unavailable scanner must not look like an accessible
    # site. Local runs without Chromium can opt out explicitly (SKIP_A11Y=1).
    VIOLATIONS_FOUND=true
    echo "❌ Accessibility scanner unavailable (need node and 'npm ci' in tools/a11y)."
    echo "   Install it, or set SKIP_A11Y=1 to skip in a local run (never in CI)."
else
    # Prefer a system browser (CI runners ship Chrome; PUPPETEER_SKIP_DOWNLOAD
    # avoids a 150MB download at npm ci time).
    A11Y_CHROME="${A11Y_CHROME:-$(command -v google-chrome || command -v chromium-browser || command -v chromium || true)}"
    export A11Y_CHROME
    echo "Scanning $WEBSITE_DIR with pa11y (browser: ${A11Y_CHROME:-puppeteer-bundled})..."
    node "$A11Y_TOOL_DIR/scan.js" "$WEBSITE_DIR" --out a11y-scan.json 2> /dev/null

    opa eval --strict-builtin-errors \
        -d policy/ \
        -d eval-context.json \
        -i a11y-scan.json \
        "data.terraform.compliance.compliance_report" > a11y-report.json

    opa eval --strict-builtin-errors \
        -d policy/ \
        -d eval-context.json \
        -i a11y-scan.json \
        "data.terraform.compliance.page_reports" > a11y-pages.json

    A11Y_COMPLIANT=$(jq -r '.result[0].expressions[0].value.compliant' a11y-report.json)

    # Per-page results join the same validations stream as the infrastructure
    # results (kind: accessibility), keeping the KSI signal contract intact.
    jq -c '.result[0].expressions[0].value[]' a11y-pages.json >> validations.ndjson

    jq -r '.result[0].expressions[0].value[] |
        if .compliant then "✅ \(.file_name) is accessible"
        else "❌ ACCESSIBILITY VIOLATION in \(.file_name):\n" +
             ([.violations[] | "  - \(.code // .type): \(.message) (Severity: \(.severity))"] | join("\n"))
        end' a11y-pages.json

    EXCEPTED_COUNT=$(jq -r '.result[0].expressions[0].value.excepted | length' a11y-report.json)
    if [ "$EXCEPTED_COUNT" != "0" ]; then
        echo "ℹ️  $EXCEPTED_COUNT accessibility finding(s) suppressed by the exceptions register (still visible in the report):"
        jq -r '.result[0].expressions[0].value.excepted[] | "  - \(.violation.resource) \(.violation.code // .violation.id): \(.exception.justification) (expires \(.exception.expiry), \(.exception.ticket))"' a11y-report.json
    fi

    if [ "$A11Y_COMPLIANT" != "true" ]; then
        VIOLATIONS_FOUND=true
        echo "❌ Overall accessibility verdict: non-compliant"
    fi
fi

# =============================================================================
# CONSOLIDATE VALIDATIONS FOR THE KSI SIGNAL EMITTER
# =============================================================================
# Convert the NDJSON accumulated above into the single validations.json
# document that scripts/build-ksi-signal.py consumes after terraform apply.
# =============================================================================
if [ -s validations.ndjson ]; then
    jq -s --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{generated_at: $generated_at, results: .}' \
        validations.ndjson > validations.json
    echo "Wrote validations.json ($(jq '.results | length' validations.json) results)"
else
    echo '{"generated_at":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","results":[]}' > validations.json
    echo "Wrote validations.json (no results)"
fi

# =============================================================================
# CLEAN UP TEMPORARY FILES
# =============================================================================
rm -f opa-report.json opa-resources.json a11y-scan.json a11y-report.json a11y-pages.json validations.ndjson eval-context.json

# =============================================================================
# FINAL DECISION: ALLOW OR BLOCK DEPLOYMENT
# =============================================================================
echo
echo "=== Compliance Check Summary ==="
if [ "$VIOLATIONS_FOUND" = "true" ]; then
    echo "❌ COMPLIANCE VIOLATIONS FOUND"
    echo "Please fix the violations above before deploying."
    echo "This includes both infrastructure security and accessibility issues."
    echo
    echo "To deploy anyway (not recommended), run:"
    echo "  terraform apply tfplan"
    exit 1
else
    echo "✅ ALL RESOURCES AND CONTENT ARE COMPLIANT"
    echo "Infrastructure security and accessibility checks passed."
    echo "Ready to deploy! Run:"
    echo "  terraform apply tfplan"
fi

echo
echo "To view the full Terraform plan:"
echo "  terraform show tfplan"
