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
# (infrastructure/policies.rego), which consumes raw `terraform show -json`
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

opa eval --strict-builtin-errors \
    -d policies.rego \
    -i tfplan.json \
    "data.terraform.compliance.compliance_report" > opa-report.json

opa eval --strict-builtin-errors \
    -d policies.rego \
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
# RUN SECTION 508 ACCESSIBILITY CHECKS
# =============================================================================
echo "Running Section 508 accessibility checks..."

# Find the website directory (check common locations)
WEBSITE_DIR=""
if [ -d "../website" ]; then
    WEBSITE_DIR="../website"
elif [ -d "website" ]; then
    WEBSITE_DIR="website"
else
    echo "Warning: Could not find website directory, skipping accessibility checks"
fi

if [ -n "$WEBSITE_DIR" ]; then
    # Process substitution (`done < <(find ...)`) is used here instead of the
    # more common `find ... | while read` because the pipe form runs the loop
    # body in a subshell, which means a `VIOLATIONS_FOUND=true` set inside the
    # loop would not propagate back to this script's parent shell — and the
    # accessibility gate would silently pass even on real violations. The
    # process-substitution form keeps the loop in the parent shell.
    while IFS= read -r html_file; do
        echo "Checking accessibility: $html_file"

        filename=$(basename "$html_file")

        jq -n --rawfile content "$html_file" --arg name "$filename" \
            '{html_content: $content, file_name: $name}' > accessibility-input.json

        opa eval -d policies.rego -i accessibility-input.json \
            "data.terraform.compliance.compliance_report" > accessibility-result.json

        ACCESSIBLE=$(jq -r '.result[0].expressions[0].value.compliant' accessibility-result.json)

        # Persist this result for the KSI signal emitter
        jq -c --arg kind "accessibility" \
              --arg file_name "$filename" \
              --arg file_path "$html_file" \
              --argjson compliant "$ACCESSIBLE" \
              '{kind: $kind,
                file_name: $file_name,
                file_path: $file_path,
                compliant: $compliant,
                violations: (.result[0].expressions[0].value.violations // []),
                policy_version: (.result[0].expressions[0].value.policy_version // "unknown")}' \
            accessibility-result.json >> validations.ndjson

        if [ "$ACCESSIBLE" != "true" ]; then
            VIOLATIONS_FOUND=true
            echo "❌ ACCESSIBILITY VIOLATION in $filename:"
            jq -r '.result[0].expressions[0].value.violations[]? | "  - \(.type): \(.message) (Severity: \(.severity))"' accessibility-result.json
            echo
        else
            echo "✅ $filename is accessible"
        fi
    done < <(find "$WEBSITE_DIR" -name "*.html" -type f)
else
    echo "Skipping accessibility checks - no website directory found"
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
rm -f opa-report.json opa-resources.json accessibility-input.json accessibility-result.json validations.ndjson

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
