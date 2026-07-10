#!/bin/bash
# =============================================================================
# TERRAFORM PLAN WITH OPA COMPLIANCE CHECK + SECTION 508 ACCESSIBILITY
# =============================================================================
# This script is the security guard for my infrastructure AND website content.
# It looks at what Terraform wants to build and checks it against my security
# rules, PLUS it checks my website content for accessibility compliance.
# If anything violates my policies, deployment is blocked.
#
# What this does:
# 1. Checks that required tools are installed
# 2. Creates a plan showing what infrastructure will be built
# 3. Converts that plan into a format security tools can read
# 4. Checks each resource against my security policies
# 5. Checks HTML files for Section 508 accessibility compliance
# 6. Blocks deployment if any violations are found
# =============================================================================

set -e  # Stop immediately if any command fails

echo "=== Terraform Plan with OPA Compliance Check + Section 508 ==="

# =============================================================================
# CHECK THAT REQUIRED TOOLS ARE INSTALLED
# =============================================================================
# Make sure we have the tools needed to check security policies
# =============================================================================

# Make sure OPA (security policy checker) is installed
if ! command -v opa &> /dev/null; then
    echo "Error: OPA is not installed. Please install OPA first:"
    echo "  curl -L -o opa https://openpolicyagent.org/downloads/v1.18.2/opa_linux_amd64_static"
    echo "  chmod 755 ./opa"
    echo "  sudo mv opa /usr/local/bin"
    exit 1
fi

# Make sure Terraform (infrastructure tool) is installed
if ! command -v terraform &> /dev/null; then
    echo "Error: Terraform is not installed."
    exit 1
fi

# =============================================================================
# CLEAN UP OLD FILES
# =============================================================================
# Remove any leftover files from previous runs to start fresh
# =============================================================================
rm -f tfplan tfplan.json

# =============================================================================
# PREPARE TERRAFORM
# =============================================================================
# Set up Terraform so it can create a plan of what will be built
# =============================================================================
echo "Initializing Terraform..."
terraform init

# Create a plan showing exactly what infrastructure will be created/changed.
# -lock-timeout: this script also runs in every PR's compliance check, where
# it can contend for the shared state lock with sibling PR checks or a
# main-branch deploy mid-apply; wait for the lock instead of failing.
echo "Generating Terraform plan..."
terraform plan -lock-timeout=300s -out=tfplan

# =============================================================================
# CONVERT PLAN TO READABLE FORMAT
# =============================================================================
# Transform the Terraform plan into JSON that security tools can understand
# =============================================================================
echo "Converting plan to JSON..."
terraform show -json tfplan > tfplan.json

# =============================================================================
# PREPARE SECURITY CHECK INPUT
# =============================================================================
# Create the initial file that will hold information for security checking
# =============================================================================
echo "Preparing OPA input..."
cat > opa-input.json << EOF
{
  "terraform_plan": $(cat tfplan.json),
  "resources": []
}
EOF

# =============================================================================
# EXTRACT RESOURCE INFORMATION
# =============================================================================
# Pull out detailed information about each AWS resource that will be created
# This is where we figure out what Terraform actually wants to build
# =============================================================================
echo "Extracting resource configurations..."
python3 << 'PYTHON_SCRIPT'
import json
import sys

# Read the Terraform plan file
with open('tfplan.json', 'r') as f:
    plan = json.load(f)

resources = []

# Look at what Terraform plans to create or change
if 'planned_values' in plan and 'root_module' in plan['planned_values']:
    root_module = plan['planned_values']['root_module']
    
    if 'resources' in root_module:
        for resource in root_module['resources']:
            # Extract basic information about each resource
            resource_config = {
                'type': resource.get('type', ''),
                'name': resource.get('name', ''),
                # mode distinguishes managed resources from data sources; the
                # classification gate only applies to managed resources (data
                # sources like data.aws_s3_bucket.website carry no tags).
                'mode': resource.get('mode', 'managed'),
                'values': resource.get('values', {}),
                'tags': resource.get('values', {}).get('tags', {}),
                # tags_all includes provider default_tags merged in; the
                # classification completeness rule reads it so the constant axes
                # applied via default_tags are visible to the gate.
                'tags_all': resource.get('values', {}).get('tags_all', {})
            }
            
            # Add special security-relevant fields for S3 buckets
            if resource['type'] == 'aws_s3_bucket':
                resource_config['versioning_enabled'] = False  # Will check this separately
                resource_config['encryption_enabled'] = False  # Will check this separately
                
            # Add special fields for CloudFront distributions
            if resource['type'] == 'aws_cloudfront_distribution':
                if 'default_cache_behavior' in resource['values']:
                    behavior = resource['values']['default_cache_behavior'][0]
                    resource_config['viewer_protocol_policy'] = behavior.get('viewer_protocol_policy', '')
                    
                if 'viewer_certificate' in resource['values']:
                    cert = resource['values']['viewer_certificate'][0]
                    resource_config['minimum_protocol_version'] = cert.get('minimum_protocol_version', '')
            
            resources.append(resource_config)

# Look for S3 security settings in separate Terraform resources
for resource in plan['planned_values']['root_module']['resources']:
    # Check if S3 versioning is being enabled
    if resource['type'] == 'aws_s3_bucket_versioning':
        bucket_ref = resource['values'].get('bucket', '')
        for r in resources:
            if r['type'] == 'aws_s3_bucket' and r['name'] in bucket_ref:
                r['versioning_enabled'] = resource['values'].get('versioning_configuration', [{}])[0].get('status') == 'Enabled'

    # Check if S3 encryption is being enabled
    if resource['type'] == 'aws_s3_bucket_server_side_encryption_configuration':
        bucket_ref = resource['values'].get('bucket', '')
        for r in resources:
            if r['type'] == 'aws_s3_bucket' and r['name'] in bucket_ref:
                # Look for encryption rules
                rules = resource['values'].get('rule', [])
                if rules and len(rules) > 0:
                    encryption_config = rules[0].get('apply_server_side_encryption_by_default', [])
                    if encryption_config and len(encryption_config) > 0:
                        algorithm = encryption_config[0].get('sse_algorithm', '')
                        # Accept both AES256 and aws:kms as valid encryption
                        if algorithm in ['AES256', 'aws:kms']:
                            r['encryption_enabled'] = True

    # Check whether S3 public access is fully blocked. Same boolean shape
    # the runtime Lambda emits from GetPublicAccessBlock API responses, so
    # the same Rego rule covers both deploy-time and runtime evaluation.
    if resource['type'] == 'aws_s3_bucket_public_access_block':
        bucket_ref = resource['values'].get('bucket', '')
        cfg = resource['values']
        all_blocked = (
            cfg.get('block_public_acls', False) and
            cfg.get('block_public_policy', False) and
            cfg.get('ignore_public_acls', False) and
            cfg.get('restrict_public_buckets', False)
        )
        for r in resources:
            if r['type'] == 'aws_s3_bucket' and r['name'] in bucket_ref:
                r['public_access_blocked'] = all_blocked

# Save the extracted resource information
with open('opa-input.json', 'r') as f:
    opa_input = json.load(f)

opa_input['resources'] = resources

with open('opa-input.json', 'w') as f:
    json.dump(opa_input, f, indent=2)

print(f"Extracted {len(resources)} resources for compliance checking")
PYTHON_SCRIPT

# =============================================================================
# RUN INFRASTRUCTURE SECURITY CHECKS
# =============================================================================
# Check each AWS resource against my infrastructure security policies
# Results are also accumulated into validations.ndjson so the deploy-time KSI
# signal emitter (scripts/build-ksi-signal.sh) can attach them to components.
# =============================================================================
echo "Running infrastructure compliance checks..."
VIOLATIONS_FOUND=false

# Reset the validations accumulator. NDJSON (one result per line) is used so
# that appends from inside a `find | while read` subshell still reach the file.
: > validations.ndjson

# Check each resource one by one against security policies
for resource in $(cat opa-input.json | jq -r '.resources[] | @base64'); do
    # Decode the resource information
    resource_data=$(echo $resource | base64 --decode)

    # Create a file with just this one resource for checking
    echo "{\"resource\": $resource_data}" > resource-input.json

    # Run the security policy check on this resource
    opa eval -d policies.rego -i resource-input.json "data.terraform.compliance.compliance_report" > opa-result.json

    # Check if this resource passed or failed security checks
    COMPLIANT=$(cat opa-result.json | jq -r '.result[0].expressions[0].value.compliant // true')
    RESOURCE_NAME=$(echo $resource_data | jq -r '.name')
    RESOURCE_TYPE=$(echo $resource_data | jq -r '.type')

    # Persist this result for the KSI signal emitter
    jq -c --arg kind "infrastructure" \
          --arg resource_type "$RESOURCE_TYPE" \
          --arg resource_name "$RESOURCE_NAME" \
          --argjson compliant "$COMPLIANT" \
          '{kind: $kind,
            resource_type: $resource_type,
            resource_name: $resource_name,
            compliant: $compliant,
            violations: (.result[0].expressions[0].value.violations // []),
            policy_version: (.result[0].expressions[0].value.policy_version // "unknown")}' \
        opa-result.json >> validations.ndjson

    if [ "$COMPLIANT" = "false" ]; then
        # This resource violated security policies
        VIOLATIONS_FOUND=true
        echo "❌ INFRASTRUCTURE VIOLATION in $RESOURCE_TYPE.$RESOURCE_NAME:"
        cat opa-result.json | jq -r '.result[0].expressions[0].value.violations[]? | "  - \(.type): \(.message) (Severity: \(.severity))"'
        echo
    else
        # This resource passed security checks
        echo "✅ $RESOURCE_TYPE.$RESOURCE_NAME is compliant"
    fi
done

# =============================================================================
# RUN SECTION 508 ACCESSIBILITY CHECKS
# =============================================================================
# Check HTML files for accessibility compliance
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

# Check HTML files for accessibility if website directory exists
if [ -n "$WEBSITE_DIR" ]; then
    # Find all HTML files in the website directory.
    #
    # Process substitution (`done < <(find ...)`) is used here instead of the
    # more common `find ... | while read` because the pipe form runs the loop
    # body in a subshell, which means a `VIOLATIONS_FOUND=true` set inside the
    # loop would not propagate back to this script's parent shell — and the
    # accessibility gate would silently pass even on real violations. The
    # process-substitution form keeps the loop in the parent shell.
    while IFS= read -r html_file; do
        echo "Checking accessibility: $html_file"
        
        # Read the HTML content
        html_content=$(cat "$html_file")
        filename=$(basename "$html_file")
        
        # Create input for OPA accessibility check
        cat > accessibility-input.json << EOF
{
    "html_content": $(echo "$html_content" | jq -R -s .),
    "file_name": "$filename"
}
EOF
        
        # Run accessibility policy check
        opa eval -d policies.rego -i accessibility-input.json "data.terraform.compliance.compliance_report" > accessibility-result.json

        # Check if this HTML file passed accessibility checks
        ACCESSIBLE=$(cat accessibility-result.json | jq -r '.result[0].expressions[0].value.compliant // true')

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

        if [ "$ACCESSIBLE" = "false" ]; then
            # This HTML file has accessibility violations
            VIOLATIONS_FOUND=true
            echo "❌ ACCESSIBILITY VIOLATION in $filename:"
            cat accessibility-result.json | jq -r '.result[0].expressions[0].value.violations[]? | "  - \(.type): \(.message) (Severity: \(.severity))"'
            echo
        else
            # This HTML file passed accessibility checks
            echo "✅ $filename is accessible"
        fi
    done < <(find "$WEBSITE_DIR" -name "*.html" -type f)
else
    echo "Skipping accessibility checks - no website directory found"
fi

# =============================================================================
# CONSOLIDATE VALIDATIONS FOR THE KSI SIGNAL EMITTER
# =============================================================================
# Convert the NDJSON appended in the loops above into a single validations.json
# document that scripts/build-ksi-signal.sh consumes after terraform apply.
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
# Remove files we created during the security check process
# =============================================================================
rm -f resource-input.json opa-result.json accessibility-input.json accessibility-result.json validations.ndjson

# =============================================================================
# FINAL DECISION: ALLOW OR BLOCK DEPLOYMENT
# =============================================================================
# Based on security and accessibility check results, either allow deployment or stop it
# =============================================================================
echo
echo "=== Compliance Check Summary ==="
if [ "$VIOLATIONS_FOUND" = "true" ]; then
    # Security or accessibility violations were found - block deployment
    echo "❌ COMPLIANCE VIOLATIONS FOUND"
    echo "Please fix the violations above before deploying."
    echo "This includes both infrastructure security and accessibility issues."
    echo
    echo "To deploy anyway (not recommended), run:"
    echo "  terraform apply tfplan"
    exit 1
else
    # All security and accessibility checks passed - allow deployment
    echo "✅ ALL RESOURCES AND CONTENT ARE COMPLIANT"
    echo "Infrastructure security and accessibility checks passed."
    echo "Ready to deploy! Run:"
    echo "  terraform apply tfplan"
fi

echo
echo "To view the full Terraform plan:"