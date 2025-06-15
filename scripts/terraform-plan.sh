#!/bin/bash
# terraform-plan.sh - Pre-deployment OPA compliance check

set -e

echo "=== Terraform Plan with OPA Compliance Check ==="

# Check if OPA is installed
if ! command -v opa &> /dev/null; then
    echo "Error: OPA is not installed. Please install OPA first:"
    echo "  curl -L -o opa https://openpolicyagent.org/downloads/v0.57.0/opa_linux_amd64_static"
    echo "  chmod 755 ./opa"
    echo "  sudo mv opa /usr/local/bin"
    exit 1
fi

# Check if Terraform is installed
if ! command -v terraform &> /dev/null; then
    echo "Error: Terraform is not installed."
    exit 1
fi

# Initialize Terraform
echo "Initializing Terraform..."
terraform init

# Generate Terraform plan
echo "Generating Terraform plan..."
terraform plan -out=tfplan

# Convert plan to JSON for OPA analysis
echo "Converting plan to JSON..."
terraform show -json tfplan > tfplan.json

# Create OPA input file
echo "Preparing OPA input..."
cat > opa-input.json << EOF
{
  "terraform_plan": $(cat tfplan.json),
  "resources": []
}
EOF

# Extract resource configurations for OPA
echo "Extracting resource configurations..."
python3 << 'PYTHON_SCRIPT'
import json
import sys

# Load the Terraform plan
with open('tfplan.json', 'r') as f:
    plan = json.load(f)

resources = []

# Extract planned changes
if 'planned_values' in plan and 'root_module' in plan['planned_values']:
    root_module = plan['planned_values']['root_module']
    
    if 'resources' in root_module:
        for resource in root_module['resources']:
            resource_config = {
                'type': resource.get('type', ''),
                'name': resource.get('name', ''),
                'values': resource.get('values', {}),
                'tags': resource.get('values', {}).get('tags', {})
            }
            
            # Add specific fields for compliance checking
            if resource['type'] == 'aws_s3_bucket':
                resource_config['versioning_enabled'] = False  # Will be checked separately
                resource_config['encryption_enabled'] = False  # Will be checked separately
                
            if resource['type'] == 'aws_cloudfront_distribution':
                if 'default_cache_behavior' in resource['values']:
                    behavior = resource['values']['default_cache_behavior'][0]
                    resource_config['viewer_protocol_policy'] = behavior.get('viewer_protocol_policy', '')
                    
                if 'viewer_certificate' in resource['values']:
                    cert = resource['values']['viewer_certificate'][0]
                    resource_config['minimum_protocol_version'] = cert.get('minimum_protocol_version', '')
            
            resources.append(resource_config)

# Check for versioning and encryption in separate resources
for resource in plan['planned_values']['root_module']['resources']:
    if resource['type'] == 'aws_s3_bucket_versioning':
        bucket_ref = resource['values'].get('bucket', '')
        for r in resources:
            if r['type'] == 'aws_s3_bucket' and r['name'] in bucket_ref:
                r['versioning_enabled'] = resource['values'].get('versioning_configuration', [{}])[0].get('status') == 'Enabled'
                
    if resource['type'] == 'aws_s3_bucket_server_side_encryption_configuration':
        bucket_ref = resource['values'].get('bucket', '')
        for r in resources:
            if r['type'] == 'aws_s3_bucket' and r['name'] in bucket_ref:
                # Check if encryption rule exists and has valid algorithm
                rules = resource['values'].get('rule', [])
                if rules and len(rules) > 0:
                    encryption_config = rules[0].get('apply_server_side_encryption_by_default', [])
                    if encryption_config and len(encryption_config) > 0:
                        algorithm = encryption_config[0].get('sse_algorithm', '')
                        # Accept both AES256 and aws:kms as valid
                        if algorithm in ['AES256', 'aws:kms']:
                            r['encryption_enabled'] = True

# Update the input file
with open('opa-input.json', 'r') as f:
    opa_input = json.load(f)

opa_input['resources'] = resources

with open('opa-input.json', 'w') as f:
    json.dump(opa_input, f, indent=2)

print(f"Extracted {len(resources)} resources for compliance checking")
PYTHON_SCRIPT

# Run OPA evaluation for each resource
echo "Running OPA compliance checks..."
VIOLATIONS_FOUND=false

for resource in $(cat opa-input.json | jq -r '.resources[] | @base64'); do
    resource_data=$(echo $resource | base64 --decode)
    
    # Create individual resource input
    echo "{\"resource\": $resource_data}" > resource-input.json
    
    # Evaluate with OPA
    opa eval -d policies.rego -i resource-input.json "data.terraform.compliance.compliance_report" > opa-result.json
    
    # Check if compliant
    COMPLIANT=$(cat opa-result.json | jq -r '.result[0].expressions[0].value.compliant // true')
    
    if [ "$COMPLIANT" = "false" ]; then
        VIOLATIONS_FOUND=true
        RESOURCE_NAME=$(echo $resource_data | jq -r '.name')
        RESOURCE_TYPE=$(echo $resource_data | jq -r '.type')
        
        echo "❌ COMPLIANCE VIOLATION in $RESOURCE_TYPE.$RESOURCE_NAME:"
        cat opa-result.json | jq -r '.result.violations[]? | "  - \(.type): \(.message) (Severity: \(.severity))"'
        echo
    else
        RESOURCE_NAME=$(echo $resource_data | jq -r '.name')
        RESOURCE_TYPE=$(echo $resource_data | jq -r '.type')
        echo "✅ $RESOURCE_TYPE.$RESOURCE_NAME is compliant"
    fi
done

# Clean up temporary files
rm -f resource-input.json opa-result.json

# Summary
echo
echo "=== Compliance Check Summary ==="
if [ "$VIOLATIONS_FOUND" = "true" ]; then
    echo "❌ COMPLIANCE VIOLATIONS FOUND"
    echo "Please fix the violations above before deploying."
    echo
    echo "To deploy anyway (not recommended), run:"
    echo "  terraform apply tfplan"
    exit 1
else
    echo "✅ ALL RESOURCES ARE COMPLIANT"
    echo "Ready to deploy! Run:"
    echo "  terraform apply tfplan"
fi

echo
echo "To view the full Terraform plan:"
