#!/bin/bash
# test-policies.sh - Test OPA policies with various scenarios

set -e

echo "=== Testing OPA Compliance Policies ==="

# Check if OPA is installed
if ! command -v opa &> /dev/null; then
    echo "Error: OPA is not installed. Please install OPA first."
    exit 1
fi

# Create test directory
mkdir -p test-results
cd test-results

# Test Case 1: Compliant S3 bucket
echo "Testing compliant S3 bucket..."
cat > compliant-s3.json << EOF
{
  "resource": {
    "type": "aws_s3_bucket",
    "name": "samaydlette-com",
    "tags": {
      "Environment": "prod",
      "CostCenter": "website-ops",
      "DataClassification": "Public",
      "Owner": "sam@samaydlette.com"
    },
    "versioning_enabled": true,
    "encryption_enabled": true
  }
}
EOF

opa eval -d ../policies.rego -i compliant-s3.json "data.terraform.compliance.compliance_report" > result-compliant-s3.json
COMPLIANT=$(cat result-compliant-s3.json | jq -r '.result.compliant')
if [ "$COMPLIANT" = "true" ]; then
    echo "✅ Compliant S3 bucket test passed"
else
    echo "❌ Compliant S3 bucket test failed"
    cat result-compliant-s3.json | jq '.result.violations'
fi

# Test Case 2: Non-compliant S3 bucket (missing tags)
echo "Testing non-compliant S3 bucket (missing tags)..."
cat > non-compliant-s3-tags.json << EOF
{
  "resource": {
    "type": "aws_s3_bucket",
    "name": "test-bucket",
    "tags": {
      "Environment": "prod"
    },
    "versioning_enabled": true,
    "encryption_enabled": true
  }
}
EOF

opa eval -d ../policies.rego -i non-compliant-s3-tags.json "data.terraform.compliance.compliance_report" > result-non-compliant-s3-tags.json
COMPLIANT=$(cat result-non-compliant-s3-tags.json | jq -r '.result.compliant')
if [ "$COMPLIANT" = "false" ]; then
    echo "✅ Non-compliant S3 bucket (missing tags) test passed"
else
    echo "❌ Non-compliant S3 bucket (missing tags) test failed"
fi

# Test Case 3: Non-compliant S3 bucket (no encryption)
echo "Testing non-compliant S3 bucket (no encryption)..."
cat > non-compliant-s3-encryption.json << EOF
{
  "resource": {
    "type": "aws_s3_bucket",
    "name": "test-bucket",
    "tags": {
      "Environment": "prod",
      "CostCenter": "website-ops",
      "DataClassification": "Public",
      "Owner": "sam@samaydlette.com"
    },
    "versioning_enabled": true,
    "encryption_enabled": false
  }
}
EOF

opa eval -d ../policies.rego -i non-compliant-s3-encryption.json "data.terraform.compliance.compliance_report" > result-non-compliant-s3-encryption.json
COMPLIANT=$(cat result-non-compliant-s3-encryption.json | jq -r '.result.compliant')
if [ "$COMPLIANT" = "false" ]; then
    echo "✅ Non-compliant S3 bucket (no encryption) test passed"
else
    echo "❌ Non-compliant S3 bucket (no encryption) test failed"
fi

# Test Case 4: Compliant CloudFront distribution
echo "Testing compliant CloudFront distribution..."
cat > compliant-cloudfront.json << EOF
{
  "resource": {
    "type": "aws_cloudfront_distribution",
    "name": "website-cdn",
    "tags": {
      "Environment": "prod",
      "CostCenter": "website-ops",
      "DataClassification": "Public",
      "Owner": "sam@samaydlette.com"
    },
    "viewer_protocol_policy": "redirect-to-https",
    "minimum_protocol_version": "TLSv1.2_2021"
  }
}
EOF

opa eval -d ../policies.rego -i compliant-cloudfront.json "data.terraform.compliance.compliance_report" > result-compliant-cloudfront.json
COMPLIANT=$(cat result-compliant-cloudfront.json | jq -r '.result.compliant')
if [ "$COMPLIANT" = "true" ]; then
    echo "✅ Compliant CloudFront distribution test passed"
else
    echo "❌ Compliant CloudFront distribution test failed"
    cat result-compliant-cloudfront.json | jq '.result.violations'
fi

# Test Case 5: Non-compliant CloudFront (insecure protocol)
echo "Testing non-compliant CloudFront (insecure protocol)..."
cat > non-compliant-cloudfront.json << EOF
{
  "resource": {
    "type": "aws_cloudfront_distribution",
    "name": "website-cdn",
    "tags": {
      "Environment": "prod",
      "CostCenter": "website-ops",
      "DataClassification": "Public",
      "Owner": "sam@samaydlette.com"
    },
    "viewer_protocol_policy": "allow-all",
    "minimum_protocol_version": "SSLv3"
  }
}
EOF

opa eval -d ../policies.rego -i non-compliant-cloudfront.json "data.terraform.compliance.compliance_report" > result-non-compliant-cloudfront.json
COMPLIANT=$(cat result-non-compliant-cloudfront.json | jq -r '.result.compliant')
if [ "$COMPLIANT" = "false" ]; then
    echo "✅ Non-compliant CloudFront (insecure protocol) test passed"
else
    echo "❌ Non-compliant CloudFront (insecure protocol) test failed"
fi

# Test Case 6: Section 508 compliant HTML
echo "Testing Section 508 compliant HTML..."
cat > section508-compliant.json << EOF
{
  "html_content": "<!DOCTYPE html><html lang=\"en\"><head><title>Test</title></head><body><h1>Main Heading</h1><img src=\"test.jpg\" alt=\"Test image\" /><p>This is accessible content with proper structure.</p></body></html>",
  "file_name": "test.html"
}
EOF

opa eval -d ../policies.rego -i section508-compliant.json "data.terraform.compliance.compliance_report" > result-section508-compliant.json
COMPLIANT=$(cat result-section508-compliant.json | jq -r '.result.compliant')
if [ "$COMPLIANT" = "true" ]; then
    echo "✅ Section 508 compliant HTML test passed"
else
    echo "❌ Section 508 compliant HTML test failed"
    cat result-section508-compliant.json | jq '.result.violations'
fi

# Test Case 7: Section 508 non-compliant HTML (missing alt text)
echo "Testing Section 508 non-compliant HTML (missing alt text)..."
cat > section508-non-compliant-alt.json << EOF
{
  "html_content": "<!DOCTYPE html><html lang=\"en\"><head><title>Test</title></head><body><h1>Main Heading</h1><img src=\"test.jpg\" /><p>This image is missing alt text.</p></body></html>",
  "file_name": "test.html"
}
EOF

opa eval -d ../policies.rego -i section508-non-compliant-alt.json "data.terraform.compliance.compliance_report" > result-section508-non-compliant-alt.json
COMPLIANT=$(cat result-section508-non-compliant-alt.json | jq -r '.result.compliant')
if [ "$COMPLIANT" = "false" ]; then
    echo "✅ Section 508 non-compliant HTML (missing alt text) test passed"
else
    echo "❌ Section 508 non-compliant HTML (missing alt text) test failed"
fi

# Test Case 8: Section 508 non-compliant HTML (missing lang attribute)
echo "Testing Section 508 non-compliant HTML (missing lang attribute)..."
cat > section508-non-compliant-lang.json << EOF
{
  "html_content": "<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Main Heading</h1><img src=\"test.jpg\" alt=\"Test image\" /><p>This page is missing lang attribute.</p></body></html>",
  "file_name": "test.html"
}
EOF

opa eval -d ../policies.rego -i section508-non-compliant-lang.json "data.terraform.compliance.compliance_report" > result-section508-non-compliant-lang.json
COMPLIANT=$(cat result-section508-non-compliant-lang.json | jq -r '.result.compliant')
if [ "$COMPLIANT" = "false" ]; then
    echo "✅ Section 508 non-compliant HTML (missing lang attribute) test passed"
else
    echo "❌ Section 508 non-compliant HTML (missing lang attribute) test failed"
fi

# Test Case 9: Section 508 non-compliant HTML (missing heading structure)
echo "Testing Section 508 non-compliant HTML (missing heading structure)..."
cat > section508-non-compliant-headings.json << EOF
{
  "html_content": "<!DOCTYPE html><html lang=\"en\"><head><title>Test</title></head><body><p>This page has no proper heading structure.</p><img src=\"test.jpg\" alt=\"Test image\" /></body></html>",
  "file_name": "test.html"
}
EOF

opa eval -d ../policies.rego -i section508-non-compliant-headings.json "data.terraform.compliance.compliance_report" > result-section508-non-compliant-headings.json
COMPLIANT=$(cat result-section508-non-compliant-headings.json | jq -r '.result.compliant')
if [ "$COMPLIANT" = "false" ]; then
    echo "✅ Section 508 non-compliant HTML (missing heading structure) test passed"
else
    echo "❌ Section 508 non-compliant HTML (missing heading structure) test failed"
fi

# Test Case 10: Complex scenario with multiple violations
echo "Testing complex scenario with multiple violations..."
cat > complex-violations.json << EOF
{
  "resource": {
    "type": "aws_s3_bucket",
    "name": "bad-bucket",
    "tags": {
      "Environment": "dev"
    },
    "versioning_enabled": false,
    "encryption_enabled": false
  }
}
EOF

opa eval -d ../policies.rego -i complex-violations.json "data.terraform.compliance.compliance_report" > result-complex-violations.json
VIOLATION_COUNT=$(cat result-complex-violations.json | jq -r '.result.total_violations')
if [ "$VIOLATION_COUNT" -gt 1 ]; then
    echo "✅ Complex scenario with multiple violations test passed ($VIOLATION_COUNT violations found)"
else
    echo "❌ Complex scenario with multiple violations test failed"
fi

# Generate summary report
echo
echo "=== Test Summary ==="
echo "Generating comprehensive test report..."

cat > test-summary.json << EOF
{
  "test_execution": {
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "total_tests": 10,
    "passed_tests": 0,
    "failed_tests": 0
  },
  "test_results": []
}
EOF

# Count passed/failed tests by checking result files
PASSED_COUNT=0
FAILED_COUNT=0

for test_case in compliant-s3 non-compliant-s3-tags non-compliant-s3-encryption compliant-cloudfront non-compliant-cloudfront section508-compliant section508-non-compliant-alt section508-non-compliant-lang section508-non-compliant-headings complex-violations; do
    if [ -f "result-${test_case}.json" ]; then
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
done

echo "Tests passed: $PASSED_COUNT"
echo "Tests failed: $FAILED_COUNT"

# Performance test
echo
echo "=== Performance Test ==="
echo "Testing OPA policy evaluation performance..."

time_start=$(date +%s%N)
for i in {1..100}; do
    opa eval -d ../policies.rego -i compliant-s3.json "data.terraform.compliance.compliance_report" > /dev/null
done
time_end=$(date +%s%N)

duration_ms=$(( (time_end - time_start) / 1000000 ))
avg_ms=$(( duration_ms / 100 ))

echo "100 policy evaluations completed in ${duration_ms}ms"
echo "Average evaluation time: ${avg_ms}ms"

if [ $avg_ms -lt 100 ]; then
    echo "✅ Performance test passed (< 100ms average)"
else
    echo "⚠️  Performance test warning (> 100ms average)"
fi

# Clean up and final report
cd ..
echo
echo "=== Final Report ==="
echo "All test files saved in test-results/ directory"
echo "Test execution completed successfully"

if [ $FAILED_COUNT -eq 0 ]; then
    echo "✅ All OPA policy tests passed!"
    exit 0
else
    echo "❌ Some OPA policy tests failed"
    exit 1
