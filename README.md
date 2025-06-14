# Sam's Website for Everything Going On

This is the central hub for what's going on with me. The repository contains Terraform configuration and OPA policies to deploy the samaydlette.com website to AWS S3 with CloudFront, including automated compliance checking for infrastructure security and Section 508 accessibility standards.

## Features

-  **Automated S3 + CloudFront deployment** with proper security configurations
-  **OPA-based compliance checking** for infrastructure and accessibility
-  **Section 508 accessibility validation** for web content
-  **Comprehensive tagging strategy** for cost allocation and governance
-  **Pre-deployment validation** to catch violations before they reach production
-  **Automated compliance reporting** with Lambda-based monitoring
-  **Route53 DNS management**
-  **SSL/TLS certificate integration** with AWS Certificate Manager

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Website Files │───▶│   S3 Bucket      │───▶│   CloudFront    │
│   (HTML/CSS/JS) │    │   (Origin)       │    │   (CDN)         │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   OPA Policies  │───▶│   Lambda         │    │   Route53       │
│   (Compliance)  │    │   (Monitoring)   │    │   (DNS)         │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```
## File Structure

```
├── main.tf                     # Main Terraform configuration
├── variables.tf                # Input variables
├── outputs.tf                  # Output values
├── terraform.tfvars.example    # Example variables file
├── policies.rego              # OPA compliance policies
├── lambda/
│   ├── index.js               # Lambda function code
│   ├── package.json           # Node.js dependencies
├── terraform-plan.sh          # Pre-deployment compliance check
├── deploy.sh                  # Complete deployment script
└── README.md                  # This file
```

## OPA Compliance Policies

### Infrastructure Compliance

The OPA policies check for:

- **Required Tags**: Environment, CostCenter, DataClassification, Owner
- **S3 Security**: Encryption enabled, versioning enabled
- **CloudFront Security**: HTTPS-only, TLS 1.2+ minimum
- **Access Controls**: Proper IAM policies and permissions

### Section 508 Accessibility Compliance

Automated checks for:

- **Alt Text**: All images must have alt attributes
- **Language Declaration**: HTML must have lang attribute  
- **Heading Structure**: Proper use of h1, h2, etc.
- **Color Independence**: Information not conveyed by color alone

### Custom Policy Example

```rego
# Add to policies.rego
custom_violation contains violation if {
    input.resource.type == "aws_s3_bucket"
    not startswith(input.resource.name, "samaydlette")
    violation := {
        "type": "naming_convention",
        "message": "S3 bucket must follow naming convention",
        "severity": "MEDIUM"
    }
}
```

### Compliance Monitoring

A Lambda function runs daily to check:

- Infrastructure compliance via AWS APIs
- Section 508 compliance by scanning HTML files
- Generates reports stored in S3
- Sends alerts for violations

## Manual Operations

### Check Compliance Manually

```bash
# Run infrastructure compliance check
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Evaluate with OPA
opa eval -d policies.rego -i tfplan.json "data.terraform.compliance.compliance_report"
```

### Trigger Lambda Compliance Check Manually

```bash
aws lambda invoke \
    --function-name samaydlette-com-opa-compliance \
    --payload '{}' \
    result.json

cat result.json | jq '.'
```

### Update Website Content Manually

```bash
# Sync files to S3
aws s3 sync . s3://samaydlette.com/ \
    --exclude "*.tf" \
    --exclude ".terraform/*" \
    --delete

# Invalidate CloudFront cache
aws cloudfront create-invalidation \
    --distribution-id E1234567890123 \
    --paths "/*"
```

## Troubleshooting

### Common Issues

1. **Certificate Validation Timeout**
   ```bash
   # Check certificate status
   aws acm describe-certificate --certificate-arn <arn> --region us-east-1
   ```

2. **OPA Policy Failures**
   ```bash
   # Test policy locally
   opa eval -d policies.rego -i test-input.json "data.terraform.compliance"
   ```

3. **Lambda Function Errors**
   ```bash
   # Check Lambda logs
   aws logs tail /aws/lambda/samaydlette-com-opa-compliance
   ```

4. **S3 Sync Issues**
   ```bash
   # Check bucket policy and permissions
   aws s3api get-bucket-policy --bucket samaydlette.com
   ```

### Debug Mode

Enable debug output:

```bash
export TF_LOG=DEBUG
export AWS_CLI_FILE_ENCODING=UTF-8
./deploy.sh
```

## Security Considerations

- SSL certificate auto-renewal via ACM
- S3 bucket encryption at rest
- CloudFront HTTPS enforcement
- IAM least-privilege access
- No hardcoded secrets in code
- Regular compliance monitoring

## License

MIT License - see LICENSE file for details.

## Support

For issues or questions:
- Check the troubleshooting section above
- Review AWS CloudWatch logs
