# Website Deployment with OPA Compliance

This repository contains Terraform configuration and OPA policies to deploy the samaydlette.com website to AWS S3 with CloudFront, including automated compliance checking for infrastructure security and Section 508 accessibility standards.

## Features

-  **Automated S3 + CloudFront deployment** with proper security configurations
-  **OPA-based compliance checking** for infrastructure and accessibility
-  **Section 508 accessibility validation** for web content
-  **Comprehensive tagging strategy** for cost allocation and governance
-  **Pre-deployment validation** to catch violations before they reach production
-  **Automated compliance reporting** with Lambda-based monitoring
-  **Route53 DNS management** (optional)
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

## Quick Start

### Prerequisites

- AWS CLI configured with appropriate permissions
- Terraform >= 1.0
- Node.js (for Lambda function)
- jq (for JSON processing)
- OPA (will be installed automatically)

### 1. Clone and Configure

```bash
git clone <this-repo>
cd website-terraform-opa

# Copy and customize variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your domain and settings
```

### 2. Create SSL Certificate

**Option A: Auto-create (Recommended)**
```bash
# Certificate will be created automatically in us-east-1
# Just ensure create_certificate = true in terraform.tfvars
```

**Option B: Use existing certificate**
```bash
# If you have an existing certificate in us-east-1:
aws acm list-certificates --region us-east-1
# Add the ARN to terraform.tfvars and set create_certificate = false
```

**Option C: Create manually**
```bash
# Create certificate manually (must be in us-east-1 for CloudFront)
aws acm request-certificate \
    --domain-name samaydlette.com \
    --subject-alternative-names *.samaydlette.com \
    --validation-method DNS \
    --region us-east-1

# Complete DNS validation in ACM console
# Add certificate ARN to terraform.tfvars
```

### 3. Deploy with Compliance Checking

```bash
# Make scripts executable
chmod +x deploy.sh terraform-plan.sh

# Run deployment (includes OPA compliance checks)
./deploy.sh
```

### 4. Sync Website Content

The deployment script will automatically sync your website files to S3, excluding infrastructure files.

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

## Configuration Options

### terraform.tfvars

```hcl
domain_name     = "samaydlette.com"
aws_region      = "us-east-2"  # Your main region
environment     = "prod"
cost_center     = "website-ops"
owner_email     = "sam@samaydlette.com"

# SSL Certificate (choose one option):
create_certificate = true         # Auto-create certificate
ssl_certificate_arn = ""         # Leave empty when auto-creating

# OR use existing certificate:
# create_certificate = false
# ssl_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/..."

cloudfront_price_class = "PriceClass_100"
manage_dns = true
compliance_check_schedule = "rate(1 day)"
section_508_compliance_level = "AA"
```

### Pre-deployment Validation

The `terraform-plan.sh` script runs OPA compliance checks against your Terraform plan before deployment:

```bash
./terraform-plan.sh
```

This will:
1. Generate Terraform plan
2. Extract resource configurations
3. Run OPA evaluation on each resource
4. Report compliance violations
5. Block deployment if violations found

### Compliance Monitoring

A Lambda function runs daily (configurable) to check:

- Infrastructure compliance via AWS APIs
- Section 508 compliance by scanning HTML files
- Generates reports stored in S3
- Sends alerts for violations

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

## Manual Operations

### Check Compliance Manually

```bash
# Run infrastructure compliance check
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Evaluate with OPA
opa eval -d policies.rego -i tfplan.json "data.terraform.compliance.compliance_report"
```

### Trigger Lambda Compliance Check

```bash
aws lambda invoke \
    --function-name samaydlette-com-opa-compliance \
    --payload '{}' \
    result.json

cat result.json | jq '.'
```

### Update Website Content

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

## Cost Estimation

Monthly AWS costs (approximate):

- **S3 Storage**: $1-5 (depending on content size)
- **CloudFront**: $5-20 (depending on traffic)  
- **Route53**: $0.50 per hosted zone
- **Lambda**: <$1 (minimal usage for compliance checks)
- **ACM Certificate**: Free
- **Cross-region data transfer**: <$1 (minimal for certificate validation)

**Total**: ~$10-30/month for typical static website

*Note: Resources are primarily in us-east-2, with SSL certificate in us-east-1 as required by AWS.*

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

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add/modify OPA policies as needed
4. Test with `terraform-plan.sh`
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues or questions:
- Check the troubleshooting section above
- Review AWS CloudWatch logs
- Open an issue in this repository
