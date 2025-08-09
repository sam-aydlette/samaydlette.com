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







# Sam's Website Infrastructure with OPA Compliance

This repository demonstrates how to deploy a static website to AWS with automated compliance checking using Open Policy Agent (OPA). It showcases practical DevSecOps principles for cloud infrastructure while maintaining cost efficiency.

## What This Project Demonstrates

- **Compliance-as-Code:** OPA policies that prevent non-compliant resources from reaching production
- **Infrastructure-as-Code:** Terraform configuration with proper state management and security
- **Automated Security:** Pre-deployment validation and continuous compliance monitoring
- **Real-World Cost Optimization:** Practical trade-offs between security and operational costs
- **DevSecOps Pipeline:** GitHub Actions workflow with security scanning and automated deployment

## Architecture Overview

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

## Quick Start (5 Minutes)

**Prerequisites:**
- AWS CLI configured with appropriate permissions
- Terraform >= 1.0
- Node.js >= 18 (for Lambda function)

**Existing Resources Required:**
This project manages compliance for existing AWS infrastructure. You need:
- S3 bucket (named after your domain)
- CloudFront distribution
- SSL certificate in ACM (us-east-1 region)
- Route53 hosted zone (optional)

```bash
# 1. Clone and setup
git clone <your-repo-url>
cd <repo-name>

# 2. Install OPA (automated in scripts)
curl -L -o opa https://openpolicyagent.org/downloads/v0.57.0/opa_linux_amd64_static
chmod 755 ./opa && sudo mv opa /usr/local/bin

# 3. Configure your deployment
cp infrastructure/terraform.tfvars.example infrastructure/terraform.tfvars
# Edit terraform.tfvars with your AWS resource IDs

# 4. Deploy with compliance checking
cd infrastructure
make pipeline
```

## Real-World Costs

**Annual Operating Costs (Actual Usage):**
- **Compliance Pipeline:** ~$125/year
  - Lambda executions: $12/year (daily compliance checks)
  - EventBridge rules: $36/year
  - CloudWatch logs: $77/year (7-day retention)
- **Website Infrastructure:** Managed separately (existing resources)
- **Optional Features:**
  - Route53 query logging: +$84/year
  - Enhanced monitoring: +$240/year

**One-Time Setup Costs:**
- SSL certificate: Free (AWS Certificate Manager)
- Initial deployment time: ~15 minutes

## Features & Implementation Status

### Production Ready
- **S3 Security Configuration:** Encryption, versioning, public access blocking
- **CloudFront Security:** HTTPS enforcement, TLS 1.2+ requirements
- **Basic OPA Policies:** Infrastructure compliance validation
- **CI/CD Pipeline:** Automated deployment with rollback capabilities
- **Cost Optimization:** Suppressed non-essential security features with documentation

### Example Implementation
- **Section 508 Accessibility:** Basic HTML validation (demonstrates concept)
- **Advanced OPA Policies:** Expanded beyond basic AWS resource checks
- **Multi-Environment Support:** Framework present, single environment configured

### Roadmap
- **Comprehensive Accessibility Testing:** Full WCAG 2.1 AA compliance automation
- **Multi-Region Deployment:** Active-passive failover configuration
- **Advanced Security Monitoring:** Integration with AWS Security Hub

## File Structure

```
├── infrastructure/
│   ├── main.tf                    # Primary Terraform configuration
│   ├── variables.tf               # Input variables and validation
│   ├── outputs.tf                 # Resource outputs and URLs
│   ├── policies.rego             # OPA compliance policies
│   ├── lambda/
│   │   ├── index.js              # Compliance monitoring function
│   │   └── package.json          # Dependencies
│   └── terraform.tfvars.example  # Configuration template
├── website/                       # Static website files
├── scripts/
│   ├── deploy.sh                 # Complete deployment automation
│   ├── terraform-plan.sh         # Pre-deployment compliance check
│   └── test-policies.sh          # OPA policy testing
├── .github/workflows/
│   └── deploy-with-opa.yml       # GitHub Actions CI/CD pipeline
├── Makefile                      # Common operations
└── README.md                     # This file
```

## OPA Compliance Policies

### Current Policy Coverage

**Infrastructure Security:**
- S3 bucket encryption and versioning
- CloudFront HTTPS enforcement
- Required resource tagging
- Public access prevention

**What's Not Covered (Intentionally):**
- VPC configurations (static website doesn't need them)
- Database security (no databases in this architecture)
- Container security (using Lambda instead)

**Policy Example:**
```rego
# Enforce S3 encryption
s3_bucket_violations[violation] {
    input.resource.type == "aws_s3_bucket"
    not input.resource.encryption_enabled
    violation := {
        "type": "encryption_disabled",
        "message": "S3 bucket server-side encryption must be enabled",
        "severity": "HIGH"
    }
}
```

### Testing Policies Locally

```bash
# Test all policies against sample resources
make test-policies

# Test specific scenario
opa eval -d policies.rego -i test-input.json "data.terraform.compliance.compliance_report"
```

## Deployment Options

### Option 1: Automated (Recommended)
```bash
# Full pipeline with compliance checks
make pipeline
```

### Option 2: Manual Steps
```bash
# 1. Check compliance before deployment
make plan

# 2. Review and apply if compliant
make deploy

# 3. Sync website content
make sync-content
```

### Option 3: GitHub Actions
Push to `main` branch triggers automatic deployment with compliance validation.

## Security Considerations & Trade-offs

### Implemented Security Controls
- **Encryption at rest:** S3 server-side encryption
- **Encryption in transit:** CloudFront HTTPS enforcement
- **Access controls:** S3 bucket policies restrict to CloudFront
- **Compliance monitoring:** Daily automated checks

### Conscious Security Trade-offs
These features were excluded to balance security with cost for a personal website:

| Feature | Security Benefit | Cost Impact | Decision |
|---------|------------------|-------------|----------|
| CloudFront WAF | DDoS/attack protection | +$120/year | Skipped - static content low risk |
| Lambda in VPC | Network isolation | +$540/year | Skipped - no sensitive data processing |
| S3 access logging | Detailed audit trail | +$180/year | Skipped - CloudTrail provides sufficient logging |
| Multi-AZ deployment | High availability | +$300/year | Skipped - acceptable downtime for personal site |

**For Enterprise Use:** Re-enable these features by removing the `#checkov:skip` comments and adjusting budget accordingly.

## Troubleshooting Guide

### Common Issues

**1. OPA Policy Failures**
```bash
# Check policy syntax
opa fmt policies.rego

# Test against sample data
echo '{"resource":{"type":"aws_s3_bucket","tags":{}}}' | opa eval -I -d policies.rego "data.terraform.compliance"
```

**2. Terraform State Issues**
```bash
# Initialize with backend configuration
terraform init -backend-config="bucket=your-state-bucket"

# Import existing resources if needed
terraform import aws_s3_bucket.website your-bucket-name
```

**3. AWS Permission Errors**
Required IAM permissions for deployment:
- S3: GetBucket*, PutBucket*, DeleteBucket*
- CloudFront: Get*, List*, CreateInvalidation
- Lambda: CreateFunction, UpdateFunction, InvokeFunction
- IAM: CreateRole, AttachRolePolicy, PassRole

**4. SSL Certificate Issues**
```bash
# Verify certificate exists in us-east-1
aws acm list-certificates --region us-east-1

# Check certificate validation status
aws acm describe-certificate --certificate-arn <arn> --region us-east-1
```

## Cost Monitoring

Monitor actual costs with:
```bash
# Get current month's Lambda costs
aws ce get-cost-and-usage --time-period Start=2024-01-01,End=2024-01-31 --granularity MONTHLY --metrics BlendedCost --group-by Type=DIMENSION,Key=SERVICE

# Check compliance function execution frequency
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/samaydlette-com-opa-compliance"
```

## Advanced Configuration

### Multi-Environment Setup
```bash
# Deploy to staging
ENVIRONMENT=staging make deploy

# Production deployment
ENVIRONMENT=prod make deploy
```

### Custom Compliance Policies
Add new policies to `policies.rego`:
```rego
# Example: Enforce naming conventions
naming_violations[violation] {
    input.resource.type == "aws_s3_bucket"
    not startswith(input.resource.name, "company-")
    violation := {
        "type": "naming_convention",
        "message": "Bucket name must start with 'company-'",
        "severity": "MEDIUM"
    }
}
```

## Contributing

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-policy`)
3. **Test** your changes (`make test-policies`)
4. **Commit** with clear messages (`git commit -m 'Add cost optimization policy'`)
5. **Push** to your branch (`git push origin feature/amazing-policy`)
6. **Submit** a pull request

### Development Guidelines
- All new policies must include test cases
- Terraform changes require `checkov` scan approval
- Documentation updates required for new features
- Cost impact analysis required for infrastructure changes

## Real-World Applications

This repository demonstrates patterns used in:
- **Startup infrastructure:** Cost-conscious compliance automation
- **Enterprise security:** Policy-as-code implementation
- **DevSecOps training:** Practical compliance integration
- **Consulting projects:** Client infrastructure templates

## Monitoring & Alerts

### Built-in Monitoring
- **Compliance violations:** Logged to CloudWatch
- **Deployment status:** GitHub Actions notifications
- **Cost anomalies:** AWS Cost Anomaly Detection (configure separately)

### Optional Integrations
```bash
# Add Slack notifications
echo "SLACK_WEBHOOK_URL=https://hooks.slack.com/..." >> .env

# Enable email alerts
aws sns create-topic --name compliance-alerts
```

## License

MIT License - feel free to use this for personal or commercial projects.

## Support & Community

- **Issues:** Use GitHub Issues for bugs and feature requests
- **Discussions:** GitHub Discussions for questions and ideas
- **Security:** Email security issues privately to [your-email]

## Acknowledgments

- **OPA Community:** Policy examples and best practices
- **AWS Well-Architected Framework:** Security and cost optimization guidance
- **HashiCorp:** Terraform configuration patterns
- **Open Source Contributors:** Various tools and libraries used

---

**Important Notes:**
- This configuration is designed for existing AWS resources - it won't create your initial infrastructure
- Always test in a non-production environment first
- Review all security trade-offs against your specific requirements
- Costs may vary significantly based on traffic and usage patterns
