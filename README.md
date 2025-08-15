# Sam's Website for Everything Going On

This is the central hub for what's going on with me. This repository also shows how to build **compliance automation**. I use Open Policy Agent (OPA) to automatically check infrastructure security and accessibility standards.

## What This Repository Demonstrates About Compliance Automation

- **Pre-deployment validation** - Catch violations before they reach production
- **Real-world policy writing** - Beyond basic examples, see policies that handle edge cases
- **Cost-aware compliance** - How to balance security with budget constraints
- **Automated accessibility testing** - Section 508 compliance checking in CI/CD
- **Production monitoring** - Lambda functions that continuously check compliance

## How the Compliance Pipeline Works

```bash
# Every deployment goes through this compliance gate:
terraform plan → OPA policy check → deploy only if compliant

# Policies run against the infrastructure plan:
make pipeline
```

**What's Different:** Instead of checking compliance after deployment (when it's expensive to fix), we validate everything upfront. No non-compliant infrastructure ever gets created.

## Try It

You need:
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

**Annual Operating Costs for Compliance Pipeline:**
- **Lambda executions:** $12/year (daily compliance checks)
- **EventBridge rules:** $36/year
- **CloudWatch logs:** $77/year (7-day retention)
- **Total compliance overhead:** ~$125/year

**What's Not Covered (and why):**
- Website infrastructure costs (managed separately)
- Optional monitoring features that add $240-320/year

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

## OPA Policies

### What We Actually Check

**Infrastructure Security:**
- S3 bucket encryption and versioning
- CloudFront HTTPS enforcement
- Required resource tagging for cost allocation
- Public access prevention

**Section 508 Accessibility:**
- Alt text for all images
- HTML language declaration
- Proper heading structure
- Color-independent information

**What's Intentionally NOT Covered:**
- VPC configurations (static website doesn't need them)
- Database security (no databases in this architecture)
- Container security (using Lambda instead)

### Policy Development in Practice

```bash
# Test policies as you write them:
make test-policies

# Test specific scenarios:
opa eval -d policies.rego -i test-input.json "data.terraform.compliance.compliance_report"

# Debug policy failures:
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
opa eval -d policies.rego -i tfplan.json "data.terraform.compliance.compliance_report"
```

### Real Policy Example

```rego
# This actually runs in production:
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

## Deployment Options

### Automated (Recommended)
```bash
make pipeline    # Full pipeline with compliance checks
```

### Manual Steps
```bash
make plan       # Check compliance before deployment
make deploy     # Apply if compliant
make sync-content # Update website files
```

### CI/CD via GitHub Actions
Push to `main` branch triggers automatic deployment with compliance validation.

## Security Trade-offs (The Hard Decisions)

### What Is Implemented
- **Encryption everywhere:** S3 server-side encryption, CloudFront HTTPS enforcement
- **Access controls:** S3 bucket policies restrict to CloudFront only
- **Continuous monitoring:** Daily automated compliance checks

### Conscious Trade-offs for Budget Reality

| Feature | Security Benefit | Annual Cost | Our Decision |
|---------|------------------|-------------|--------------|
| CloudFront WAF | DDoS/attack protection | +$120 | **Skipped** - static content, low risk |
| Lambda in VPC | Network isolation | +$540 | **Skipped** - no sensitive data processing |
| S3 access logging | Detailed audit trail | +$180 | **Skipped** - CloudTrail provides basics |
| Multi-AZ deployment | High availability | +$300 | **Skipped** - acceptable downtime for personal site |

**For Enterprise Use:** Remove the `#checkov:skip` comments to enable these features.

**Why This Matters:** Real compliance automation means making informed trade-offs, not implementing every possible control regardless of context.

## When Things Break (And They Will)

### Common Compliance Failures and Fixes

**OPA Policy Failures**
```bash
# First, check your policy syntax:
opa fmt policies.rego

# Then test with minimal data:
echo '{"resource":{"type":"aws_s3_bucket","tags":{}}}' | opa eval -I -d policies.rego "data.terraform.compliance"
```

**Certificate Validation Issues**
```bash
# Check what's actually happening:
aws acm describe-certificate --certificate-arn <arn> --region us-east-1
```

**Lambda Compliance Monitor Failures**
```bash
# Check the logs first:
aws logs tail /aws/lambda/samaydlette-com-opa-compliance

# Then trigger manually to debug:
aws lambda invoke --function-name samaydlette-com-opa-compliance --payload '{}' result.json
```

**Deployment Stuck? Try Manual Steps**
```bash
# Sync files manually:
aws s3 sync . s3://samaydlette.com/ --exclude "*.tf" --exclude ".terraform/*" --delete

# Invalidate CloudFront cache:
aws cloudfront create-invalidation --distribution-id E1234567890123 --paths "/*"
```

### Debug Mode (When You're Really Stuck)

```bash
export TF_LOG=DEBUG
export AWS_CLI_FILE_ENCODING=UTF-8
./deploy.sh
```

**Pro Tip:** Most compliance automation failures happen during policy development, not in production. Test extensively with sample data before going live.

## License

MIT License - see LICENSE file for details.