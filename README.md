# Sam's Website for Everything Going On

This is the central hub for what's going on with me. The repository also doubles as a working example of **compliance automation**: every deploy passes an OPA policy gate, GitOps drives every change, and the pipeline derives two compliance reports from a single canonical inventory of the system's components — a Sigstore-signed FedRAMP 20x KSI signal and a NIST OSCAL Rev 5 System Security Plan, re-expressing the same state in two control vocabularies. A daily Lambda re-validates the live AWS configuration to keep both reports honest.

## What This Repository Demonstrates About Compliance Automation

- **Pre-deployment validation** — OPA evaluates the Terraform plan and the static content before any AWS resource is touched. Violations block the deploy.
- **Real-world policy writing** — Policies that go past trivial examples to handle attribute-only resources, content checks, and severity gating.
- **Cost-aware compliance** — Documented trade-offs for which controls are on, off, and why.
- **Automated accessibility testing** — Section 508 checks run in the same gate as the infrastructure checks; same shape, same reporting.
- **Continuous runtime validation** — A Lambda re-validates the live AWS configuration on a schedule against what was deployed.
- **A KSI signal informed by a canonical inventory** — Every deploy publishes a JSON document at `/.well-known/ksi-signal.json` containing (1) a snapshot of this system's canonical inventory (PURL for software, ARN paired with a normalized type for cloud resources, sha256 for static artifacts) and (2) policy results attached to specific inventory components by reference, signed via Sigstore keyless. The inventory is the layer; the signal is one report built on it. SBOMs, vulnerability scans, license reports, and configuration drift reports could all ride on the same layer. See [docs/ksi-signal.md](docs/ksi-signal.md) for the full reference.
- **An OSCAL Rev 5 System Security Plan** — Every deploy also generates and publishes a NIST OSCAL System Security Plan at `/.well-known/oscal-ssp.json`, deterministically derived from the canonical inventory and the FedRAMP KSI catalog. 331 NIST 800-53 Rev 5 implemented-requirements (the full FedRAMP Moderate baseline of 323 controls plus 8 KSI-extension controls) with differentiated `implementation-status` (74% implemented, 26% not-applicable, 0% partial) and FedRAMP-style `control-origination` (52% sp-system, 19% sp-corporate, 16% shared with AWS, 13% inherited) per control, plus an actual implementation statement per control rather than a mass-assigned default. Two views of the same truth: the KSI signal is the wire format; the OSCAL SSP is the human-and-tool-friendly compliance artifact.

## How the Compliance Pipeline Works

```bash
# Every deployment goes through this gate:
terraform plan
    → OPA policy check (infrastructure + accessibility)
    → terraform apply
    → build KSI signal (joins state + package-lock + content hashes + provenance + validations)
    → cosign sign-blob (Sigstore keyless via GitHub OIDC)
    → publish ksi-signal.json + ksi-signal.bundle to /.well-known/
    → invalidate CloudFront

# All run in one make target:
make pipeline
```

**What's Different:** Compliance is not just a gate. It is also an output. Every deploy emits a structured, signed KSI signal naming what was deployed, what was validated, and how to verify it. The signal is informed by a canonical inventory of components — names that are global by construction (PURL, ARN, sha256) — so a consumer can curl the document from any machine, validate it against the schema, verify the cosign bundle against the public Sigstore transparency log, and join validations to components by reference. The canonical inventory layer is what makes the signal compose across CSPs and across systems within a portfolio without a separate inventory deliverable; the signal is one report on top of it.

## KSI Signal

Every deploy emits a **KSI signal** at `/.well-known/ksi-signal.json` — a validation report informed by a canonical inventory of this system's components.

Two layers, one document:

- **Canonical inventory** (`components[]`): every component of this system named in canonical form. PURL for software (`pkg:npm/<name>@<version>`), ARN paired with a normalized type (`object_store`, `cdn_distribution`, `function`) for cloud resources, content hash for static artifacts, HBOM reference for hardware. Two reports of the same thing produce bit-identical identifiers, so anything referencing the inventory composes across systems without reconciliation.
- **Validation report** (`validations[]`): policy results from the OPA gate, each one attached to the specific inventory components it evaluated via `component_refs[]`. The report rides on the inventory layer.

The inventory is the architectural primitive. The signal is one report built on it. SBOMs, vulnerability scans, license reports, configuration drift reports could all be other reports referencing the same inventory layer; what composes across systems is whatever is built on the inventory, not just this one report.

The signal joins five sources into one document:

- **Cloud resources** from Terraform state, with the post-apply ARN as `native_id` and a normalized `type` (`object_store`, `cdn_distribution`, `function`).
- **Software components** from the Lambda's `package-lock.json`, identified by Package URL (`pkg:npm/<name>@<version>`).
- **Static artifacts** from every HTML file under `website/`, identified by SHA-256 content hash.
- **Provenance** from GitHub Actions environment variables (repository, commit SHA, workflow run ID).
- **Validations** from the OPA gate, each one carrying a `component_refs[]` array naming the specific inventory components it evaluated.

For a browser-friendly view of the live signal and SSP, see the [Live Trust Dashboard](https://samaydlette.com/viewer.html). For programmatic access:

```bash
# The signal is published live; anyone can fetch it.
curl -s https://samaydlette.com/.well-known/ksi-signal.json | jq '{
  signal_id, emitted_at, csp, system_id,
  component_count: (.components | length),
  validation_count: (.validations | length),
  attestation: .provenance.attestation.format
}'

# It is signed via Sigstore keyless; anyone can verify it.
curl -O https://samaydlette.com/.well-known/ksi-signal.json
curl -O https://samaydlette.com/.well-known/ksi-signal.bundle
cosign verify-blob \
  --bundle ksi-signal.bundle \
  --certificate-identity-regexp 'https://github.com/sam-aydlette/samaydlette.com/.github/workflows/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ksi-signal.json
```

A separate Lambda re-validates the live AWS configuration on a schedule and publishes a runtime signal at `/.well-known/ksi-signal-runtime.json` with the same shape but `emitter: "runtime"`. Drift between the deploy-time and runtime signals is detectable from outside.

For the schema, the component vocabulary, the join semantics, and the cross-CSP normalization decisions, see [docs/ksi-signal.md](docs/ksi-signal.md).

## OSCAL Rev 5 SSP

Alongside the KSI signal, every deploy generates a NIST OSCAL System Security Plan in the FedRAMP Rev 5 Moderate baseline shape, published at `/.well-known/oscal-ssp.json`.

```bash
curl -s https://samaydlette.com/.well-known/oscal-ssp.json | jq '{
  uuid: ."system-security-plan".uuid,
  oscal_version: ."system-security-plan".metadata."oscal-version",
  controls: (."system-security-plan"."control-implementation"."implemented-requirements" | length),
  components: (."system-security-plan"."system-implementation".components | length)
}'
```

The SSP is deterministically generated from two inputs: the canonical inventory in the live KSI signal, and the FedRAMP KSI catalog (`infrastructure/schemas/ksi-catalog.json`, source: FRMR.KSI). Each in-scope NIST 800-53 control is an `implemented-requirement` entry with a differentiated `implementation-status` (implemented / partial / not-applicable), a FedRAMP-style `control-origination` (sp-system / sp-corporate / shared / inherited), and an actual prose implementation statement — either explicit (for controls the system actively implements with traceable evidence) or family-level (for controls handled at the family level, with rationale that names how AWS-inherited / sole-operator-attested / N/A applies). Each requirement also links to (a) the contributing KSIs, (b) the live KSI signal as evidence, (c) the Sigstore bundle that signs it, and (d) the documentation file that records the implementation rationale. Reading the SSP at any time gives a Rev 5-shaped view of the same compliance state the KSI signal represents in 20x-shape; the two views never disagree because they're derived from the same source.

The SSP is not currently signed independently. The signed KSI signal is the verifiable root; the SSP references it as evidence. A natural extension would sign the SSP as well, with the same Sigstore chain.

For the full reference, see [docs/ksi-signal.md](docs/ksi-signal.md).

## Compliance Documentation

The repository ships a documentation set that closes 27 KSI indicators with rationales, runbooks, and review templates. Each file is referenced by the OSCAL SSP's per-control `links`, and by the KSI signal's `validations[]` indirectly via the OPA gate that produces them.

| File | KSIs addressed | Purpose |
|------|---------------|---------|
| [`docs/ksi-signal.md`](docs/ksi-signal.md) | KSI-PIY-01, KSI-MLA-07, KSI-CNA-08, KSI-SVC-05 | Schema, join semantics, normalization decisions, verification |
| [`docs/architecture-decisions.md`](docs/architecture-decisions.md) | KSI-CMT-04, KSI-CNA-01/03/05/06, KSI-IAM-04, KSI-MLA-01/02/08, KSI-PIY-04, KSI-SVC-01/06/08/09 | ADR-style records of architectural decisions per KSI |
| [`docs/incident-response.md`](docs/incident-response.md) | KSI-INR-01, KSI-INR-02, KSI-INR-03 | IR runbook with detection sources, triage, after-action template |
| [`docs/recovery-plan.md`](docs/recovery-plan.md) | KSI-RPL-01, KSI-RPL-02, KSI-RPL-03, KSI-RPL-04 | RTO 21 days / RPO 24 hours, recovery procedure, tabletop log |
| [`docs/security-review.md`](docs/security-review.md) | KSI-PIY-06 | Annual security review template + first entry |
| [`docs/supply-chain.md`](docs/supply-chain.md) | KSI-TPR-03, KSI-TPR-04 | SCRM with Dependabot config in `.github/dependabot.yml` |
| [`docs/training-log.md`](docs/training-log.md) | KSI-CED-01, KSI-CED-02, KSI-CED-03, KSI-CED-04 | Self-attested training log |
| [`docs/poam.md`](docs/poam.md) | (cross-cutting — meta) | Plan of Action & Milestones for tracked security gaps with remediation plans (kept in sync with `/.well-known/oscal-poam.json`) |
| [`docs/policies/`](docs/policies/) | NIST 800-53 Rev 5 *-1 controls (AC-1, AT-1, ... SR-1, PT-1) | Per-family policy and procedures docs, plus the FedRAMP 20x Secure Configuration Guide. Each file integrates the relevant 20x rules (SCN, VDR, MAS, SCG, CCM, ICP, FSI, UCM) and cites AWS authorization package AGENCYAMAZONEW for inherited families |
| [`docs/continuous-monitoring-plan.md`](docs/continuous-monitoring-plan.md) | CA-7, KSI-MLA, FedRAMP 20x CCM | Continuous Monitoring strategy and mechanisms (deploy-time gate, runtime emitter, VDR aggregator, annual review) |
| [`docs/privacy-threshold-analysis.md`](docs/privacy-threshold-analysis.md) | PT-1 (negative determination) | PTA: no PII processed; full PIA not required |
| [`docs/rules-of-behavior.md`](docs/rules-of-behavior.md) | PL-4 | Sole-operator acceptable-use commitments |
| [`website/.well-known/security.txt`](website/.well-known/security.txt) | KSI-PIY-03 | RFC 9116 vulnerability disclosure |

## Real-World Costs

**Annual Operating Costs (AWS list pricing):**
- **KMS customer-managed key (encryption at rest):** ~$12/year
- **Secrets Manager (2 secrets):** ~$10/year
- **Route 53 hosted zone:** ~$6/year
- **Lambda, EventBridge, CloudWatch, CloudFront, S3:** within the AWS free tier for this workload (~$0)
- **Total recurring:** ~$30/year (domain registration ~$13/year separate)

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
- **KSI Signal (informed by a canonical inventory):** Schema, deploy-time emitter, runtime emitter, and Sigstore-signed bundle published at `/.well-known/`. See [docs/ksi-signal.md](docs/ksi-signal.md).

### Example Implementation
- **Section 508 Accessibility:** Basic HTML validation (demonstrates concept)
- **Advanced OPA Policies:** Expanded beyond basic AWS resource checks
- **Multi-Environment Support:** Framework present, single environment configured

### Roadmap
- **Comprehensive Accessibility Testing:** Full WCAG 2.1 AA compliance automation
- **Multi-Region Deployment:** Active-passive failover configuration
- **Advanced Security Monitoring:** Integration with AWS Security Hub

### Tracked POA&M items

Known security gaps with remediation plans documented in [`docs/poam.md`](docs/poam.md):

- **POAM-001:** Migrate the deployer from long-lived AWS access keys to GitHub OIDC role assumption. (Medium severity; the Sigstore signing chain in this repo already proves the OIDC pattern works for cosign — POAM-001 extends it to AWS.)
- **POAM-002:** Sign the runtime KSI signal cryptographically (currently trusted implicitly via S3 + IAM). (Low for PoC, Medium in portfolio context; KMS asymmetric signing is the proposed approach.)

## Architecture

```
   ┌─────────────────────┐                AWS
   │  GitHub Actions     │     ┌─────────────────────────────────────────────┐
   │  ─────────────────  │     │                                             │
   │  - OPA gate         │ ──▶ │   ┌────────────────┐    ┌──────────────┐    │
   │  - terraform apply  │     │   │ S3: site files │ ◀─ │ CloudFront   │    │
   │  - build KSI signal │     │   │ /.well-known/  │    │ (TLS 1.2+,   │    │
   │  - cosign sign-blob │     │   └────────────────┘    │  HSTS, CSP)  │    │
   │  - sync to S3       │     │           ▲             └──────────────┘    │
   └─────────────────────┘     │           │                                 │
            │                  │   ┌───────┴────────┐                        │
            │                  │   │ Lambda:        │ ◀─── EventBridge       │
            ▼                  │   │ runtime KSI    │      (rate(1 day))     │
    /.well-known/              │   │ emitter        │                        │
    ksi-signal.json            │   └────────────────┘                        │
    ksi-signal.bundle          │                                             │
    ksi-signal.schema.json     └─────────────────────────────────────────────┘
    (deploy-time, signed)                                          │
                                                                   ▼
                                                       /.well-known/
                                                       ksi-signal-runtime.json
                                                       (continuously updated)
```

The pipeline produces five artifacts at `/.well-known/` — the FedRAMP 20x KSI signal (deploy-time + runtime), its Sigstore bundle, the schema both signals conform to, and the OSCAL Rev 5 SSP derived from them:

| Path | Producer | Cadence | Signed |
|------|----------|---------|--------|
| `/.well-known/ksi-signal.json` | CI emitter, `scripts/build-ksi-signal.py` | Every push to `main` | Yes (Sigstore keyless via GitHub OIDC) |
| `/.well-known/ksi-signal.bundle` | `cosign sign-blob` in CI | Every push to `main` | (the bundle itself) |
| `/.well-known/ksi-signal-runtime.json` | Lambda, `infrastructure/lambda/index.js` | EventBridge schedule (default daily) | No (PoC) — implicitly trusted via S3 + IAM |
| `/.well-known/ksi-signal.schema.json` | Static, `infrastructure/schemas/` | Republished on each deploy | No (informational) |
| `/.well-known/oscal-ssp.json` | CI generator, `scripts/build-oscal-ssp.py` | Every push to `main` | No (PoC) — references the signed KSI signal as evidence |

## File Structure

```
├── infrastructure/
│   ├── main.tf                    # Primary Terraform configuration
│   ├── variables.tf               # Input variables and validation
│   ├── outputs.tf                 # Resource outputs and URLs
│   ├── policies.rego              # OPA compliance policies
│   ├── schemas/
│   │   ├── ksi-signal.schema.json # JSON Schema for the KSI signal
│   │   └── ksi-catalog.json       # FedRAMP KSI catalog (FRMR.KSI source)
│   ├── lambda/
│   │   ├── index.js               # Runtime KSI signal emitter
│   │   └── package.json           # AWS SDK v3 dependencies
│   └── terraform.tfvars.example   # Configuration template
├── website/
│   ├── .well-known/
│   │   └── security.txt           # RFC 9116 vulnerability disclosure
│   └── ...                        # Static website files
├── scripts/
│   ├── deploy.sh                  # Complete deployment automation
│   ├── terraform-plan.sh          # Pre-deployment compliance check
│   ├── build-ksi-signal.py        # Deploy-time KSI signal emitter
│   ├── build-oscal-ssp.py         # OSCAL Rev 5 SSP generator
│   └── test-policies.sh           # OPA policy testing
├── docs/
│   ├── ksi-signal.md              # KSI signal technical reference
│   ├── architecture-decisions.md  # Architectural decisions per KSI
│   ├── incident-response.md       # IR runbook (KSI-INR-01..03)
│   ├── recovery-plan.md           # Recovery plan (KSI-RPL-01..04)
│   ├── security-review.md         # Annual security review (KSI-PIY-06)
│   ├── supply-chain.md            # Supply-chain risk (KSI-TPR-03/04)
│   ├── training-log.md            # Self-attested training (KSI-CED-01..04)
│   └── poam.md                    # Plan of Action & Milestones for tracked gaps
├── .github/workflows/
│   └── deploy-with-opa.yml        # GitHub Actions CI/CD pipeline
├── Makefile                       # Common operations
└── README.md                      # This file
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

## Try It

If you want to spin up a copy of this infrastructure to experiment with the pipeline:

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

| Feature | Security Benefit | Annual Cost | Decision | POA&M |
|---------|------------------|-------------|----------|-------|
| CloudFront WAF | DDoS/attack protection | +$120 | **Risk-accepted** — static content, low risk | [POAM-007](docs/poam.md) |
| Lambda in VPC | Network isolation | +$540 | **Risk-accepted** — no sensitive data processing | [POAM-010](docs/poam.md) |
| S3 access logging | Detailed audit trail | +$180 | **Risk-accepted** — CloudTrail provides the audit basics | [POAM-005](docs/poam.md) |
| Multi-region active-passive | Regional failover | +$300 | **Risk-accepted** — declared 21-day RTO accommodates regional failure | [POAM-016](docs/poam.md) |

The full register of risk-accepted items, including the 13 inline Checkov suppressions in `infrastructure/main.tf`, lives in [`docs/poam.md`](docs/poam.md) as POA&M entries with status `Risk-accepted`. This table is the budget-context summary; the POA&M is the authoritative register.

**For Enterprise Use:** Remove the `#checkov:skip` comments and reopen the corresponding POA&M entries to enable these features.

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