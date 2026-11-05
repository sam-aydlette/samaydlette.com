# Sam's Website for Everything Going On

This is the central hub for what's going on with me. The repository also doubles as a working example of **compliance automation**: every deploy passes an OPA policy gate, GitOps drives every change, and the pipeline derives two compliance reports from a single canonical inventory of the system's components — a Sigstore-signed FedRAMP 20x KSI signal and a NIST OSCAL Rev 5 System Security Plan, re-expressing the same state in two control vocabularies. A daily Lambda re-validates the live AWS configuration to keep both reports honest.

## What This Repository Demonstrates About Compliance Automation

- **Pre-deployment validation** — OPA evaluates the Terraform plan and the static content before any AWS resource is touched. Violations block the deploy.
- **Real-world policy writing** — Policies that go past trivial examples to handle attribute-only resources, content checks, and severity gating.
- **Cost-aware compliance** — Documented trade-offs for which controls are on, off, and why.
- **Automated accessibility testing** — pa11y (WCAG 2 AA in headless Chromium) produces facts; the same OPA gate makes the pass/fail decision and reporting. Scanners produce facts, OPA decides.
- **Continuous runtime validation** — A Lambda re-validates the live AWS configuration on a schedule against what was deployed.
- **A KSI signal informed by a canonical inventory** — Every deploy publishes a JSON document at `/.well-known/ksi-signal.json` containing (1) a snapshot of this system's canonical inventory (PURL for software, ARN paired with a normalized type for cloud resources, sha256 for static artifacts) and (2) policy results attached to specific inventory components by reference, signed via Sigstore keyless. The inventory is the layer; the signal is one report built on it. SBOMs, vulnerability scans, license reports, and configuration drift reports could all ride on the same layer. See [docs/ksi-signal.md](docs/ksi-signal.md) for the full reference.
- **A CR26 Security Decision Record in place of a System Security Plan** — Every deploy publishes a Security Decision Record at `/.well-known/security-decision-record.json` and a Certification Package Overview at `/.well-known/certification-package-overview.json`, deterministically derived from the canonical inventory and the FedRAMP KSI catalog. The SDR records how each KSI is met and, for each applicable NIST 800-53 Rev 5 control (the full FedRAMP Moderate baseline plus KSI-extension controls), its parameter values, implementation status, origination, mechanisms, verification and validation, including automatic downgrade to Partially Implemented while a contributing KSI is failing. The per-control view is the control projection in `scripts/_controls.py`. The OSCAL SSP that used to carry it was retired under CR26 on 2026-11-05.

## How the Compliance Pipeline Works

```
Every deployment goes through this gate, in CI:

  unit tests (pytest) + opa test + Regal + ruff/mypy
    → terraform plan → OPA policy check (infrastructure + accessibility)
    → [ prod environment: halts here for human approval ]
    → terraform apply
    → sync website/ to S3  (--exclude .well-known/*, which is published below)
    → build KSI signal   joins terraform state + package-lock + CycloneDX SBOMs
    │                    + every website/**/*.html sha256 + OPA validations
    │                    + SLSA-style build provenance
    ├─ build VDR + vuln trend ledger (RA-5(6))
    ├─ build IIW (SSP Appendix M)
    ├─ build SDR + CPO                ├─ build Ongoing Certification Report
    │                                 └─ build CDS certification-data artifacts
    │
    → RECONCILIATION GATE — fails closed on any cross-artifact drift
    │    (a) completeness   every live in-boundary AWS resource is inventoried,
    │                       enumerated from the cloud API, deny-by-default
    │    (b) referential    (c) suppressions     (d) impact level
    │    (e) binding — every artifact carries ONE inventory signal_id
    │    (f) publish freshness  (g) POA&M parity  (h) finding coverage
    │    (i) live classification tags  (j) POA&M refs  (k) retired
    │    (l) boundary map
    │
    → cosign sign-blob (Sigstore keyless via GitHub OIDC) for every artifact
    → publish the signed set to /.well-known/
    → in-toto/SLSA provenance attestation
    → invalidate CloudFront
    → post-publish round-trip verify (the served bytes carry THIS commit)
    → external verifier smoke test (the reciprocity handshake)
```

The gate and the publish step live in `.github/workflows/deploy-with-opa.yml` and
run nowhere else. **`make` never publishes** — see Deployment Options below.

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

For a browser-friendly view of the live signal and the CR26 record, see the [Trust Center](https://samaydlette.com/trust/index.html). For programmatic access:

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

## Security Decision Record (replaces the SSP)

Every deploy publishes the CR26 Security Decision Record at `/.well-known/security-decision-record.json`, signed and with an in-toto provenance attestation.

```bash
curl -s https://samaydlette.com/.well-known/security-decision-record.json | jq '{
  ksi_signal_id,
  ksi_records: (.rule_records | length),
  rev5_controls: (.rev5_controls | length)
}'
```

`rule_records` summarize each in-scope KSI (`SDR-CSX-KSI`); `rev5_controls` summarize each applicable Rev5 control (`SDR-CSF-CTF`): parameter values, implementation status, origination, the implementation statement, verification and validation. Both come from one control projection (`scripts/_controls.py`), computed from the canonical inventory in the live KSI signal and the FedRAMP KSI catalog (`infrastructure/schemas/ksi-catalog.json`, source: FRMR.KSI), so they cannot disagree. The SDR names the inventory it was built from (`ksi_signal_id`), and the reconciliation gate fails the deploy if it differs from the signal's.

For the full reference, see [docs/ksi-signal.md](docs/ksi-signal.md).

## Compliance Documentation

The repository ships a documentation set that closes 27 KSI indicators with rationales, runbooks, and review templates. Each file is referenced by the SDR's per-control `artifacts`, and by the KSI signal's `validations[]` indirectly via the OPA gate that produces them.

| File | KSIs addressed | Purpose |
|------|---------------|---------|
| [`docs/ksi-signal.md`](docs/ksi-signal.md) | KSI-PIY-GIV, KSI-MLA-LET, KSI-CNA-EIS, KSI-SVC-VRI | Schema, join semantics, normalization decisions, verification |
| [`docs/architecture-decisions.md`](docs/architecture-decisions.md) | KSI-CMT-RVP, KSI-CNA-RNT/ULN/RVP/OFA, KSI-IAM-JIT, KSI-MLA-OSM/RVL/ALA, KSI-PIY-RSD, KSI-SVC-EIS/ASM/PRR/VCM | ADR-style records of architectural decisions per KSI |
| [`docs/incident-response.md`](docs/incident-response.md) | KSI-INR-RIR, KSI-INR-RPI, KSI-INR-AAR | IR runbook with detection sources, triage, after-action template |
| [`docs/recovery-plan.md`](docs/recovery-plan.md) | KSI-RPL-RRO, KSI-RPL-ARP, KSI-RPL-ABO, KSI-RPL-TRC | RTO 21 days / RPO 24 hours, recovery procedure, tabletop log |
| [`docs/security-review.md`](docs/security-review.md) | KSI-PIY-RIS | Annual security review template + first entry |
| [`docs/supply-chain.md`](docs/supply-chain.md) | KSI-SCR-MIT, KSI-SCR-MON | SCRM with Dependabot config in `.github/dependabot.yml` |
| [`docs/training-log.md`](docs/training-log.md) | KSI-CED-RAT | Self-attested training log |
| [`data/decisions.json`](data/decisions.json) | (cross-cutting — meta) | The decision register: every decision about a finding (false positive, accepted risk, operational requirement, remediation history), with who decided, when, and the review date. Replaced the POA&M under CR26 |
| [`docs/policies/`](docs/policies/) | NIST 800-53 Rev 5 *-1 controls (AC-1, AT-1, ... SR-1, PT-1) | Per-family policy and procedures docs, plus the FedRAMP 20x Secure Configuration Guide. Each file integrates the relevant 20x rules (SCN, VDR, MAS, SCG, CCM, ICP, FSI, UCM) and cites AWS authorization package AGENCYAMAZONEW for inherited families |
| [`docs/continuous-monitoring-plan.md`](docs/continuous-monitoring-plan.md) | CA-7, KSI-MLA, FedRAMP 20x CCM | Continuous Monitoring strategy and mechanisms (deploy-time gate, runtime emitter, VDR aggregator, annual review) |
| [`docs/privacy-threshold-analysis.md`](docs/privacy-threshold-analysis.md) | PT-1 (negative determination) | PTA: no PII processed; full PIA not required |
| [`docs/rules-of-behavior.md`](docs/rules-of-behavior.md) | PL-4 | Sole-operator acceptable-use commitments |
| [`website/.well-known/security.txt`](website/.well-known/security.txt) | KSI-PIY-RVD | RFC 9116 vulnerability disclosure |

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

### Recorded decisions

The authoritative register is [`data/decisions.json`](data/decisions.json). Under CR26 the POA&M is retired (2026-11-04): open findings and their deadlines are in the published VDR report, and every human decision about a finding is a record in the register. Records carried over from the POA&M keep their number (POAM-007 is DEC-007) and their old ID in `former_id`; POAM-016 was retired before the migration. The register holds closed remediations, documented false positives, and in-force risk acceptances, each with its rationale and a review date.

Two early items this README used to track as open are now closed:

- **POAM-001** (closed 2026-06-15): the deployer was migrated from long-lived AWS access keys to GitHub OIDC role assumption; the legacy IAM user, its keys, and the repository secrets were deleted.
- **POAM-002** (closed 2026-06-17): the runtime KSI signal is signed with a KMS ECC P-256 key; the public key is published at `/.well-known/runtime-signing-pubkey.pem` and the signature travels in the signal's `provenance.attestation`.

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

The pipeline produces five artifacts at `/.well-known/` — the FedRAMP 20x KSI signal (deploy-time + runtime), its Sigstore bundle, the schema both signals conform to, and the Security Decision Record derived from them (the full list is in `infrastructure/schemas/freshness-config.json`):

| Path | Producer | Cadence | Signed |
|------|----------|---------|--------|
| `/.well-known/ksi-signal.json` | CI emitter, `scripts/build-ksi-signal.py` | Every push to `main` | Yes (Sigstore keyless via GitHub OIDC) |
| `/.well-known/ksi-signal.bundle` | `cosign sign-blob` in CI | Every push to `main` | (the bundle itself) |
| `/.well-known/ksi-signal-runtime.json` | Lambda, `infrastructure/lambda/index.js` | EventBridge schedule (default daily) | No (PoC) — implicitly trusted via S3 + IAM |
| `/.well-known/ksi-signal.schema.json` | Static, `infrastructure/schemas/` | Republished on each deploy | No (informational) |
| `/.well-known/security-decision-record.json` | CI generator, `scripts/build-sdr.py` | Every push to `main` | Yes (Sigstore keyless, plus an in-toto attestation) |

## File Structure

```
├── infrastructure/                 # the per-deploy Terraform stack
│   ├── main.tf variables.tf outputs.tf backend.tf
│   ├── cloudtrail.tf logging.tf cognito.tf silk-reeling.tf
│   ├── Makefile                    # local work only — never publishes
│   ├── terraform.tfvars.example    # copy to terraform.tfvars
│   ├── policy/                     # OPA policy packages
│   │   ├── gate.rego               # input contract + normalization (the only input reader)
│   │   ├── s3.rego cloudfront.rego tagging.rego accessibility.rego
│   │   ├── main.rego               # terraform.compliance aggregator
│   │   │                           #   walk(data.policy) + fail-closed + exceptions
│   │   ├── *_test.rego             # one test package per policy
│   │   ├── config/data.json        # organization-defined parameters (data, not code)
│   │   └── exceptions/data.json    # exceptions register (POA&M-as-code, dated + ticketed)
│   ├── schemas/                    # KSI signal schema, FedRAMP KSI catalog, policy-input schemas
│   ├── lambda/index.js             # runtime KSI emitter; runs the SAME Rego, compiled to Wasm
│   └── bootstrap/                  # operator-applied: OIDC, IAM, CloudFront, DNSSEC, tf state
├── scripts/                        # the artifact generators — 25 live
│   ├── _common.py                  # the shared helpers (classify, sha256_file, prop, ...)
│   ├── build-ksi-signal.py         # THE CANONICAL INVENTORY; everything derives from it
│   ├── _controls.py                # the control projection (per-control view)
│   ├── build-vdr-report.py build-iiw.py
│   ├── build-sdr.py build-cpo.py build-ocr.py ...
│   ├── reconcile.py                # the fail-closed reconciliation gate
│   ├── vuln-gate.py check-exceptions.py check-policy-annotations.py check-wasm-safe.py
│   ├── verify-published.sh         # verify the LIVE evidence, no AWS needed
│   └── staged/                     # NOT wired into the pipeline — see its README
├── website/                        # static site; every *.html is hashed into the inventory
│   ├── index.html trust/ pages/ assets/
│   ├── research/                   # methodology + scope docs; read these for the "why"
│   └── .well-known/security.txt    # RFC 9116 (generated artifacts are NOT committed)
├── data/                           # vendored NIST/FedRAMP source data + PROVENANCE.md
│   ├── catalogs/ profiles/ mappings/ baselines/ schemas/oscal/
├── policies/triage.rego            # vulnerability triage policy
├── docs/                           # policies/, scn/, runbooks/, assessment/
├── tools/                          # both are CI gates, not optional tooling
│   ├── a11y/                       # pa11y; renders every page and emits the facts
│   │                               #   policy.accessibility decides over. Installed by
│   │                               #   the blocking OPA job; terraform-plan.sh FAILS
│   │                               #   CLOSED if it is missing.
│   └── essay/                      # anchor/footnote/bibliography integrity for the
│                                   #   long-form pages. Enforced by tests/test_essay_
│                                   #   gates.py, which runs both gates against the real
│                                   #   committed pages on every pytest run.
├── tests/                          # 300+ tests: one per gate invariant
│   ├── fixtures/broken/            # committed must-FAIL fixtures — the gate's negative
│   ├── fixtures/clean/ plans/      # hermetic inputs
│   └── golden/                     # frozen pre-refactor baseline + current OPA goldens
└── .github/workflows/
    ├── deploy-with-opa.yml         # the pipeline: gates, generation, signing, publish
    ├── zap-dast.yml scn-tag.yml
```


## OPA Policies

### What We Actually Check

**Infrastructure Security:**
- S3 bucket encryption and versioning
- CloudFront HTTPS enforcement
- Required resource tagging for cost allocation
- Public access prevention

**Section 508 Accessibility:**
- pa11y renders every page in headless Chromium and checks WCAG 2 AA
  (alt text, language, labels, ARIA names, contrast — things string
  matching can't see)
- OPA decides over the scanner's JSON facts: which issue types fail the
  gate is configuration, and accepted findings go through the exceptions
  register with justification + expiry, staying visible under `excepted`

**What's Intentionally NOT Covered:**
- VPC configurations (static website doesn't need them)
- Database security (no databases in this architecture)
- Container security (using Lambda instead)

### Policy Development in Practice

The gate is a set of OPA packages under `infrastructure/policy/`, one per
domain, each emitting uniform violation objects; the aggregator
(`terraform.compliance`) discovers every `violations` set under
`data.policy` dynamically, so a new policy package participates with zero
aggregator edits. The decision is fail-closed (`default compliant := false`),
unreadable input yields an explicit `input_error`, enforcement parameters
live in `config/data.json` (800-53 organization-defined parameters as data),
accepted findings live in `exceptions/data.json` with justification + expiry
(POA&M-as-code), and every rule's METADATA carries its NIST/KSI lineage —
diffed against the KSI catalog in CI. The same source is compiled to Wasm
for the runtime Lambda; a CI parity test proves both evaluators agree.

```bash
# Test policies as you write them (from the repo root):
opa test infrastructure/policy/

# Test a specific scenario against a checked-in fixture:
opa eval --strict-builtin-errors -d infrastructure/policy/ \
    -i tests/fixtures/plans/s3-missing-tags.json \
    "data.terraform.compliance.compliance_report"

# Debug policy failures against a real plan — the policy consumes raw
# `terraform show -json` output directly (run in infrastructure/):
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
opa eval --strict-builtin-errors -d policy/ -i tfplan.json "data.terraform.compliance.compliance_report"
```

The policy fails closed: input that matches none of its supported shapes
(a plan's `resource_changes[]`, a single `{resource}`, or
`{html_content, file_name}`) yields an explicit `input_error` violation and
`"compliant": false` — never a vacuous pass.

### Real Policy Example

```rego
# This actually runs in production:
s3_bucket_violations contains violation if {
    some r in resources
    r.type == "aws_s3_bucket"
    not r.encryption_enabled
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
curl -L -o opa https://openpolicyagent.org/downloads/v1.18.2/opa_linux_amd64_static
echo "9903e5125ac281104f2c4b7371d10cc3b74a98933743fcbfc174f9bf0ab20de8  opa" | sha256sum -c -   # published hash for v1.18.2
chmod 755 ./opa && sudo mv opa /usr/local/bin

# 3. Configure your deployment
cp infrastructure/terraform.tfvars.example infrastructure/terraform.tfvars
# Edit terraform.tfvars with your AWS resource IDs

# 4. Apply the infrastructure locally (this publishes nothing)
cd infrastructure
make plan          # OPA compliance check against the plan
make pipeline      # init + validate + plan + apply-infra

# 5. Run the offline gates
make python-test test-policies a11y
make reconcile     # add RECONCILE_FLAGS=--live to reconcile against live AWS
```

Content and the `/.well-known/` artifacts are published only by the CI deploy job.
That is deliberate: a local publish would put an unsigned, unreconciled, partial
artifact set over the published one, breaking the cross-artifact `signal_id`
binding on the live site — with the gate that exists to catch exactly that never
having run.

## Deployment Options

### Publishing: CI only
Push to `main`. The workflow runs the gates, then **halts** — the `deploy` job is
bound to the `prod` GitHub Environment, which requires a human reviewer before
`terraform apply`. Approve it in the Actions UI and the run continues through the
reconciliation gate, signing, and publish. The nightly scheduled run halts the
same way.

There is no local publish target, by design.

### Local: infrastructure and the offline gates
```bash
cd infrastructure
make plan          # terraform plan + OPA compliance check
make apply-infra   # apply the reviewed plan; stops there, publishes nothing
make pipeline      # init + validate + plan + apply-infra

make gate          # OPA gate against a plan
make python-test   # pytest
make test-policies # opa test + coverage floor
make a11y          # pa11y scan (produces the facts the a11y policy decides over)
make figures-check # dashboard figures vs. their sources
make essay-check   # essay + homepage structure and citations (local only)
make reconcile     # cross-artifact reconciliation (RECONCILE_FLAGS=--live)
```

### Verifying what is actually published
```bash
make verify-published   # fetch the LIVE evidence and reproduce the verdict
```
Needs no AWS credentials and no secrets — it verifies the cosign signatures against
the public Sigstore transparency log and re-runs the cross-artifact reconciliation
over the served bytes. Anyone can run it.

## Security Trade-offs (The Hard Decisions)

### What Is Implemented
- **Encryption everywhere:** S3 server-side encryption, CloudFront HTTPS enforcement
- **Access controls:** S3 bucket policies restrict to CloudFront only
- **Continuous monitoring:** Daily automated compliance checks

### Conscious Trade-offs for Budget Reality

| Feature | Security Benefit | Annual Cost | Decision | Record |
|---------|------------------|-------------|----------|-------|
| CloudFront WAF | DDoS/attack protection | +$120 | **Risk-accepted** — managed interfaces + Shield Standard + throttling cover SC-7/SC-5; WAF's incremental layer-7 filtering is the documented residual | [DEC-007](data/decisions.json) |
| Lambda in VPC | Network isolation | +$540 | **Risk-accepted** — no sensitive data processing | [DEC-010](data/decisions.json) |
| S3 access logging | Detailed audit trail | ~$0 at current traffic | **Implemented** (2026-06-18) — S3 server-access + CloudFront logs delivered to a dedicated locked-down log bucket | [DEC-005](data/decisions.json) (closed) |
| Multi-region active-passive | Regional failover | +$300 | **Risk-accepted** — declared 21-day RTO accommodates regional failure ([recovery plan](docs/recovery-plan.md)) | POAM-016 (retired) |

The full register of dispositions — closed remediations, documented false positives, and open risk acceptances, including the scanner suppressions carried with inline rationale — lives in [`data/decisions.json`](data/decisions.json). This table is the budget-context summary; the register is authoritative.

## When Things Break (And They Will)

### Common Compliance Failures and Fixes

**OPA Policy Failures**
```bash
# First, check your policy syntax:
opa fmt --list policy/

# Then test with minimal data:
echo '{"resource":{"type":"aws_s3_bucket","tags":{}}}' | opa eval -I -d policy/ "data.terraform.compliance"
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