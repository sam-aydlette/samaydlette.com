# Architecture and Operational Decisions

This document records the architectural and operational decisions that satisfy 14 of the in-scope KSI indicators. Each decision is named, justified briefly, and tagged with the KSI it addresses. The shape is loosely modeled on Architectural Decision Records (ADRs) but compressed for a one-person operation that does not need formal stakeholder sign-off.

## Change management procedures (KSI-CMT-04)

Change management is GitOps, full stop. Every change to infrastructure or content reaches production through a pull request to `main`, which triggers the OPA gate, the Terraform plan, the apply, the canonical inventory build, the Sigstore signing, and the publish — all visible in the GitHub Actions log.

There is no separate change-management ticketing system because there is no separate change-management team. The PR is the change request, the review (when applicable), and the approval. For solo work, the diff itself serves all three roles.

**Effectiveness review:** monthly, by checking that no commits have reached `main` outside the workflow. The git log makes this trivial; the runtime KSI signal makes drift detectable.

## Ingress and egress restriction (KSI-CNA-01)

The system has exactly one ingress: CloudFront, fronting an S3 bucket whose public access is fully blocked. CloudFront's origin access is restricted to the bucket via a service-principal policy with a `SourceArn` condition; no other principal can read the bucket directly. There is no public ingress to any compute resource.

Egress: the Lambda calls AWS APIs for S3 and CloudFront within the account. The Lambda has no internet egress and no NAT gateway. Outbound traffic from the Lambda to AWS service endpoints stays within the AWS network.

There are no other ingress or egress paths to control because there are no other moving parts.

## Traffic flow controls (KSI-CNA-03)

The system has two logical paths: viewer→CloudFront→S3 (read-only, all viewers) and Lambda→AWS API (scoped via IAM). There is no internal east-west traffic to control. The IAM policy on the Lambda role is the entire traffic-flow control mechanism for the only non-public path that exists.

## DDoS and unwanted-activity protection (KSI-CNA-05)

CloudFront includes AWS Shield Standard at no cost; this is the baseline protection. AWS WAF was evaluated and consciously excluded as a cost trade-off (~$120/year) documented in the README. The threat model for a static personal site does not justify it: there are no forms, no authentication endpoints, no APIs, and no expensive backend resources to protect from request floods. Shield Standard handles the L3/L4 cases that exist.

**Effectiveness review:** annually (see [`security-review.md`](security-review.md)). If traffic patterns change or the threat profile shifts (e.g., the site starts serving forms or APIs), the WAF decision is revisited.

## High availability (KSI-CNA-06)

The system uses single-region AWS managed services (S3, CloudFront, Lambda, ACM, Route 53). CloudFront is global by design. S3 has 11-nines durability within a region. The declared RTO of 21 days (see [`recovery-plan.md`](recovery-plan.md)) accommodates regional failure scenarios; multi-region active-passive was excluded as a cost trade-off (~$300/year). For a personal site, "highly available" is the AWS default; "highly available with regional failover" is overkill.

## Just-in-time authorization (KSI-IAM-04)

The Lambda IAM role is fixed-scope, not just-in-time. Rationale: the Lambda has exactly one job (read deploy signal, query S3+CloudFront config, publish runtime signal), exactly one schedule (daily, plus manual invocation for testing), and exactly one trust principal (the EventBridge rule). The benefit JIT is meant to deliver — reduction of standing privilege — is achieved here by reducing scope to the absolute minimum: read-only on three S3 config APIs, read-only on one specific CloudFront distribution, write to one specific S3 key. The role has no human-assumable trust policy.

JIT machinery (e.g., AWS Identity Center session-bound access) would add operational complexity without reducing the effective standing-privilege surface, which is already as small as the Lambda's job admits.

## SIEM-equivalent logging (KSI-MLA-01)

CloudWatch Logs is the SIEM equivalent for this system. Sources collected:

- Lambda execution logs (via the Lambda runtime's standard logging integration)
- CloudFront access logs — currently excluded for cost; revisit if any incident response would have benefited from them
- CloudTrail (account-wide) — captures all AWS API calls, including the deployer's

For a two-resource, one-Lambda system, this is meaningfully a SIEM. Tamper resistance: log groups have 7-day retention and CloudTrail is account-managed, so logs are write-once from the producing service. The deployer credentials cannot delete CloudTrail logs without an additional IAM action that is not granted by default.

If the system grew to require true SIEM features (correlation rules, alerting, longer retention), the next step would be Amazon Security Lake or a third-party SIEM ingesting from CloudWatch. Out of scope today.

## Audit log review cadence (KSI-MLA-02)

Quarterly. Specifically:

- Review CloudTrail for any unexpected API calls (especially IAM and CloudFront writes from non-CI principals)
- Review Lambda execution logs for runtime KSI emitter failures
- Review GitHub Actions workflow run history for unexpected workflow modifications

A no-finding review does not require a commit. Anomalies are recorded in [`security-review.md`](security-review.md) with a date and disposition.

## Log access scoping (KSI-MLA-08)

Log access is scoped via AWS IAM. The deployer credentials have CloudWatch Logs read access account-wide; the Lambda role has none. No other principal exists in the system.

## CISA Secure-by-Design alignment (KSI-PIY-04)

This system aligns with CISA Secure-by-Design principles by design and by accident, both:

- **Memory safety:** N/A (no native code; the only compute is a short-lived Node.js Lambda)
- **Eliminate default passwords:** No passwords in this system; AWS root requires MFA, deployer credentials are GitHub Actions encrypted secrets, signing is keyless
- **Single sign-on:** GitHub for repo access, AWS for cloud access
- **Provenance for software components:** the canonical inventory carries PURL, ARN, and content hashes for every component; the deploy chain is signed via Sigstore; the bundle is verifiable against the public Rekor transparency log
- **Vulnerability disclosure:** see [`/.well-known/security.txt`](../website/.well-known/security.txt)
- **Build secure software through a secure SDLC:** policy-as-code OPA gate before every deploy, with a runtime re-validator confirming what was deployed still matches what was claimed

The CISA Secure-by-Design pledge has 7 goals; this system addresses or trivially satisfies all of them by virtue of the technology stack and the deployment discipline.

## Continuous improvement (KSI-SVC-01)

Continuous improvement is mechanized through the runtime KSI signal. Drift between the deploy-time signal and the runtime signal is the primary improvement signal. Each detected drift event triggers a fix in the policy or the implementation, recorded in the git log.

The annual security review (see [`security-review.md`](security-review.md)) is the human-layer continuous improvement loop.

## Secret management (KSI-SVC-06)

Secrets in scope:

- **AWS access keys (deployer):** stored as GitHub Actions encrypted secrets; rotated annually as part of the security review.
- **TLS certificate:** ACM-managed, auto-rotated by AWS.
- **GitHub PATs:** none in use. All GitHub access uses the workflow's `GITHUB_TOKEN` with workflow-scoped permissions, plus the OIDC token for cosign keyless signing (which is ephemeral).
- **Sigstore signing identity:** ephemeral, generated per-run by Fulcio, never stored anywhere.

The keyless signing chain is the single biggest reduction in secret-management surface area for this system: there is literally no signing key to manage, rotate, or lose.

## Prevent residual risk (KSI-SVC-08, mod-only)

Post-deploy verification covers residual-risk inspection. The runtime KSI emitter validates the live state every day and would surface any residual misconfiguration that survived a deploy. CloudFront cache invalidation is part of every deploy to remove residual cached content. S3 versioning preserves prior states for rollback if a deploy introduces unwanted residue.

This indicator is low-risk for this system because the system has nothing to leave behind — no per-customer state, no temporary files, no configuration that should change between customers (because there are no customers in the FedRAMP sense).

## Threat Modeling (NIST SA-11.2)

Token threat model, sized to the system's actual blast radius. Methodology: STRIDE applied informally to each component in the canonical inventory.

**In-scope assets and threat surfaces:**

- The deploy chain: GitHub repository, GitHub Actions runners, the deployer credentials, the cosign signing flow.
- The runtime emitter: the Lambda execution role, the S3 write surface, the CloudFront read path.
- The published artifacts: `/.well-known/ksi-signal.json`, `/.well-known/ksi-signal.bundle`, `/.well-known/oscal-ssp.json`, `/.well-known/ksi-signal-runtime.json`, the static site content under `s3://samaydlette.com/`.
- The verification chain: Sigstore Fulcio, Rekor, the GitHub OIDC issuer.

**Top threats considered:**

1. **GitHub repository compromise → arbitrary deploy.** An attacker with write access to `main` can push code that the OPA gate would have to flag. *Mitigations:* GitHub branch protection on `main`, OPA gate evaluating Terraform plan + content + IAM policy on every PR, Sigstore signing chain that records every produced artifact in the public Rekor log so a falsified deploy is externally detectable.
2. **Deployer credential leak → AWS account access.** The long-lived AWS access keys in GitHub Actions secrets are the largest standing-privilege surface. *Mitigations:* GitHub secret scanning with push protection, scoped IAM permissions on the deployer principal, planned migration to GitHub OIDC role assumption (POAM-001).
3. **Runtime Lambda compromise → falsified runtime signal.** An attacker with Lambda code-modification access could publish misleading runtime KSI signals. *Mitigations:* tight Lambda IAM (write only to one S3 key, read-only on three S3 config APIs and one CloudFront distribution), drift between deploy-time and runtime signals is detectable from outside, runtime signal is not currently signed (POAM-002).
4. **Sigstore-chain compromise.** A compromise of Fulcio, Rekor, or the GitHub OIDC issuer would invalidate the signing chain. *Mitigations:* none operator-side — these are public infrastructure components with thousands of independent observers; compromise of any one is detectable by anyone running independent verification.
5. **Bucket policy weakening.** A change to the S3 bucket policy or public-access block that re-enabled public read or write. *Mitigations:* OPA gate at deploy time blocks the change; runtime KSI emitter detects the drift within 24 hours.

**Threats accepted as out-of-scope:**

- DDoS at scales beyond AWS Shield Standard (consciously skipped WAF; no high-value target on the site)
- Side-channel attacks on the underlying AWS infrastructure (inherited from AWS authorization)
- Insider threat on the operator's personal endpoints (operator's laptop is outside system boundary)

**Vulnerability analysis** is automated through the SAST/SCA tools described under SA-11 (Checkov, tfsec, Dependabot). Annual review of the threat model occurs in [`security-review.md`](security-review.md).

## Communication integrity (KSI-SVC-09, mod-only)

Cross-component communications:

- viewer ↔ CloudFront: TLS 1.2+
- CloudFront ↔ S3: TLS within the AWS network, with origin authentication via service principal + SourceArn
- Lambda ↔ AWS service APIs: TLS within the AWS network
- CI ↔ AWS APIs: TLS, with credentials scoped via IAM

Authenticity at the application layer: the canonical inventory is signed (KSI-SVC-05). Communication integrity at the transport layer is AWS-default TLS. End-to-end signed-message integrity at the application layer beyond the signed signal is not implemented because no application-layer protocol exists between components beyond the standard AWS APIs.
