# Architecture and Operational Decisions

This document records the architectural and operational decisions that satisfy 14 of the in-scope KSI indicators. Each decision is named, justified briefly, and tagged with the KSI it addresses. The shape is loosely modeled on Architectural Decision Records (ADRs).

## Change management procedures (KSI-CMT-RVP)

Change management is GitOps, full stop. Every change to infrastructure or content reaches production through a pull request to `main`, which triggers the OPA gate, the Terraform plan, the apply, the canonical inventory build, the Sigstore signing, and the publish — all visible in the GitHub Actions log.

There is no separate change-management ticketing system because there is no separate change-management team. The PR is the change request, the review (when applicable), and the approval. For solo work, the diff itself serves all three roles.

**Effectiveness check:** automated, every night. The audit-log review (`scripts/audit-log-review.py`, published as `/.well-known/vdr-audit-log-review.json`) lists every commit on `main` since the previous run and flags any without a merged pull request, any workflow change outside one, and any ruleset or environment changed in the window; the runtime KSI signal makes drift detectable.

## Ingress and egress restriction (KSI-CNA-RNT)

The system has two ingress paths:

1. **CloudFront → S3** for the static site: the bucket's public access is fully blocked and CloudFront's origin access is restricted via a service-principal policy with a `SourceArn` condition; no other principal can read the bucket directly.
2. **API Gateway → Silk Reeling Lambda** for the gated app: the HTTP API's data routes (`ANY /api/{proxy+}`) require a Cognito JWT authorizer, the stage is throttled (20 req/s, burst 10), and access-logged. This is the only public ingress to compute, added with SCN-2026-001.

Egress: the compliance Lambda calls AWS APIs only, within the AWS network — no internet egress, no NAT gateway. The Silk Reeling Lambda calls no third-party service: it writes feedback text from the scores itself, and its only outbound call is to the Cognito user pool's public signing-key (JWKS) endpoint over TLS. It runs outside a VPC, so that limit is set by its code and configuration, not a network control. The app's optional LLM-written feedback is customer-configurable and disabled in this deployment; the Anthropic interconnection it used was removed under [SCN-2026-006](scn/SCN-2026-006-remove-anthropic-interconnection.md) (formerly POAM-020).

## Traffic flow controls (KSI-CNA-ULN)

The system has three logical paths: viewer→CloudFront→S3 (read-only, all viewers), authenticated user→API Gateway→Silk Reeling Lambda (JWT-gated, throttled), and compliance Lambda→AWS APIs (scoped via IAM). There is no internal east-west traffic to control; the IAM policies on the two Lambda roles and the gateway authorizer are the traffic-flow control mechanisms for the non-public paths.

## DDoS and unwanted-activity protection (KSI-CNA-RVP)

CloudFront includes AWS Shield Standard at no cost; this is the baseline protection. AWS WAF was evaluated and consciously excluded as a cost trade-off (~$120/year) documented in the README and POAM-007. Since the Silk Reeling app was added, the system does have an authentication endpoint and an API — those are protected by API Gateway stage throttling (20 req/s, burst 10), Cognito account lockout, and Shield Standard, which together cover the SC-5 cases at this scale. POAM-023's closure keeps a standing trigger: credential-guessing evidence in the app's logs forces the WAF rate-rule immediately.

**Effectiveness check:** the Annual Security Review (`scripts/hold-security-review.py`, [`security-review.md`](security-review.md)) fails when a component type added since the previous review, such as a new form or API, is not named in this section or the threat model, so a change in the threat profile reopens the WAF decision through a reviewed pull request.

## High availability (KSI-CNA-OFA)

The system uses single-region AWS managed services (S3, CloudFront, Lambda, ACM, Route 53). CloudFront is global by design. S3 has 11-nines durability within a region. The declared RTO of 21 days (see [`recovery-plan.md`](recovery-plan.md)) accommodates regional failure scenarios; multi-region active-passive was excluded as a cost trade-off (~$300/year). For a personal site, "highly available" is the AWS default; "highly available with regional failover" is overkill.

## Just-in-time authorization (KSI-IAM-JIT)

The Lambda IAM role is fixed-scope, not just-in-time. Rationale: the Lambda has exactly one job (read deploy signal, query S3+CloudFront config, publish runtime signal), exactly one schedule (daily, plus manual invocation for testing), and exactly one trust principal (the EventBridge rule). The benefit JIT is meant to deliver — reduction of standing privilege — is achieved here by reducing scope to the absolute minimum: read-only on three S3 config APIs, read-only on one specific CloudFront distribution, write to one specific S3 key. The role has no human-assumable trust policy.

JIT machinery (e.g., AWS Identity Center session-bound access) would add operational complexity without reducing the effective standing-privilege surface, which is already as small as the Lambda's job admits.

## SIEM-equivalent logging (KSI-MLA-OSM)

CloudWatch Logs is the SIEM equivalent for this system. Sources collected:

- Lambda execution logs (via the Lambda runtime's standard logging integration; 365-day retention, customer-CMK encrypted — POAM-017/018)
- API Gateway access logs for the Silk Reeling HTTP API (same retention and encryption — POAM-024)
- S3 server access logs and CloudFront access logs, delivered to the dedicated locked-down log bucket (POAM-005, C-3; 400-day lifecycle)

- CloudTrail management events (all AWS API activity, including the deploy
  role's), captured by a multi-region trail with log-file validation and
  delivered to a dedicated TLS-only bucket with AU-11 retention tiering
  (12 months active, Deep Archive to 30 months, then expire)

For a small single-account system this is meaningfully a SIEM. Tamper
resistance: log groups are write-once from the producing services, retained
365 days under a customer CMK; the trail's log-file validation makes
after-the-fact tampering detectable; and the deploy role deliberately holds no
`cloudtrail:StopLogging` / `cloudtrail:DeleteTrail`, so the automated pipeline
cannot silence the audit record.

Alerting today is scoped to evidence freshness: the evidence SLA watchdog (`infrastructure/watchdog.tf`) pages the operator by email when published reporting goes stale or the nightly refresh fails. If the system grew to require true SIEM features (correlation rules, alerting on control-plane events, longer retention), the next step would be Amazon Security Lake or a third-party SIEM ingesting from CloudWatch. Out of scope today.

## Audit log review (KSI-MLA-RVL)

Automated, every night: `scripts/audit-log-review.py` runs in `evidence-nightly.yml` and publishes `/.well-known/vdr-audit-log-review.json`, signed. It:

- reads CloudTrail's event history (`cloudtrail:LookupEvents`, write events only, in us-east-1 and us-east-2) for IAM, CloudFront, KMS, Lambda, Cognito, CloudTrail and S3 bucket-policy or public-access writes, and flags any whose principal is not one of the five CI roles, AWS itself, or a Cognito app user's own sign-in (capture depth is documented in the SIEM section above);
- reads GitHub's record of `main` (commits and their merged pull requests, workflow changes, rulesets and environments) and flags any change outside a merged pull request;
- evaluates each flagged event by rule (IEC-CSO-EFR): one that stops or reconfigures the trail, creates long-lived credentials or a user, disables a key or removes a public access block is a possible FedRAMP Reportable Incident and fails the nightly; any other is a process finding in the VDR (gate check `audit-log.unexpected`);
- plants two events from a plainly simulated intruder, Mallory McHypothetical (simulated), on every run and fails unless both are caught and evaluated reportable.

The emitter's failures are covered by the evidence watchdog and the runtime signal's freshness, not by reading its logs. Nobody reads the logs by hand.

## Log access scoping (KSI-MLA-ALA)

Who may read log data is an allowlist in the policy configuration (`infrastructure/policy/config/data.json`, `gate.log_access.readers`). Each entry names one reader, the actions and the log resources it may read, the basis for it, and who decided it. The OPA rule `log_read_grant_unexpected` (`infrastructure/policy/iam.rego`) fails the deploy gate when an IAM policy (inline or customer-managed) or the policy of a log bucket (the access-log and CloudTrail buckets) grants a read of log content outside an entry: objects in a log bucket, CloudWatch Logs events and queries, or the CloudTrail event history. A broader grant to a listed reader still fails. The rule runs over the per-deploy stack's plan and over the trust root's plan on every deploy, and the runtime emitter re-applies it daily to the live inline policies. Its known-bad case, Curious Carl (simulated), an intern handed log reads "just to look around", must be stopped on every test run (`tests/fixtures/plans/log-read-grant-curious-carl.json`).

Two readers are listed, both decided by the operator on 2026-11-06:

- the deploy role reads the CloudFront access records under the access-log bucket's CloudFront prefixes, to build the aggregate access summary (CDS-TRC-ACL);
- the nightly evidence role reads the CloudTrail event history for the automated audit-log review (DEC-195).

The plan role's AWS-managed ReadOnlyAccess is denied log-event reads by its own inline policy. Neither Lambda role can read logs. The rule does not cover AWS-managed policies attached by ARN, because their documents are not in the plan or the runtime input. Two such attachments grant log reads: the operators group, which the operator's IAM user belongs to, holds AWSLambda_FullAccess, which includes CloudWatch Logs event reads; the read-only group holds ReadOnlyAccess, which reads log buckets and log events.

## CISA Secure-by-Design alignment (KSI-PIY-RSD)

This system aligns with CISA Secure-by-Design principles by design and by accident, both:

- **Memory safety:** N/A (no native code; compute is a short-lived Node.js Lambda and a Python 3.13 Lambda)
- **Eliminate default passwords:** No default or shared passwords; the app's Cognito pool enforces a 14-character policy with mandatory TOTP MFA, AWS root requires MFA, CI deploys via ephemeral OIDC role assumption, signing is keyless
- **Single sign-on:** GitHub for repo access, AWS for cloud access
- **Provenance for software components:** the canonical inventory carries PURL, ARN, and content hashes for every component; the deploy chain is signed via Sigstore; the bundle is verifiable against the public Rekor transparency log
- **Vulnerability disclosure:** see [`/.well-known/security.txt`](../website/.well-known/security.txt)
- **Build secure software through a secure SDLC:** policy-as-code OPA gate before every deploy, with a runtime re-validator confirming what was deployed still matches what was claimed

The CISA Secure-by-Design pledge has 7 goals; this system addresses or trivially satisfies all of them by virtue of the technology stack and the deployment discipline.

## Continuous improvement (KSI-SVC-EIS)

Continuous improvement is mechanized through the runtime KSI signal. Drift between the deploy-time signal and the runtime signal is the primary improvement signal. Each detected drift event triggers a fix in the policy or the implementation, recorded in the git log.

The Annual Security Review (`scripts/hold-security-review.py`, see [`security-review.md`](security-review.md)) is the yearly loop: it re-checks every document, the component types against the threat model, decisions, findings, incident patterns and recurring cost, and a failing item fails the run until a pull request fixes it.

## Secret management (KSI-SVC-ASM)

Secrets in scope:

- **Deployer credentials:** none stored. CI deploys via GitHub OIDC role assumption ([POAM-001](../data/decisions.json), closed 2026-06-15); the ephemeral token exists only for the workflow run. The legacy long-lived access keys and their 90-day rotation procedure were retired with the migration.
- **Silk Reeling app:** holds no secrets. Its Anthropic API key was removed with the interconnection (SCN-2026-006). The runtime emitter's SC-12 rotation check still covers any Secrets Manager secret the inventory carries; today there are none.
- **TLS certificate:** ACM-managed, auto-rotated by AWS.
- **GitHub PATs:** none in use. All GitHub access uses the workflow's `GITHUB_TOKEN` with workflow-scoped permissions, plus the OIDC token for cosign keyless signing (which is ephemeral).
- **Sigstore signing identity:** ephemeral, generated per-run by Fulcio, never stored anywhere.

The keyless signing chain is the single biggest reduction in secret-management surface area for this system: there is literally no signing key to manage, rotate, or lose.

## Prevent residual risk (KSI-SVC-PRR, mod-only)

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
2. **Deploy-identity compromise → AWS account access.** CI assumes a scoped IAM role via GitHub OIDC ([POAM-001](../data/decisions.json), closed): there are no long-lived deployer keys to leak, and the token is valid only for the workflow run. *Mitigations:* OIDC trust policy scoped to this repository, scoped IAM permissions on the deploy role, GitHub secret scanning with push protection for the few remaining repository secrets (which carry no AWS credentials).
3. **Runtime Lambda compromise → falsified runtime signal.** An attacker with Lambda code-modification access could publish misleading runtime KSI signals. *Mitigations:* tight Lambda IAM (write only to two S3 keys, read-only configuration-metadata access on the inventory's buckets and one CloudFront distribution), drift between deploy-time and runtime signals is detectable from outside, and the runtime signal is signed with a KMS ECC P-256 key (POAM-002, closed) whose public key is published for independent verification.
4. **Sigstore-chain compromise.** A compromise of Fulcio, Rekor, or the GitHub OIDC issuer would invalidate the signing chain. *Mitigations:* none operator-side — these are public infrastructure components with thousands of independent observers; compromise of any one is detectable by anyone running independent verification.
5. **Bucket policy weakening.** A change to the S3 bucket policy or public-access block that re-enabled public read or write. *Mitigations:* OPA gate at deploy time blocks the change; runtime KSI emitter detects the drift within 24 hours.

**Threats accepted as out-of-scope:**

- DDoS at scales beyond AWS Shield Standard (consciously skipped WAF; no high-value target on the site)
- Side-channel attacks on the underlying AWS infrastructure (inherited from AWS authorization)
- Insider threat on the operator's personal endpoints (operator's laptop is outside system boundary)

**Vulnerability analysis** is automated through the SAST/SCA tools described under SA-11 (Checkov, tfsec, Dependabot). The Annual Security Review (`scripts/hold-security-review.py`) fails when a component type added since the previous review is not named in this threat model, so the model is kept current through pull requests ([`security-review.md`](security-review.md)).

## Communication integrity (KSI-SVC-VCM, mod-only)

Cross-component communications:

- viewer ↔ CloudFront: TLS 1.2+
- CloudFront ↔ S3: TLS within the AWS network, with origin authentication via service principal + SourceArn
- authenticated user ↔ API Gateway ↔ Silk Reeling Lambda: TLS, Cognito JWT verified at the gateway
- Lambda ↔ AWS service APIs: TLS within the AWS network
- CI ↔ AWS APIs: TLS, with an ephemeral OIDC-assumed role scoped via IAM

The viewer-facing settings (HTTPS redirect, the TLS floor) are checked by the OPA gate twice: at plan time, over the trust root's plan, because the distribution belongs to the bootstrap stack, which CI never applies; the deploy plans it read-only and runs the same gate over it on every deploy (a violation stops the deploy), and daily by the runtime emitter against the live distribution.

Authenticity at the application layer: the canonical inventory is signed (KSI-SVC-VRI). Communication integrity at the transport layer is AWS-default TLS. End-to-end signed-message integrity at the application layer beyond the signed signal is not implemented because no application-layer protocol exists between components beyond the standard AWS APIs.
