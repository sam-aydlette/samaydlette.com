# Continuous Monitoring Plan

## Purpose

This Continuous Monitoring Plan (CMP) describes the strategy and mechanisms by which the system maintains awareness of its security posture between formal authorization decisions, per NIST SP 800-37 Risk Management Framework step 6 (Monitor) and the FedRAMP 20x Collaborative Continuous Monitoring (CCM) rule. The CMP names what is monitored, by what mechanism, on what cadence, where the results are published, and how an authorizing official or independent reviewer can verify the monitoring is happening.

## Scope

The full system as defined in the [authorization boundary](../website/research/authorization-boundary.html), including all components inside the boundary (Cloud Service Offering internals, leveraged AWS services, and external services without FedRAMP ATO that are in boundary per Rule of Thumb #2).

The Silk Reeling Mirror app is **active in production** (`create_silk_reeling = true` in the main deploy pipeline; live since 2026-06-03), so the scope includes its components — the app Lambda (Python 3.13 ZIP), the API Gateway HTTP API, the customer-managed KMS key and Secrets Manager secrets, and the **external Anthropic API interconnection** (non-FedRAMP-authorized, in boundary per SA-9/CA-3, POAM-020). These were introduced under [SCN-2026-001](scn/SCN-2026-001-silk-reeling.md) (Adaptive). Their dependency ecosystems (PyPI, the SPA's npm tree) are monitored by mechanism 2 via the Syft+Grype SCA source.

## Monitoring Mechanisms

Four mechanisms operate concurrently:

**1. Deploy-time policy gate (per pull request).** Every PR triggers the OPA compliance gate (the `infrastructure/policy/` packages evaluated by `scripts/terraform-plan.sh`). The gate evaluates the Terraform plan, the website tree, and the IAM policy against in-house Rego rules. PR cannot merge if the gate fails. Frequency: per PR.

**2. Build-time vulnerability evaluation (per deploy).** Every deploy runs the VDR aggregator (`scripts/build-vdr-report.py`) which ingests OPA gate output, Checkov SARIF, tfsec JSON, Dependabot alerts, Grype SCA output (Syft SBOM → Grype, over the built Silk Reeling Lambda + SPA artifact — the detection source for the app's PyPI and client-JS dependencies), and the CISA KEV catalog. Findings are classified per FedRAMP 20x VDR-EVA-* (PAIN N1-N5, IRV, LEV, KEV) and emitted as `/.well-known/vdr-report.json`. The build is the report. Build blocks if any finding exceeds Class C tolerance. Frequency: per deploy (which exceeds VER-TFR-MHR's monthly minimum).

**3. Runtime configuration revalidation (daily).** An AWS Lambda (`infrastructure/lambda/index.js`) runs daily on an EventBridge schedule. It loads the same `policy.wasm` compiled at deploy time (so deploy-time and runtime evaluate identical compiled bytes), queries the live AWS configuration of every cloud component named in the canonical inventory, and re-evaluates each policy. Results are published as `/.well-known/ksi-signal-runtime.json`. Drift between the deploy-time signal and the runtime signal is the externally-visible drift detector. Frequency: daily.

**4. Annual structural review.** Documented in [`docs/security-review.md`](security-review.md). The review re-examines (a) cost/benefit of risk-accepted items, (b) whether the threat model still holds, (c) whether the conscious trade-offs in the README still apply. Frequency: annual, plus after any Transformative significant change per SCN.

## Reporting

These artifacts are published continuously at `/.well-known/`:

- `ksi-signal.json` — the FedRAMP 20x KSI signal (Sigstore-signed); per-deploy emission
- `ksi-signal-runtime.json` — the daily runtime revalidation, signed with an asymmetric KMS key (ECC NIST P-256); the signature is carried in `provenance.attestation` and verifiable against `runtime-signing-pubkey.pem` (POAM-002)
- `runtime-signing-pubkey.pem` — the public key for verifying the runtime signal's signature
- `oscal-ssp.json` — the NIST OSCAL System Security Plan; per-deploy emission
- `oscal-poam.json` — the NIST OSCAL Plan of Action and Milestones; per-deploy emission
- `vdr-report.json` — the FedRAMP 20x VDR report; per-deploy emission
- `vdr-report.md` — human-readable VDR rendering (VER-TFR-MHR)
- `ongoing-certification-report.json` / `.md` — the quarterly Ongoing Certification Report (CCM-OCR-AVL), Sigstore-signed; carries the eight required summaries plus the target dates for the next report (CCM-OCR-NRD) and next quarterly review (CCM-QTR-NRD)

All artifacts carry FedRAMP-namespaced provenance (deploy chain identity, system-id, ownership block). The deploy-time signal is signed via Sigstore keyless with verification anchored in the public Rekor transparency log; an external consumer can verify integrity via `cosign verify-blob` without trusting this site.

**Quarterly Ongoing Certification Report.** CR26 CCM is a quarterly cycle, not a stream. `ongoing-certification-report.json` (CCM-OCR-AVL) is regenerated on every deploy from the system's own artifacts and carries the eight required summaries — changes to certification data (from the SCN register), planned changes (open POA&M items), accepted vulnerabilities (from the VDR), transformative changes, updated recommendations, agencies using the product (none), a FedRAMP-Reportable-Incident attestation (none — no federal data), and lessons learned (none) — plus the next-report and next-review target dates. The four monitoring mechanisms above feed it; per-deploy emission keeps it current and overshoots the 3-month floor.

This implements the **publication half** of FedRAMP 20x Collaborative Continuous Monitoring (CCM): every monitoring artifact is publicly retrievable and signature-verifiable, and the quarterly Ongoing Certification Report is produced as a distinct deliverable, so any reviewer can fetch and verify the current posture without trusting this site. The relationship-dependent rules — the synchronous Quarterly Review (CCM-QTR-MTG), the feedback channel (CCM-OCR-FBM), and the anonymized feedback summary (CCM-OCR-AFS) — are N/A absent a consuming agency, as the scope note below explains.

**Honest scope — the collaborative half is N/A here, not done.** CCM is a two-party relationship: a CSP publishes, and a *consuming agency / authorizing official* reviews on an agreed cadence, raises significant-change and finding concerns, and makes risk decisions that feed back into the CSP's posture. This system has **no agency sponsor and no consuming agency** (it is a public proof of concept with no federal data). So the relationship-dependent obligations — the agency-side review cadence, the collaborative finding-disposition loop, the authorizing-official sign-off — are **not applicable**, because there is no counterparty to exercise them. What is built is the mechanism a CSP would use to *support* CCM; what is absent is the relationship that gives it meaning. Claiming CCM is "satisfied" would overstate it: the closed monitoring loop does not exist, and cannot, until a consuming party is onboarded.

## Vulnerability Detection and Response (VDR) cadence (Class C)

The system targets 20x Class C. Per VDR-TFR-PVR Class C (full table reproduced in [`docs/policies/ra-policy.md`](policies/ra-policy.md)):

- N5 + LEV + IRV: 2 days to mitigation
- N5 + LEV + NIRV: 4 days
- N4 + LEV + IRV: 4 days
- N4 + LEV + NIRV: 8 days
- N3 + LEV + IRV: 16 days
- ... and so on

The VDR aggregator currently blocks the build on (a) any KEV-listed CVE without remediation, (b) any N5 + LEV + IRV finding present at all. SLA-clock enforcement for lower-tier findings depends on a first-detected ledger; until that ledger is added, the Class C SLA table is encoded in the script but inert for those tiers. This is acknowledged in the script's comments and in the RA policy.

## Significant Change Notification (SCN) integration

Significant changes to the system are governed by the FedRAMP 20x SCN rule (full integration in [`docs/policies/cm-policy.md`](policies/cm-policy.md)). Every PR carries an SCN-Type tag (Adaptive / Routine Recurring / Transformative); the CI workflow validates the tag. Git history is the SCN audit record (SCN-CSO-MAR). Transformative-class changes trigger a CMP review.

## Roles and responsibilities

Sole-operator system. The operator is the System Owner, the Continuous Monitoring lead, and the Incident Response lead. The runtime KSI emitter is an automated agent in the monitoring chain.

### Separation of duties (AC-5) — structurally constrained, with compensating controls

A single human cannot satisfy AC-5 separation of duties in the conventional sense: there is no second person to provide an independent check, no maker/checker split, no segregation between the person who changes the system and the person who reviews the change. This is an inherent, **honestly acknowledged** limitation of a sole-operator system, not something tooling can fix. It does not generalize to the scaled version this repo is a proof of concept for, where these duties would be split across distinct roles.

The compensating controls that stand in for a second human are **automated and non-human reviewers** in the change path, each independent of the operator's intent:

- **The fail-closed reconciliation gate** is an independent reviewer the operator cannot satisfy by assertion: it re-derives the artifacts from live cloud state and blocks publication if anything drifts — the operator cannot merge a claim the live account contradicts.
- **The OPA pre-deploy gate + Checkov** evaluate policy against the Terraform plan before any apply; a noncompliant change is rejected regardless of operator intent.
- **GitOps audit trail.** Every change is a reviewable commit/PR; git history is the immutable record of who changed what and when (the SCN audit record). There is no out-of-band path to production.
- **Sigstore signing + the public Rekor log** make every published artifact tamper-evident to anyone, so the operator cannot quietly substitute a different artifact after the fact.
- **GitHub OIDC deploy role (no standing key)** means the deploy identity is a short-lived, workflow-scoped token, not a credential the operator holds and could use out-of-band.

Together these provide *machine* independence in place of *human* independence: the operator can author changes but cannot unilaterally push an unreviewed, noncompliant, or tampered state to production without the automation refusing. This bounds the sole-operator risk; it does not eliminate the structural single-person constraint, which is recorded here as a residual.

## Effectiveness review

Quarterly review of the runtime KSI signal against the deploy-time signal: are they reconciling? Are any drift events recorded? Are any findings persisting past their Class C SLAs?

Annual structural review per [`docs/security-review.md`](security-review.md).

## Reference: 20x rules and NIST controls satisfied

- FedRAMP 20x Collaborative Continuous Monitoring (CCM-OCR-* and CCM-QTR-* rules) — the quarterly Ongoing Certification Report (`CCM-OCR-AVL`) and the next-report/next-review dates (`CCM-OCR-NRD` / `CCM-QTR-NRD`) are produced and published; mechanisms 1-4 feed it. The synchronous Quarterly Review (`CCM-QTR-MTG`), feedback channel (`CCM-OCR-FBM`), and feedback summary (`CCM-OCR-AFS`) are **N/A** absent a consuming agency (see scope note above)
- FedRAMP 20x Vulnerability Detection and Response (VDR-* rules) — covered by mechanism 2
- FedRAMP 20x Significant Change Notifications (SCN-* rules) — covered by SCN PR tag
- KSI-MLA family (Monitoring, Logging, Auditing) — covered across all mechanisms
- KSI-SVC-EIS (Continuous Improvement) — covered by drift detection + annual review
- NIST CA-7 (Continuous Monitoring) — primary control implemented by this plan
- NIST CA-7.4 (Risk Monitoring) — covered by VDR cadence
- NIST CM-3 (Configuration Change Control) — covered by SCN
- NIST RA-5 (Vulnerability Monitoring and Scanning) — covered by mechanism 2
- NIST SI-4 (System Monitoring) — covered by mechanisms 1-3
