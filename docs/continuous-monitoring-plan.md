# Continuous Monitoring Plan

## Purpose

This Continuous Monitoring Plan (CMP) describes the strategy and mechanisms by which the system maintains awareness of its security posture between formal authorization decisions, per NIST SP 800-37 Risk Management Framework step 6 (Monitor) and the FedRAMP 20x Collaborative Continuous Monitoring (CCM) rule. The CMP names what is monitored, by what mechanism, on what cadence, where the results are published, and how an authorizing official or independent reviewer can verify the monitoring is happening.

## Scope

The full system as defined in the [authorization boundary](../website/research/authorization-boundary.html), including all components inside the boundary (Cloud Service Offering internals, leveraged AWS services, and external services without FedRAMP ATO that are in boundary per Rule of Thumb #2).

## Monitoring Mechanisms

Four mechanisms operate concurrently:

**1. Deploy-time policy gate (per pull request).** Every PR triggers the OPA compliance gate (`infrastructure/policies.rego` evaluated by `scripts/terraform-plan.sh`). The gate evaluates the Terraform plan, the website tree, and the IAM policy against in-house Rego rules. PR cannot merge if the gate fails. Frequency: per PR.

**2. Build-time vulnerability evaluation (per deploy).** Every deploy runs the VDR aggregator (`scripts/build-vdr-report.py`) which ingests OPA gate output, Checkov SARIF, tfsec JSON, Dependabot alerts, and the CISA KEV catalog. Findings are classified per FedRAMP 20x VDR-EVA-* (PAIN N1-N5, IRV, LEV, KEV) and emitted as `/.well-known/vdr-report.json`. The build is the report. Build blocks if any finding exceeds Class C tolerance. Frequency: per deploy (which exceeds VDR-TFR-MHR's monthly minimum).

**3. Runtime configuration revalidation (daily).** An AWS Lambda (`infrastructure/lambda/index.js`) runs daily on an EventBridge schedule. It loads the same `policy.wasm` compiled at deploy time (so deploy-time and runtime evaluate identical compiled bytes), queries the live AWS configuration of every cloud component named in the canonical inventory, and re-evaluates each policy. Results are published as `/.well-known/ksi-signal-runtime.json`. Drift between the deploy-time signal and the runtime signal is the externally-visible drift detector. Frequency: daily.

**4. Annual structural review.** Documented in [`docs/security-review.md`](security-review.md). The review re-examines (a) cost/benefit of risk-accepted items, (b) whether the threat model still holds, (c) whether the conscious trade-offs in the README still apply. Frequency: annual, plus after any Transformative significant change per SCN.

## Reporting

Five artifacts are published continuously at `/.well-known/`:

- `ksi-signal.json` — the FedRAMP 20x KSI signal (Sigstore-signed); per-deploy emission
- `ksi-signal-runtime.json` — the daily runtime revalidation
- `oscal-ssp.json` — the NIST OSCAL System Security Plan; per-deploy emission
- `oscal-poam.json` — the NIST OSCAL Plan of Action and Milestones; per-deploy emission
- `vdr-report.json` — the FedRAMP 20x VDR report; per-deploy emission

All artifacts carry FedRAMP-namespaced provenance (deploy chain identity, system-id, ownership block). The deploy-time signal is signed via Sigstore keyless with verification anchored in the public Rekor transparency log; an external consumer can verify integrity via `cosign verify-blob` without trusting this site.

This satisfies the FedRAMP 20x Collaborative Continuous Monitoring (CCM) rule by making every monitoring artifact publicly retrievable and signature-verifiable. There is no closed monitoring loop; an agency consumer fetches the same artifacts as anyone else.

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

## Effectiveness review

Quarterly review of the runtime KSI signal against the deploy-time signal: are they reconciling? Are any drift events recorded? Are any findings persisting past their Class C SLAs?

Annual structural review per [`docs/security-review.md`](security-review.md).

## Reference: 20x rules and NIST controls satisfied

- FedRAMP 20x Collaborative Continuous Monitoring (CCM-CSO-* rules) — covered by mechanisms 1-4
- FedRAMP 20x Vulnerability Detection and Response (VDR-* rules) — covered by mechanism 2
- FedRAMP 20x Significant Change Notifications (SCN-* rules) — covered by SCN PR tag
- KSI-MLA family (Monitoring, Logging, Auditing) — covered across all mechanisms
- KSI-SVC-01 (Continuous Improvement) — covered by drift detection + annual review
- NIST CA-7 (Continuous Monitoring) — primary control implemented by this plan
- NIST CA-7.4 (Risk Monitoring) — covered by VDR cadence
- NIST CM-3 (Configuration Change Control) — covered by SCN
- NIST RA-5 (Vulnerability Monitoring and Scanning) — covered by mechanism 2
- NIST SI-4 (System Monitoring) — covered by mechanisms 1-3
