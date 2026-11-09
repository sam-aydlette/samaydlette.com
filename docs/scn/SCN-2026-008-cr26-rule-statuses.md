# SCN-2026-008 — Significant Change Notification & Security Impact Analysis
## Publish a status for every applicable CR26 rule and KSI, decided in Rego

| | |
| --- | --- |
| **SCN ID** | SCN-2026-008 |
| **System** | samaydlette.com (FedRAMP 20x Class C proof of concept; not an authorized system) |
| **SCN type** | **Adaptive** (`SCN-ADP`) |
| **Status** | **Proposed; awaiting the operator's approval and the gated deploy.** The deploy's claims gate fails until the operator approves or rejects each Impractical and Not Applicable proposal. |
| **Date initiated** | 2026-11-09 |
| **Approver** | Sam Aydlette — System Owner / Authorizing Operator |
| **Authoritative source** | FedRAMP Consolidated Rules 2026.11.02.01 (`infrastructure/schemas/fedramp-rules/`) |

## 1. Categorization (SCN-CSO-EVA)

Changes the compliance engine: what the system says about its own security
state, and a new gate on the deploy path. That is more than routine-recurring
maintenance, so it is Adaptive.

It is not Transformative:
- no new service, data flow, interconnection or AWS resource;
- no federal data;
- no customer-responsibility or class change.

## 2. Required information (SCN-CSO-INF)

- **Short description:** every one of the 154 FedRAMP rules that applies to a
  20x Class C provider gets one record (`data/frr-records.json`) with one of
  four statuses: Implemented, Not Demonstrated, Impractical, Not Applicable.
  Each of the 46 KSIs gets a status from a count of its automated methods.
  Both decisions are Rego (`policies/compliance/claims.rego`,
  `policies/compliance/ksi.rego`); Python collects the facts. The Security
  Decision Record publishes both in FedRAMP's item shape, and the trust center
  shows the counts.
- **Reason:** the published posture said every KSI passed. That counted
  validations linked to a KSI, not methods that test it, and said nothing
  about the other rules. The statuses now say what is met and what is not.
- **Customer impact:** none. There are no agency customers. Readers of the
  trust center and the SDR see lower, accurate numbers.
- **Changes:**
  - Removes the CMMC, GovRAMP and TX-RAMP figures and the files only they used.
  - Adds the rule register, its shape check and the claims gate (a new deploy
    step, and `make check-claims`).
  - Adds the KSI method count. OPA rules carry `custom.resource_types`; a rule
    counts at plan and at live only where that stage evaluated a matching
    resource. Other mechanisms are listed in `data/ksi-methods.json`.
  - Live credit needs a runtime signal whose signature verifies against the
    pinned key, and nightly credit needs a fresh beacon.
  - Replaces the operator's email address with the LinkedIn profile in
    `security.txt`, the offering record and the signal.

## 3. Security impact analysis

- **No new exposure.** No IAM, network or data-flow change. The OPA policy
  bundle changes only in annotations, so the Wasm the runtime Lambda runs is
  rebuilt with the same rules.
- **New failure mode:** the deploy stops while any rule record claims more than
  its fields support, including any stand-in or scope cut the operator has not
  approved. That is the gate working.
- **Cost:** none.

### Verification plan (post-implementation)

1. The deploy passes the claims gate after the operator's approvals are
   recorded.
2. The published SDR carries `fedRampRequirements` (154) and
   `keySecurityIndicators` (46), and its status counts match the trust center.
3. `security.txt` serves the LinkedIn profile as its contact.
4. `make verify-published` passes.
