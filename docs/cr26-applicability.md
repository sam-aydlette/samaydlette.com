# CR26 Rule-Family Applicability

The FedRAMP Consolidated Rules for 2026 (launched **2026-06-24**, in effect for widespread adoption **2026-07-04**; active 20x certifications must conform by **2027-01-01**) fold a set of rule families into the default requirements. This document is the authoritative statement of which families this system mechanizes and which are **Not Applicable**, with the corpus's own reasoning for each N/A. It exists so that nothing is silently omitted: a family that is not met is recorded here with a reason, not dropped.

<!-- AI-drafted for the operator's review (2026-11-06: rewritten for the four statuses). -->

## The four statuses

Every applicable rule (`data/frr-records.json`) and every Key Security Indicator carries one of four statuses (the operator's "Proof-of-concept latitude", `CLAUDE.md`):

| Status | Meaning | What the record must carry |
|---|---|---|
| **Implemented** | A real mechanism ran on real inputs, and evidence exists. | Evidence that resolves; no stand-in. |
| **Simulated** | A real mechanism ran on a labelled stand-in input. The stand-in may replace an outside party (a simulated assessor, FedRAMP, agency, incident recipient, mail system or SAM.gov), the people, or infrastructure deliberately not built (an inbox, a meeting, a notification transport). | What is real and what is simulated; a test that a bad stand-in changes the result; a statement of how a real input would replace the stand-in and what would have to change, citing a test where one exists; deploy-time evidence; the operator's approval. A guard that refuses real agencies or FedRAMP (DEC-194) is policy, not logic. |
| **Not Demonstrated** | Not built, or nothing runs. | Why, and no claimed evidence; the operator's approval. |
| **Not Applicable** | The rule or KSI does not apply. | Why; the operator's approval. |

Anyone may propose a stand-in or a scope cut; only the operator approves one. The deploy's claim gate (`scripts/_frr.py --claims`) and the simulated assessor fail on a record whose fields do not support its status, including one not yet approved, and never on an honestly stated status. KSI statuses other than Not Applicable are computed by `scripts/build-sdr.py` from the methods that genuinely test each KSI's measures: Implemented with two or more on real inputs, Simulated when two are reached only with a stand-in input, otherwise Not Demonstrated. KSI scope cuts are in `data/ksi-applicability.json` (KSI-SVC-RUD: no federal customer data, approved by the operator on 2026-11-06).

FedRAMP's published status enum has three values (Implemented, Partially Implemented, Not Implemented). In the Security Decision Record, Implemented is published as Implemented, Not Demonstrated as Not Implemented, and Simulated and Not Applicable leave the official field out; `providerExtensions.status` carries the real status.

This system is a **self-attested proof of concept** — one operator, no agency sponsor, no federal customer data, no FedRAMP Marketplace listing, no FedRAMP Recognized independent assessment service engaged. Several CR26 families are structurally unavailable to such a system; the corpus text frequently supplies the exact reason.

## Mechanized (produced as signed artifacts or enforced in the pipeline)

| Family | What is produced / enforced | Key rules |
|---|---|---|
| **MAS** — Minimum Assessment Scope | Every inventory component carries a FIPS 199 category and information-flow tag; third-party AWS resources documented at the inheritance level | `MAS-CSO-IIR/FLO/TPR` (`MDI`/`SUP` N/A — no federal customer data, no supplemental materials) |
| **SCN** — Significant Change Notifications | Commit-time `SCN-Type` gate (routine/adaptive/transformative/emergency), per-change SCN records + register, full transformative timeframe set | `SCN-CSO-*`, `SCN-RTR-NNR`, `SCN-ADP-NTF`, `SCN-TRF-NIP/NFP/NAF/NAV/UPD/TPR` |
| **VDR / VER** — Vulnerability Detection, Evaluation & Reporting | Per-deploy and nightly VDR report (PAIN/IRV/LEV, Class C SLA, KEV gate) + human-readable rendering; from it, the FedRAMP-schema Vulnerability Detail Report (`vdr-detail-report.json`), Accepted Vulnerability Info (`vdr-accepted-vulnerabilities.json`) and history (`vdr-history.json`), each validated against the vendored 2026-06-24 schema before it is written; 14-day drift cadence | `VDR-TFR-PVR/KEV/PDD`, `VER-EVA-*`, `VER-RPT-VDT/AVI/PER`, `VER-TFR-MHR/MRH/IRI/NRI` |
| **CCM** — Collaborative Continuous Monitoring | Quarterly Ongoing Certification Report (8 summaries + incident attestation) + the dates of the next report and Quarterly Review | `CCM-OCR-AVL/NRD`, `CCM-QTR-NRD` |
| **CDS** — Certification Data Sharing | The CDS fields published in the Certification Package Overview (the separate certification-overview package is retired), service list, availability feed, policy index, trust manifest — all signed + human-readable | `CDS-CSO-PUB/SVC/FID/CBF/AVR/IRP` |
| **CMU** — Cryptographic Module Use | Each module documented with CMVP-validation status (the authorization-boundary FIPS section); validated modules used for sensitive crypto | `CMU-CSO-CMD/UVM` (`CAT` N/A — no agency tenants) |
| **SDR** — Security Decision Record | Per-KSI records (explanation, verification, validation, artifacts) + metric history; the 20x SSP replacement | `SDR-CSO-FRR/MTD`, `SDR-CSX-KSI/KMT` |
| **CPO** — Certification Package Overview | Rollup of CDS/MAS/CMU/IVV + named accountable official; with the SDR, the SSP replacement | `CPO-CSO-OVR/MTD`, `CPO-CSX-CPM` |
| **SCG** — Secure Configuration Guide | Public, versioned guide for top-level administrative accounts; secure-by-default provisioning | `SCG-CSO-RSC/PUB/SDF`, `SCG-ENH-*` |

The POA&M is retired (2026-11-04): CR26 has no POA&M. Open findings and their deadlines are in the VDR report; vulnerabilities not remediated within the maximum period are reported as Accepted (`VER-RPT-AVI`); and every human decision about a finding (false positive, accepted risk, operational requirement, remediation history) is a record in `data/decisions.json`, read by the VDR builder, the vulnerability gate, reconciliation and the trust center. The published `oscal-poam.json` was deleted. The OSCAL Rev 5 SSP is retired too (2026-11-05): CR26 has no SSP. The Security Decision Record and the Certification Package Overview replace it. CR26 gives the two certification types the **same rule families**; the only material difference is the evidence shape. The Rev5 Security Decision Record summarizes each applicable Rev5 control (`SDR-CSF-CTF`, "for each applicable Rev5 Control"), and the 20x record summarizes each Key Security Indicator (`SDR-CSX-KSI`). `scripts/build-sdr.py` produces both in one record (`rev5_controls` and `rule_records`) from one control projection (`scripts/_controls.py`), so the automation is demonstrated under both paradigms. The published `oscal-ssp.json` was deleted. The remaining Rev5-only IDs (`IVV-CSF-*`, `CDS-CSF-TCM`, `VDR-TFR-MVF`) are control-vs-KSI assessment variants that this 20x system does not use, and the Class C VDR remediation timeframes are identical across both tracks.

## Not Applicable families (structurally unavailable to an unsponsored, unlisted, self-attested system)

Each rule record below is proposed Not Applicable and awaits the operator's approval like every other scope cut.

- **MKT — Marketplace Listing.** FedRAMP scopes the Marketplace rules to providers seeking a listing in the FedRAMP Marketplace, and no listing is sought, by statutory scope: `MKT-IIP-AGU` requires demonstrating the offering is for agency use within 44 USC § 3506 scope, and the rule text is explicit that *"services used by private companies to meet other compliance requirements (such as CMMC) that do not also meet one of the above use cases are outside the scope of FedRAMP."* There is no agency use case, so the offering is outside that scope and no listing request is made. The rule records `MKT-CSO-MLR` and `MKT-CSO-PML` give the same reason.

MKT is N/A because of *what this system is*, not because of an engineering gap. If the system were ever sponsored, listed or handling federal data, it would activate, and the certification data under `/.well-known/` (the CPO, the SDR, the VDR reports) is the input a listing would consume.

**IVV — Independent Verification and Validation** is no longer recorded N/A; its assessor rules are proposed **Simulated**. No FedRAMP Recognized independent assessment service (the artifact formerly called a 3PAO) has assessed this system. The assessor port is exercised instead: every deploy is assessed by a *simulated* assessor, a workflow in this repository signing under its own identity, whose signed results are published at `/.well-known/simulated-assessment.json` and quoted in the Security Decision Record. It is labelled as simulated and is not a FedRAMP assessment.

**AFC — Addressing FedRAMP Communication** is no longer recorded N/A (operator's decision, 2026-11-05): its rules are proposed **Simulated**, run against a *simulated* FedRAMP Security Inbox. The inbox logic (`scripts/_fsi.py`) runs on every deploy over committed synthetic messages and publishes `/.well-known/fedramp-inbox-simulation.json`, labelled as a simulation; no mail is received or sent, and the published contact sends FedRAMP to the operator on LinkedIn. See `docs/runbooks/fedramp-security-inbox.md`.

**IEC — Incident Evaluation and Communication** is not recorded N/A either; the rules that deliver to a recipient are proposed **Simulated**. This system holds no federal customer data, so in practice no incident is FedRAMP-reportable, but every incident is evaluated and recorded in `data/incidents.json`, and reportable ones get Initial, Ongoing and Final reports in FedRAMP's schema, on the Class C clocks, published under `/.well-known/` and delivered to *simulated* FedRAMP and agency recipients (`/.well-known/incident-deliveries.json`; nothing is sent). Exercised 2026-11-05 with simulated incidents marked as exercises; see `docs/incident-response.md`.
