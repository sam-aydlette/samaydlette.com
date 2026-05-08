# RA — Risk Assessment

Risk assessment is continuous and automated. Three sources feed the running risk picture:

- **SAST/SCA tooling:** Dependabot for npm dependencies, Checkov and tfsec for Terraform, the OPA gate for in-house policy violations. All four run on every PR.
- **VDR-aligned aggregation:** the build-time VDR aggregator collects findings across the SAST/SCA tools, classifies each detected vulnerability into the FedRAMP Potential Adverse Impact (PAIN) scale (N1–N5 per `VDR-EVA-EPA`), determines internet-reachability (IRV per `VDR-EVA-EIR`) and likely-exploitability (LEV per `VDR-EVA-ELX`), and emits `/.well-known/vdr-report.json`. The build is the report (`VDR-RPT-PER`, `VDR-TFR-MHR`). The build blocks if any finding exceeds the Class C remediation timeframes (`VDR-TFR-PVR` Class C):
  - N5 + LEV + IRV: 2 days
  - N5 + LEV + NIRV: 4 days
  - N5 + NLEV: 16 days
  - N4 + LEV + IRV: 4 days
  - N4 + LEV + NIRV: 8 days
  - N4 + NLEV: 64 days
  - N3 + LEV + IRV: 16 days
  - N3 + LEV + NIRV: 32 days
  - N3 + NLEV: 128 days
  - N2 + LEV + IRV: 48 days
  - N2 + LEV + NIRV: 128 days
  - N2 + NLEV: 192 days
- **Threat modeling:** STRIDE-style review documented in [`architecture-decisions.md`](../architecture-decisions.md) under the Threat Modeling section.

Vulnerabilities not fully mitigated within 192 days of evaluation are categorized as Accepted (`VDR-TFR-MAV`) and tracked in [`poam.md`](../poam.md) with the `VDR-RPT-AVI` fields.

KEVs (CISA Known Exploited Vulnerabilities) are remediated according to the BOD 22-01 due dates (`VDR-TFR-KEV`).

**20x rule integration.** Vulnerability Detection and Response (full VDR-* family at Class C cadence). KSI-PIY-RVD (Reviewing Vulnerability Disclosures).

**Review cadence.** Continuous (per-PR + per-deploy); structural review annually.
