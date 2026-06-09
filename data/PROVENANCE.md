# `data/` — Authoritative source provenance

All control catalogs, baseline profiles, and crosswalks under `data/` are vendored
verbatim from authoritative sources at pinned commits. Nothing here is hand-keyed or
reconstructed; each file is a byte-identical copy from the commit recorded below.
Retrieval date: **2026-06-09**.

## NIST OSCAL control catalogs
- **Source:** `usnistgov/oscal-content` — https://github.com/usnistgov/oscal-content
- **Pinned commit:** `78650f02ad9321bb7b817846f8fbd4f2bcd620de`
- **Vendored:**
  - `catalogs/NIST_SP-800-53_rev5_catalog.json` — NIST SP 800-53 Rev 5 control catalog (the hub catalog).
- **Authority:** NIST maintains the official OSCAL representations of SP 800-53 Rev 4/5.

## FedRAMP Rev 5 OSCAL baselines
- **Source:** `OSCAL-Foundation/fedramp-resources` — https://github.com/OSCAL-Foundation/fedramp-resources
- **Pinned commit:** `383977291aad960b0811faf6ebf5a893b0811f7f`
- **Relocation note:** FedRAMP's machine-readable OSCAL content **moved** from
  `GSA/fedramp-automation` to `OSCAL-Foundation/fedramp-resources` per FedRAMP
  **Notice 0009** (https://www.fedramp.gov/notices/0009/) and **RFC-0024** (FedRAMP 20x
  machine-readable packages, https://www.fedramp.gov/rfcs/0024/). The old GSA repo path
  no longer resolves; this repo is the current authoritative home.
- **Vendored:**
  - `profiles/FedRAMP_rev5_MODERATE-baseline_profile.json` — FedRAMP Rev 5 Moderate **profile** (imports the 800-53 Rev5 catalog; 323 controls selected, 264 `set-parameters`, 4 `alters`).
  - `profiles/FedRAMP_rev5_HIGH-baseline_profile.json` — FedRAMP Rev 5 High profile (needed for the "narrow High" control absorption).
  - `profiles/FedRAMP_rev5_MODERATE-baseline-resolved-profile_catalog.json` — FedRAMP-published **resolved** Moderate catalog.
  - `profiles/FedRAMP_rev5_HIGH-baseline-resolved-profile_catalog.json` — FedRAMP-published resolved High catalog.

  The `*-resolved-profile_catalog.json` files are FedRAMP's own resolution output; they
  are used as a **correctness oracle** — our in-house resolver resolves the profile and
  its result is diffed against this published catalog to prove the resolver is correct.

## Pending (sourced at their respective checkpoints)
- **800-53 Rev 4 catalog + baselines** (Rev4 bridge) — `usnistgov/oscal-content` (same pin).
- **800-171 Rev 2 catalog** (CMMC) — **no authoritative NIST OSCAL catalog exists**; will be
  derived from NIST CPRT machine-readable 800-171 Rev 2 + Appendix-D 800-53 mapping, **not**
  a community OSCAL conversion. Decision recorded at the CMMC checkpoint.
- **Crosswalks** (`mappings/`) — Rev5↔Rev4 from the FedRAMP comparison workbook + the 47-control
  disposition; 171↔53 from NIST; authored as OSCAL Control Mapping Model (v1.2.x) documents.

## Target OSCAL version
All authored artifacts target **OSCAL v1.2.x** (current release v1.2.2; the Control Mapping
Model is released and stable as of v1.2.0).
