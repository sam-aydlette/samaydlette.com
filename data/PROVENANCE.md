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
  - `catalogs/NIST_SP-800-53_rev4_catalog.json` — NIST SP 800-53 Rev 4 control catalog (Rev4-bridge target).
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

## Control Mappings (`mappings/`) — derived, OSCAL Control Mapping Model v1.2.x
- `mappings/SP800-53_rev4-to-rev5.mapping.json` — Rev4→Rev5 control mapping, **derived
  deterministically from the two vendored NIST catalogs** by `scripts/build-control-mapping.py`
  (same-id active → `equivalent`; controls withdrawn in Rev5 → the Rev5 catalog's *own*
  `incorporated-into`/`moved-to` link → `subset-of`). 919/922 mapped; 3 residue (no clean
  single successor) recorded in the document. No hand-keyed crosswalk.

## Pending (sourced at their respective checkpoints)
- **800-171 Rev 2 catalog** (CMMC) — **no authoritative NIST OSCAL catalog exists**; will be
  derived from NIST CPRT machine-readable 800-171 Rev 2 + Appendix-D 800-53 mapping, **not**
  a community OSCAL conversion. Decision recorded at the CMMC checkpoint.
- **171 Rev2 ↔ 53 Rev4 crosswalk** — from NIST SP 800-171 Rev 2 Appendix D, at the CMMC checkpoint.

## OSCAL JSON schemas (validation gate)
- `schemas/oscal/oscal_{component,mapping,ssp}_schema.json` — vendored from the
  **usnistgov/OSCAL v1.2.2** release. Used by `scripts/validate-oscal.py`. (Patterns
  are stripped at validation time — OSCAL's ECMA `\p{}` regex is incompatible with
  Python `re`; structure/required/enums are still enforced. Full Metaschema constraint
  validation via NIST `oscal-cli` is the CI gold standard.)

## Target OSCAL version
All authored artifacts target **OSCAL v1.2.x** (current release v1.2.2; the Control Mapping
Model is released and stable as of v1.2.0).
