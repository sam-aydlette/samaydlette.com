# `data/` — Authoritative source provenance

The baseline profiles under `data/` are vendored verbatim from
authoritative sources at pinned commits. Nothing here is hand-keyed or reconstructed;
each file is a byte-identical copy from the commit recorded below.
Retrieval date: **2026-06-09**.

The CMMC (800-171), GovRAMP and TX-RAMP inputs, the Rev 4 and Rev 5 catalogs and crosswalks,
the FedRAMP High baseline and the OSCAL schemas that used to live here were removed with
the framework figures they fed (git history keeps them). What remains is what the
Rev 5 Moderate view of the Security Decision Record reads.

## FedRAMP Rev 5 OSCAL baseline
- **Source:** `OSCAL-Foundation/fedramp-resources` — https://github.com/OSCAL-Foundation/fedramp-resources
- **Pinned commit:** `383977291aad960b0811faf6ebf5a893b0811f7f`
- **Relocation note:** FedRAMP's machine-readable OSCAL content **moved** from
  `GSA/fedramp-automation` to `OSCAL-Foundation/fedramp-resources` per FedRAMP
  **Notice 0009** (https://www.fedramp.gov/notices/0009/) and **RFC-0024** (FedRAMP 20x
  machine-readable packages, https://www.fedramp.gov/rfcs/0024/). The old GSA repo path
  no longer resolves; this repo is the current authoritative home.
- **Vendored:**
  - `profiles/FedRAMP_rev5_MODERATE-baseline_profile.json` — FedRAMP Rev 5 Moderate **profile** (imports the 800-53 Rev5 catalog; 323 controls selected, 264 `set-parameters`, 4 `alters`). `scripts/_controls.py` reads its parameter values.
  - `profiles/FedRAMP_rev5_MODERATE-baseline-resolved-profile_catalog.json` — FedRAMP-published **resolved** Moderate catalog. `scripts/_controls.py` reads the baseline's control set from it.

## Target OSCAL version
The authored component definition (`component-definitions/`) targets **OSCAL v1.2.x**.
