# scripts/staged/ — generators that are not wired up

Nothing in this directory runs in CI, in `infrastructure/Makefile`, or in any test.
It is parked here so that it cannot be mistaken for a live generator.

The problem this solves: `scripts/` held 36 Python files and nothing distinguished the
26 that produce published artifacts from the 10 that do not. A reader — or the author six
months later — had no way to tell which ones the compliance pipeline actually depends on.

## What is here

| Script | Kind | Status |
|---|---|---|
| `build-171-catalog.py` | one-shot data vendoring | Output committed at `data/catalogs/NIST_SP-800-171_rev2_catalog.json`. Needs `openpyxl`, deliberately not a pipeline dependency. |
| `build-control-mapping.py` | one-shot data vendoring | Output committed at `data/mappings/SP800-53_rev4-to-rev5.mapping.json`. |
| `build-171-53-mapping.py` | one-shot data vendoring | Output committed at `data/mappings/SP800-171r2-to-SP800-53r4.mapping.json`. |
| `build-ksi-catalog.py` | one-shot data vendoring | Output committed at `infrastructure/schemas/ksi-catalog.json`, which `build-oscal-ssp.py` reads on **every deploy**. Regenerating it is a reviewed change, not a refresh. |
| `build-baseline-spokes.py` | Phase 2 spoke | GovRAMP / TX-RAMP profiles + coverage projection. |
| `build-spoke.py` | Phase 2 spoke | The reusable hub→spoke projection the spokes share. |
| `build-dispositions.py` | Phase 2 spoke | Dispositions the above-Moderate residue the spokes surface. |
| `migrate_hub_to_component_def.py` | one-time migration | Would lift `CONTROL_OVERRIDES` out of `build-oscal-ssp.py` into an OSCAL Component Definition. Not taken; the SSP generator is still the hub. |
| `oscal_resolver.py` | library | Minimal profile resolver, written as the spoke interface. Nothing imports it. |
| `validate-oscal.py` | validation gate | Validates authored OSCAL against the vendored NIST v1.2.2 schemas. Never added to CI. |

## What wiring one up requires

The three data-vendoring scripts and the migration are finished work — they ran, their
output is committed, and they exist for reproducibility. They do not need wiring.

The spoke generators do. Wiring one into the pipeline means all four of:

1. A step in the `deploy` job of `.github/workflows/deploy-with-opa.yml`, after the SSP build.
2. A cosign signing step and a publish step under `/.well-known/`.
3. **An invariant in `scripts/reconcile.py`** binding the new artifact to the same inventory
   `signal_id` as everything else — this is the part that matters. An artifact that publishes
   without a reconciliation invariant is exactly the drift the gate exists to prevent, and
   invariant (k) already does this for the SCuBA bundle as the pattern to copy.
4. A unit test for that invariant, plus a broken fixture under `tests/fixtures/broken/`.

## Note on `OSCAL_VERSION`

`migrate_hub_to_component_def.py` pins OSCAL `1.2.2`; the live generators emit `1.1.2` from
`scripts/_common.py`. That divergence predates this directory and is left as-is rather than
silently harmonised — changing it would change a published artifact.

## Shared helpers

These scripts import from `scripts/_common.py` the same way the live ones do, via a
`sys.path.insert` of the parent directory. Keeping them on the shared helpers means they stay
in step with the live generators rather than drifting while parked.
