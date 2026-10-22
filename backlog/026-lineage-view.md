# Optional: draw the product lineage graph in the Trust Center.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: a lineage view built from `data-products.json` `inputs[]` shows signal → SSP, POA&M, VDR and SDR → Trust Center, plus the CSO and shared-services products, with owner role and freshness status on each node; it reuses vendored cytoscape and the boundary map's module patterns; a text equivalent is present and pa11y passes.
OUT OF SCOPE: New data beyond the contracts.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: `website/assets/js/boundary-map.js` is 426 lines with a preset layout (`layout()` at L101) and an aria/text-view pattern at L243-245; share helpers rather than forking the module.
DEPENDS ON: 019, 025
LIVE-EDGE: load the view on https://samaydlette.com/trust/ and confirm each node's freshness matches the live product.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Optional (work item 6).
