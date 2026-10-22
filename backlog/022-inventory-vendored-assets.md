# Inventory vendored front-end assets, not just HTML pages.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: a new `build_vendored_components` hashes every file under `website/assets/vendor/` into the canonical inventory with the purl taken from that package's provenance note; cytoscape appears in the signal; invariants (l) and (n) still pass; a test adds a fake vendored file and expects exactly one new component. Because this is a reviewed artifact change it also requires an approved deploy, `make verify-published` exit 0, and the served artifact carrying the merge commit and a fresh `emitted_at`.
OUT OF SCOPE: SBOM-scanning the vendored assets. Changing how HTML pages are hashed.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: `build_html_components` (`scripts/build-ksi-signal.py` L1338-1360) runs `rglob("*.html")` only, so vendored cytoscape 3.34.3 is served but not inventoried today. New components need a classification (`CLASSIFICATION_DEFAULTS` at L650-676) and a boundary group, or invariant (l) fails the deploy; classify them in the same change.
DEPENDS ON: 021
LIVE-EDGE: `curl -s https://samaydlette.com/.well-known/ksi-signal.json | jq '[.components[]|select((.purl//"")|test("cytoscape"))]|length'` prints 1.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Phase 2 trunk, serialized. A prerequisite for vendoring the query engine in 024.
