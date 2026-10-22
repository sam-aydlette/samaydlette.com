# Optional: add a CSO dimension to the SSP, POA&M and VDR, or a per-CSO SSP.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: each SSP component, POA&M item and VDR finding names its CSO(s) or the shared services; invariants (b), (g) and (h) still pass. Because this is a reviewed artifact change it also requires an approved deploy, `make verify-published` exit 0, and the served artifact carrying the merge commit and a fresh `emitted_at`.
OUT OF SCOPE: Separate authorization boundaries.
LANDMINES: POA&M changes must keep `docs/poam.md` and `data/poam-items.json` in sync (invariant g).
DEPENDS ON: 018
LIVE-EDGE: `make verify-published` exit 0.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Optional.
