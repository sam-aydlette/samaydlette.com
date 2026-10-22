# Optional: sign each CSO's product under its own workflow identity.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: each CSO's product is signed from its own reusable workflow so the Fulcio certificate identity differs per CSO; the portfolio registry pins each identity; `scripts/verify-published.sh` accepts exactly the right identity per product.
OUT OF SCOPE: Moving signing out of this repository.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: `scripts/verify-published.sh` already pins two identities (L33, L46) for the deploy and the nightly; follow that pattern. Every job that signs needs `id-token: write`, and a job that has it without signing is a privilege widening.
DEPENDS ON: 024
LIVE-EDGE: `cosign verify-blob` of each CSO product succeeds against only its own identity.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Optional.
