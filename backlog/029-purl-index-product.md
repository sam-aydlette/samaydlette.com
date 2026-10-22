# Optional: publish a small per-signal purl index so portfolio consumers need not download whole signals.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: a contracted, signed purl index product exists per CSO and the portfolio query can use it; the query results are unchanged.
OUT OF SCOPE: Changing the signals.
LANDMINES: This is the scale step for the portfolio query: at many systems, fetching full signals per query does not scale.
DEPENDS ON: 024
LIVE-EDGE: the live page returns the same rows with the index as without it.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Optional.
