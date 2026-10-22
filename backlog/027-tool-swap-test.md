# Optional: write the vulnerability-management contract so it is scanner-independent, and list exactly what a scanner swap would touch.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: the vulnerability-management product's contract names no scanner in its schema or semantics; a document lists every touch point of a swap with file and line; scanner choice is a local decision bounded by 021's allowed set.
OUT OF SCOPE: Swapping the scanner.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: Syft and Grype steps at `deploy-with-opa.yml` L966-1015 and `evidence-nightly.yml` L399-400; `SYFT_VERSION` and `GRYPE_VERSION` env pins; `ingest_grype` at `scripts/build-vdr-report.py` L645-694; the `grype-` prefix baked into finding ids referenced by POA&M items and `data/vuln-dispositions.json`.
DEPENDS ON: 019, 021
LIVE-EDGE: none (documentation).
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Optional (work item 7).
