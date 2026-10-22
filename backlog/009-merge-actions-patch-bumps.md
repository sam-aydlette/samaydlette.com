# Merge the two GitHub Actions patch bumps (#424 upload-sarif 4.38.1→4.38.3, #418 download-artifact 8.0.1→8.0.2).
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: both PRs are merged by the operator (`gh pr view 424 --json state` and `gh pr view 418 --json state` both return MERGED); `grep -ho 'download-artifact@[^ ]*' .github/workflows/deploy-with-opa.yml .github/workflows/evidence-nightly.yml | sort -u` prints one line.
OUT OF SCOPE: Any other bump. Changing what the steps do. The deploy workflow's gates.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: neither PR changes the canonical inventory (Actions versions are not inventoried; they appear only as `GITHUB_*` provenance). #418 edits `deploy-with-opa.yml` L639 and L647 and `evidence-nightly.yml` L261 together; keep the two workflows on one version. Both PRs' CI was green, but the Deploy job is skipped on PRs, so the reconciliation gate never ran on them.
DEPENDS ON: none
LIVE-EDGE: the next `evidence-nightly.yml` run is green (`gh run list -w evidence-nightly.yml -L1`).
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Phase 0 leaf. Low risk, no conflict with trunk work beyond one-line workflow edits that rebase trivially.
