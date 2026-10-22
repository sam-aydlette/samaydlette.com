# Record the Silk Reeling commit each deploy builds, and make the nightly scan that commit instead of a moving branch.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: the deploy records the cloned mirror's `git rev-parse HEAD` in the canonical signal's provenance (for example `provenance.inputs.silk_reeling_commit`); the nightly reads that SHA from the published, signature-verified signal and checks out exactly it; a test covers the provenance field and its 40-hex format.
OUT OF SCOPE: Widening the nightly's OIDC role. Changing silk-reeling-mirror. Changing which ref the deploy builds by default.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: the deploy clones `--depth 1 --branch ${SILK_REELING_REF:-main}` at `deploy-with-opa.yml` L908-914 and records no commit; the nightly re-clones the same moving ref at `evidence-nightly.yml` L365-371, so it can scan code that is not deployed. `git clone --branch` cannot take a SHA; use `git init` plus `git fetch --depth 1 origin <sha>`. The nightly is the unattended path; if this needs any new permission, stop: per CLAUDE.md the answer is to ask whether the work belongs there, not to widen the role.
DEPENDS ON: 006
LIVE-EDGE: `curl -s https://samaydlette.com/.well-known/ksi-signal.json | jq .provenance` shows a 40-hex Silk Reeling commit; the next nightly's log shows it checked out the same SHA.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Phase 2, first trunk task. A prerequisite for a Silk Reeling product that says what it describes.
