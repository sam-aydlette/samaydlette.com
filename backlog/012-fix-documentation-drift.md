# Fix the documentation drift found while planning the data-mesh work.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: `docs/silk-reeling-deploy.md` describes the Cognito JWT authorizer the Terraform deploys (any remaining mention of Basic Auth is explicitly historical); `CLAUDE.md` says the nightly republishes six objects plus the beacon, and that most of `website/.well-known/` is gitignored build output rather than tracked; the `tools/a11y/scan.js` header comment names pa11y 10.0.0.
OUT OF SCOPE: Any behaviour change. Removing the dead response-headers policy in `infrastructure/main.tf` (an infrastructure change; see 023).
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: `docs/silk-reeling-deploy.md` L12-31 describes Basic Auth with no Gateway authorizer, while `infrastructure/silk-reeling.tf` L10-26 documents the Cognito JWT authorizer. CLAUDE.md's "five objects" vs `evidence-nightly.yml` L653-660 (six, including `vdr-report.json.intoto.jsonl`). `.gitignore` L31-43 ignores the generated `/.well-known/` files; only `security.txt` and `vdr-trend.json` are tracked. `tools/a11y/scan.js` L19 says 9.1.1; `tools/a11y/package.json` pins 10.0.0.
DEPENDS ON: none
LIVE-EDGE: none (documentation only).
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Phase 0 leaf.
