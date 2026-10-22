# Allow WebAssembly compilation in the site's Content Security Policy, and nothing else. Security decision; operator approval and an operator-applied bootstrap change.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: `script-src` in `infrastructure/bootstrap/cloudfront.tf` becomes `'self' 'wasm-unsafe-eval'`, with no CDN, no `blob:`, and `connect-src` still `'self'`; the dead duplicate policy in `infrastructure/main.tf` is removed or explicitly marked unused; `terraform plan` in the bootstrap stack shows only this change; the operator applies it from a tree synced to `origin/main` and not while a deploy run is in flight; the PR states the residual: `'wasm-unsafe-eval'` permits compiling WebAssembly and does not permit JavaScript `eval`.
OUT OF SCOPE: Any other header. Any cross-origin source.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: the live policy is `infrastructure/bootstrap/cloudfront.tf` L95-110 (`script-src 'self'` at L98). `default-src 'self'` already permits same-origin workers, so no `worker-src` change is needed. A dead duplicate sits at `infrastructure/main.tf` L226-270 behind a variable that defaults to false. The policy is not applied to `/silk-reeling/*` (L72-73). Bootstrap is operator-applied: follow CLAUDE.md's sync-before-apply rule (a stale tree reverts merged changes) and its no-apply-during-deploy rule (2026-10-05).
DEPENDS ON: none (sequenced before 024)
LIVE-EDGE: `curl -sI https://samaydlette.com/ | grep -i content-security-policy` shows `'wasm-unsafe-eval'` in `script-src` and `connect-src 'self'`.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Phase 2. The operator chose DuckDB-Wasm in the page for the portfolio query; this is the one CSP change that requires.
