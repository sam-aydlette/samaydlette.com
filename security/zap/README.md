# DAST scans (OWASP ZAP)

Dynamic application security testing runs **daily and after every successful
deploy to `main`** in `.github/workflows/zap-dast.yml`, as two scans in one run:

- **Site baseline** (unauthenticated, passive rules) against
  `https://samaydlette.com`. It keeps one tracking issue up to date and uploads
  its report as the `zap-dast-report` artifact.
- **Authenticated API scan** of the Silk Reeling API. The routes come from the
  app's own OpenAPI document (`/silk-reeling/openapi.json`, the routes the
  deployed app serves). The scan signs in as a dedicated Cognito scanner user
  (SRP + TOTP, `scripts/dast-cognito-token.py`; setup in
  `docs/runbooks/dast-scanner-user.md`) so its requests pass the API Gateway JWT
  authorizer. Before and after the scan the job checks that an `/api` route
  answers 200 with the token and 401 without it. Report: the `zap-api-report`
  artifact.

## The contract

- The deploy and the nightly fetch both reports (`report_json.json` of each
  artifact) from the latest successful `main`-branch run of that workflow,
  whatever triggered it (`scripts/fetch-detection-feeds.sh`). A run succeeds
  only when both scans did.
- The VDR build **fails** if there is no baseline report
  (`detection.zap.missing`), or if it is more than **3 days** old or carries no
  `@generated` time (`detection.zap.stale`, `--zap-max-age-days 3`, the Class C
  sample-detection cadence of VDR-TFR-PSD).
- The detection gate **fails** the run if the API report is missing, malformed
  or more than **72 hours** old (`detection.zap-api`,
  `infrastructure/schemas/detection-feeds.json`).
- All three are G7 detection checks. Their mode, `block`, is a decision record
  in `infrastructure/schemas/gate-modes.json`. A skipped scan never reads as
  "0 findings".
- Every ZAP alert above informational then flows into the VDR as a
  vulnerability: the baseline's as `zap-<alert ref>`, the API scan's as
  `zap-api-<alert ref>` (`scripts/_zap_api.py`), so each is decided on its own.
  The **vulnerability gate** (`scripts/vuln-gate.py`) fails the build unless
  each one is fixed or covered by an in-force decision in `data/decisions.json`.
  Allowlisted alerts are recorded in `allowlist.json`.

## Running a scan by hand

Run **ZAP DAST Scan** from the Actions tab (`workflow_dispatch`) on `main`. The
next deploy or nightly picks up its artifacts.

A deeper local scan (a full active scan of the site) does not feed the build.
Use it to investigate, and record what it finds as dispositions or
remediations:

```
docker run --rm -v "$PWD:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t https://samaydlette.com -J zap-report.json
```
