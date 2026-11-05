# DAST scans (OWASP ZAP)

Dynamic application security testing runs **weekly in CI**:
`.github/workflows/zap-dast.yml` runs a passive ZAP baseline scan against
`https://samaydlette.com`. It keeps one tracking issue up to date and uploads the
report as the `zap-dast-report` artifact.

## The contract

- The deploy and the nightly fetch the report (`report_json.json`) from the
  latest successful `main`-branch run of that workflow
  (`scripts/fetch-detection-feeds.sh`).
- The VDR build **fails** if there is no such report (`detection.zap.missing`).
  It also fails if the report is older than **14 days** or carries no
  `@generated` time (`detection.zap.stale`, `--zap-max-age-days`, the Class C
  drift-detection cadence). Both are G7 detection checks. Their mode, `block`,
  is a decision record in `infrastructure/schemas/gate-modes.json`. A skipped
  scan never reads as "0 findings".
- Every ZAP alert above informational then flows into the VDR as a
  vulnerability. The **vulnerability gate** (`scripts/vuln-gate.py`) fails the
  build unless each one is fixed or covered by an in-force decision in
  `data/decisions.json`. Allowlisted alerts are recorded in
  `allowlist.json`.

## Running a scan by hand

Run **ZAP DAST Scan** from the Actions tab (`workflow_dispatch`) on `main`. The
next deploy or nightly picks up its artifact.

A deeper local scan (full or authenticated, including the API) does not feed the
build. Use it to investigate, and record what it finds as dispositions or
remediations:

```
docker run --rm -v "$PWD:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t https://samaydlette.com -J zap-report.json
# add -z "auth.*" / a context file to cover the authenticated API routes
```
