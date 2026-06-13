# DAST scans (OWASP ZAP)

Dynamic application security testing is run **offline on a monthly cadence** and
the report is **committed here**, rather than scanning the live site on every
build. Rationale: a live active scan every build would repeatedly attack
production (including the Silk Reeling API, which invokes an LLM — real cost and
junk traffic per push), make builds non-deterministic (external dependency), and
scan the previously-deployed version. Running it offline gives full control over
scan depth and authentication, and keeps the build deterministic.

## The contract

- Drop your latest ZAP JSON report at **`security/zap/zap-report.json`**.
- Every deploy's VDR build ingests it and **fails closed** if it is missing or
  **older than 35 days** (`--zap-max-age-days`, monthly + grace). A silently
  skipped scan cannot read as "0 findings."
- Every ZAP alert above informational then flows into the VDR as a vulnerability,
  and the **vulnerability gate** (`scripts/vuln-gate.py`) fails the build unless
  each one is fixed or dispositioned `false-positive` / `operational-requirement`
  in `data/vuln-dispositions.json`.

## Running the scan

Baseline (passive — static pages + spider), against the live site:

```
docker run --rm -v "$PWD/security/zap:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://samaydlette.com -J zap-report.json
```

Full / authenticated (active — includes the API), when you want deeper coverage:

```
docker run --rm -v "$PWD/security/zap:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t https://samaydlette.com -J zap-report.json
# add -z "auth.*" / a context file to cover the authenticated API routes
```

Then commit `security/zap/zap-report.json`. The report's `@generated` header is
what the freshness gate reads.
