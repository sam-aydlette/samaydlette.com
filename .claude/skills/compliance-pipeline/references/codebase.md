# Compliance pipeline: codebase map

Confirm against the working tree on first use, and correct this file in the same PR when reality differs.

## The canonical inventory and its artifacts

- `scripts/build-ksi-signal.py` builds **the canonical inventory** (the KSI signal). `build_html_components()` hashes every `*.html` under `website/` into it as an `html_artifact`.
- The VDR builder (`scripts/build-vdr-report.py`) and the CR26 record builders derive from the inventory:
  - `build-sdr.py`: the Security Decision Record. Its `rev5_controls` publishes the per-control view.
  - `build-cpo.py`: the Certification Package Overview.
  - `build-cr26-vdr.py`: turns the VDR report into FedRAMP's VDT, AVI and history reports.
- The CR26 reports are validated against FedRAMP's 2026-06-24 JSON schemas by `scripts/_fedramp_schema.py` before they are written; a report that does not validate is never written. The schemas are vendored verbatim, with their sha256s, in `infrastructure/schemas/fedramp-2026-06-24/`.
- `scripts/_controls.py` holds the control projection: status, origination and statement per NIST 800-53 control, computed in memory from the inventory and the KSI catalog. It replaced the OSCAL SSP, which was retired under CR26 on 2026-11-05.
- `scripts/_decisions.py` reads the decision register `data/decisions.json`. Under CR26 the register replaced the POA&M. The VDR builder, the vulnerability gate, reconciliation and the trust center all read it.
- `scripts/_common.py` holds the shared helpers: `classify` (the inheritance rule that four artifacts must agree on), `sha256_file`, `prop`, `load_hub`, `sid`.

## Gates

- `scripts/reconcile.py`: the reconciliation gate. It runs in CI before publish and fails closed. Its invariants are lettered (a)–(l) in the file header; (g) and (k) are retired. The ones referred to most:
  - (e) binding: the VDR, SDR and CPO are built from one inventory `signal_id`.
  - (f) publish freshness: the staged artifacts carry the current commit and an `emitted_at`. It has **no staleness threshold**; see pitfalls.
  - (h) finding coverage: every VDR finding carries a `decision_id` that resolves to an in-force record in `data/decisions.json`.
  - (l) boundary map: fails on an unclassified component.
- OPA policies live in `infrastructure/policy/` (`accessibility.rego` among them), plus `policies/triage.rego`, which decides the VDR triage.
- `scripts/vuln-gate.py` is the vulnerability gate; `scripts/detection-gate.py` fails the run when a scanner or feed failed.
- `scripts/check-published-redaction.py` scans what the deploy publishes for identifiers that must not leave.

## Published artifacts (`/.well-known/`)

- `website/.well-known/` is the publish root. In git it tracks only `security.txt` and `vdr-trend.json`. Everything else there is gitignored build output that the deploy signs and uploads, and the website sync excludes `.well-known/*`.
- Every freshness window is a governed value in `infrastructure/schemas/freshness-config.json`: one entry per published artifact, schema-validated, with who decided it and a review date. The trust center, the watchdog (Lambda and alarm thresholds) and `scripts/check-evidence-freshness.py` all read it and fail closed without it.
- Published reporting must be under 24 hours old.

## Boundary map

- `scripts/build-boundary-graph.py` generates the map **on every deploy** from the inventory and Terraform state, and publishes it signed at `/.well-known/boundary-map.json`.
- `docs/boundary/boundary-classification.json` is the operator-owned meaning: zones, groups, declared nodes and the data-flow table.
- `tools/boundary-map/corroborate.py` (local only) corroborates the map independently with RAMPART on TAP, which collects the account from the AWS APIs. The operator runs it and commits `docs/boundary/corroboration.json`. The deploy signs and publishes it as `/.well-known/boundary-corroboration.json`, and the trust center reports its result and age (30-day window). Resources only TAP sees go to the decision queue.

## Trust Center

- `scripts/build-trust-center.py` builds `/.well-known/trust-center.json` (signed): the "is this picture true?" checks, the queue of decisions that need a person, the policy catalog, the escalation rate and the decision log. All of it is derived from this build's artifacts and the registers. It runs after the reconciliation gate, and fails closed if its inputs are bound to another inventory.
- `website/trust/index.html` and `website/assets/js/trust.js` render it. The page re-checks the runtime signal and the nightly beacon live against the published freshness windows. `/viewer.html` is a redirect stub.

## Workflows and runtime

- `.github/workflows/deploy-with-opa.yml`: the gated deploy. The `deploy` job is bound to the `prod` environment (human reviewer). It has **no `schedule:` trigger**: every path to `terraform apply` is human-initiated and human-approved. It also runs the accessibility scan (pa11y) and `update-cache-version.js` before the S3 sync.
- `.github/workflows/evidence-nightly.yml`: the unattended VDR refresh, twice a day plus once after every successful deploy (`workflow_run`). It re-scans with Syft and Grype against a fresh vulnerability DB, rebuilds the VDR and trend, and runs the vulnerability and reconciliation gates. It then republishes its objects under `.well-known/` (the publish step lists each one) and, pass or fail, writes the unsigned status beacon `.well-known/vdr-status.json`. Its alerting is its own `alert` job (a GitHub issue).
- `infrastructure/watchdog.tf` and `infrastructure/watchdog/`: the evidence SLA watchdog. An hourly Lambda reads every artifact in the freshness config from the bucket (AWS APIs only, no internet egress) and publishes ages and counts as CloudWatch metrics. Four alarms email the operator through a CMK-encrypted SNS topic. The email subscription is created out of band so no address enters Terraform state. Runbook: `docs/runbooks/evidence-sla-alarm.md`.
- `infrastructure/lambda/`: the runtime Lambda. `infrastructure/bootstrap/`: the IAM trust layer, CloudFront (including the site CSP and headers), DNSSEC and the remote-state backend. The operator applies it by hand.

## AWS

The account is referenced in the published KSI signal; never commit it. `us-east-2` holds the site, app, Lambda, S3, CloudWatch, API Gateway and Secrets Manager. `us-east-1` holds ACM, CloudFront and the DNSSEC and CloudFront KMS keys. Confirm before acting.

## Make targets

| Target | What it does |
|---|---|
| `make dev-setup` | Creates `.venv` from `requirements-dev.txt`, which pins exactly what CI installs |
| `make check` | `lint` (ruff), `typecheck` (mypy, `scripts/`), `test` (pytest), `test-policies` (opa fmt, coverage floor, policy tests). Hermetic: no AWS, network, state or generated artifacts. About 4s; the first non-zero exit wins |
| `make check-full` | `check` plus `reconcile`. Needs generated artifacts, so it needs AWS |
| `make -C infrastructure plan` | `terraform plan` with the OPA compliance check |
| `make -C infrastructure apply-infra` | Applies the reviewed plan, **against production**. Publishes nothing |
| `make -C infrastructure pipeline` | `dev-setup validate plan apply-infra`, which **applies to production**. Never use it to check anything |
| `make -C infrastructure deploy` | A stub that refuses, by design |
| `make -C infrastructure verify-published` | Fetches and verifies the live published evidence |
