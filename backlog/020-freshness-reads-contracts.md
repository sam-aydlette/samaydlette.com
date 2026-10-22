# Make every freshness consumer read its threshold from the product contracts.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: the hardcoded windows are replaced with contract reads in `infrastructure/watchdog.tf` (via `yamldecode(file(...))`), `infrastructure/watchdog/logic.mjs` (via an environment variable Terraform passes), `scripts/build-trust-center.py`, `scripts/check-evidence-freshness.py` and `MAX_EVIDENCE_AGE_HOURS` in the nightly, `scripts/check-runtime-divergence.py`, and the ZAP default in `scripts/build-vdr-report.py`, with `--zap-max-age-days` passed explicitly by the deploy and the nightly; `terraform plan` shows no change to alarm thresholds; a test asserts every consumer equals its contract and that a ZAP window of 0 is rejected; `security/zap/README.md` points at the contract.
OUT OF SCOPE: Changing any threshold value. Changing the watchdog's network posture.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: `infrastructure/watchdog.tf` L49 (24 h) and L54 (26 h); `infrastructure/watchdog/logic.mjs` L16 (26 h); `scripts/build-trust-center.py` L40-46 and the literal "48 hours" at L394; `scripts/check-evidence-freshness.py` L35 and `evidence-nightly.yml` L113; `scripts/check-runtime-divergence.py` L228 (48 h); `scripts/build-vdr-report.py` L1499; the deploy passes `--zap` at L1465 and the nightly at L508, neither with a max age. The watchdog Lambda has no internet egress, so thresholds reach it through Terraform, never a fetch. The nightly's role must not change.
DEPENDS ON: 019
LIVE-EDGE: `aws cloudwatch describe-alarms --alarm-name-prefix evidence --query 'MetricAlarms[].Threshold'` matches the contracts (report the outcome in the PR, not the alarm ARNs).
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Phase 2, serialized after 019.
