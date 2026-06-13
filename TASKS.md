# Remediation progress — FedRAMP assessment findings

Run mode: **PR-only** (applies via CI on merge; local read-only creds broadened for Done-checks). Base: `main` @ `3b3d8b2` (cycle-2 PR #93 merged). One PR per task, stacked.

| Task | Scope | Status |
|---|---|---|
| 0 | Ground truth (live vs artifacts); `docs/assessment/ground-truth.md` | ✅ done |
| 1 | Inventory completeness + fail-closed reconciliation gate (keystone) | ⏳ in progress — **STOP for review after** |
| 1.5 | Pipeline publish integrity + ZAP/DAST into VDR | ⬜ pending |
| 2 | GitHub OIDC for deployer; delete IAM user (POAM-001) | ⬜ pending |
| 3 | Cognito + API GW authorizer/throttling/access-logging; drop Basic Auth (POAM-021/022/023/024) | ⬜ pending |
| 4 | Migrate app to Bedrock; remove Anthropic interconnection (POAM-020); close POAM-019 | ⬜ pending |
| 5 | KMS-sign runtime signal (POAM-002, D-2); Route 53 DNSSEC (D-3) | ⬜ pending |
| 6 | SSE-KMS for S3 + logs + Lambda env (POAM-011/018) | ⬜ pending |
| 7 | Log retention 365d; CloudFront/S3 access logging; SC-7/SC-5 narrative (POAM-017/005/007/008) | ⬜ pending |
| 8 | Revisited cost-trade-off findings under Moderate (POAM-003–018) | ⬜ pending |
| D | Document what tooling can't fix (A-1, A-3, C-4, A-2) | ⬜ pending |

## Required human / console actions (surfaced, not blocking)
- **DNSSEC DS record** at the registrar (Task 5) — I enable signing + output the DS record; operator publishes it.
- **Bedrock FedRAMP-authorization confirmation** (Task 4) — compliance fact to confirm from a current source.

## Couldn't verify / deferred
- Write-path Done-checks on API GW/Secrets/Cognito/KMS/SQS/Signer defer to apply-time in CI (PR-only).
