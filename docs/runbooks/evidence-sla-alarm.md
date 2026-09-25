# Runbook: an evidence SLA alarm fired

The evidence SLA watchdog (`infrastructure/watchdog.tf`) emails the operator through the `samaydlette-com-evidence-alerts` SNS topic when published compliance evidence goes stale. It runs hourly on AWS's clock, independent of GitHub, and pages when a metric breaches in 2 of the last 3 hourly periods. When an alarm clears you get an OK email.

| Alarm (`samaydlette-com-evidence-watchdog-…`) | Fires when | Usually means |
|---|---|---|
| `nightly-failed` | the evidence nightly's last run failed, or no run has reported in 26h | a gate failed; or the cron is disabled or stuck |
| `vdr-age` | the published VDR is more than 24h old | the reporting policy is breached; nightly runs have failed or stopped |
| `runtime-age` | the runtime signal is more than 26h old | the daily runtime-check Lambda has failed or stopped |

Any alarm also fires if the watchdog stops publishing metrics, because missing data counts as a breach. If all three fire together, check the watchdog itself first.

## `nightly-failed`

1. Open the latest **Evidence Nightly** run in GitHub Actions. The status beacon at `/.well-known/vdr-status.json` gives its URL (`run_url`), the overall `result`, and each gate's outcome.
2. The GitHub issue labelled `evidence-freshness` names the gate and, for a vulnerability-gate failure, each finding with its advisory and any open Dependabot PR.
   - **Vulnerability gate failed:** follow [`vuln-gate-failure.md`](vuln-gate-failure.md).
   - **Reconciliation gate failed:** the live system and its documentation disagree. The step log names the failing invariant. Fix the drift through the reviewed deploy path; never weaken the gate.
   - **`not reached` everywhere, or no recent run at all:** check whether GitHub has disabled the workflow's schedule (**Actions → Evidence Nightly**; it does this after 60 days without repository activity) and re-enable it. Then run it once by hand.
3. Close the alert issue once a run passes. The alarm clears on its own within about two hours.

## `vdr-age`

The policy is already breached, so treat this as the priority. It usually follows `nightly-failed`: fix that, and the next passing run republishes the VDR. The nightly runs twice a day, so a single late run should not reach 24h. If the nightly is passing but the VDR is still old, the publish or CloudFront step is at fault. The run's "Assert published evidence is fresh at the edge" step says which.

## `runtime-age`

Check the compliance Lambda (`samaydlette-com-opa-compliance`): its CloudWatch logs, its EventBridge rule, and the shared dead-letter queue `samaydlette-com-opa-compliance-dlq` for failed invocations.

## All three at once

Check the watchdog: its log group `/aws/lambda/samaydlette-com-evidence-watchdog`, the dead-letter queue, and its EventBridge rule. Each run logs one JSON line with the three values it published.

## Setup and testing (operator)

The email subscription is **not** in Terraform, deliberately: an address in Terraform ends up in state and in the plan artifact CI uploads for a public repository. Create it once, with your own credentials:

```sh
aws sns subscribe --region us-east-2 \
  --topic-arn "$(aws sns list-topics --region us-east-2 --query "Topics[?ends_with(TopicArn, ':samaydlette-com-evidence-alerts')].TopicArn" --output text)" \
  --protocol email --notification-endpoint <your address>
```

Then confirm the subscription from the email AWS sends.

To test end to end, force one alarm into ALARM and back. This proves the whole delivery path, including the KMS grant that lets CloudWatch publish to the encrypted topic, which otherwise fails silently:

```sh
aws cloudwatch set-alarm-state --region us-east-2 \
  --alarm-name samaydlette-com-evidence-watchdog-nightly-failed \
  --state-value ALARM --state-reason "manual end-to-end test"
```

An email should arrive within a minute. The alarm returns to its real state at the next evaluation.

## Silencing

To stop the emails during planned work, disable alarm actions rather than deleting anything:

```sh
aws cloudwatch disable-alarm-actions --region us-east-2 --alarm-names <alarm-name>
```

Re-enable them with `enable-alarm-actions`. The next deploy also restores them.
