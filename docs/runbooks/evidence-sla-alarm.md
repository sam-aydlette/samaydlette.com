# Runbook: an evidence SLA alarm fired

The evidence SLA watchdog (`infrastructure/watchdog.tf`) emails the operator through the `samaydlette-com-evidence-alerts` SNS topic when published compliance evidence goes stale. It runs hourly on AWS's clock, independent of GitHub, and pages when a metric breaches in 2 of the last 3 hourly periods. When an alarm clears you get an OK email.

| Alarm (`samaydlette-com-evidence-watchdog-…`) | Fires when | Usually means |
|---|---|---|
| `nightly-failed` | the evidence nightly's last run failed, or no run has reported in 26h | a gate failed; or the cron is disabled or stuck |
| `vdr-age` | the published VDR is more than 24h old | the reporting policy is breached; nightly runs have failed or stopped |
| `runtime-age` | the runtime signal is more than 26h old | the daily runtime-check Lambda has failed or stopped |
| `incident-report-overdue` | an incident report listed as due in `/.well-known/incident-reports.json` is past its Class C deadline, or the incident log is missing or unreadable | an Initial, Ongoing or Final incident report was not issued in time; or a vulnerability that is a FedRAMP Reportable Incident (VER-TFR-IRI/NRI) has no incident opened |
| `artifact-stale` | any artifact listed in `infrastructure/schemas/freshness-config.json` is past its window, missing, or has no readable timestamp | no deploy within the deploy-cadence window; the corroboration was not re-run; or one of the above |

The windows are governed values in `infrastructure/schemas/freshness-config.json`; the thresholds above are read from it. Change a window there, through review, never in the alarm.

Any alarm also fires if the watchdog stops publishing metrics, because missing data counts as a breach. If all five fire together, check the watchdog itself first (a missing or invalid freshness config stops it before it publishes anything).

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

## `incident-report-overdue`

The published incident log (`/.well-known/incident-reports.json`, `obligations_due`) names each report still due, for which incident or finding, and its deadline. Follow [`docs/incident-response.md`](../incident-response.md#reporting-fedramp-reportable-incidents-iec): record the report (or, for a finding with no incident, open the incident) in `data/incidents.json` and push it; the **Incident Reports** workflow validates, builds, signs and publishes within minutes, and the alarm clears once the republished log no longer lists the report as due. If the log itself is missing or unreadable, run the workflow by hand and check its publish step.

## `artifact-stale`

The watchdog's log line for the run lists the stale artifacts under `stale`. To see the same from outside, run `python3 scripts/check-evidence-freshness.py --all https://samaydlette.com`.

- **Deploy-cadence artifacts** (KSI signal, SSP, POA&M, trust center, boundary map, CDS artifacts): no deploy has run inside the window. Start and approve a deploy.
- **`boundary-corroboration.json`:** re-run `tools/boundary-map/corroborate.py`, commit the result, and deploy.
- **Nightly artifacts** (`vdr-*`): follow `nightly-failed` / `vdr-age` above.

## All five at once

Check the watchdog: its log group `/aws/lambda/samaydlette-com-evidence-watchdog`, the dead-letter queue, and its EventBridge rule. Each run logs one JSON line with the values it published, the config version, and the stale artifacts.

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
