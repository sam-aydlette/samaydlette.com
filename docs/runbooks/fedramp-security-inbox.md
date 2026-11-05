# Runbook: the FedRAMP Security Inbox

The FedRAMP Security Inbox (FSI) is the address FedRAMP writes to (AFC-CSO-INB). The address is in `data/cds/offering.json` under `fedramp_security_inbox.address`, and nowhere else. The CPO publishes it, and the infrastructure reads it from that file.

**Senior security official** (AFC-CSO-EMR): the accountable official named in the CPO (`accountable_official` in `data/cds/offering.json`), who is the operator. Pages go to the operator's subscription on the evidence-alert SNS topic (`samaydlette-com-evidence-alerts`). The runbook [`evidence-sla-alarm.md`](evidence-sla-alarm.md) explains how to set up that subscription.

## How it works

| Step | What happens | Rule |
|---|---|---|
| Receive | The domain's MX record points to SES receiving in us-east-2. One receipt rule accepts mail for the inbox address only. TLS is optional, so a sender without TLS is not refused. Spam and virus verdicts are recorded and never used to drop mail. | RCV |
| Store | SES writes the raw message to `s3://samaydlette-com-fsi-mail/inbound/<message id>`, encrypted with the at-rest CMK. | INB |
| Classify | The `samaydlette-com-fedramp-inbox` function treats mail as FedRAMP when the From address or the envelope sender is exactly `@fedramp.gov` or `@gsa.gov`. A failed SPF, DKIM or DMARC check is shown in the page, but the message is still treated as FedRAMP. | TFG |
| Designate | The function reads the designator from the subject line: Emergency Test, Emergency, Important, or none (a general message). It matches broadly, so an occasional false Emergency is possible; a missed one is not. | CDS |
| Track | The function writes a register item to `register/open/<id>.json`. The item has a triage deadline and, for Emergency and Emergency Test messages, a due date for the required actions. The default due date is 3:00 p.m. ET on the 2nd business day, which is the AFC-FRP-ERT default for Class C. | CRA, IMA |
| Acknowledge | SES sends an automatic reply to the sender from the inbox address. The reply is DKIM-signed, and it is not sent to auto-replies, bulk mail, bounces, or mail that fails sender authentication (genuine FedRAMP mail passes SPF, DKIM and DMARC under AFC-FRP-VRE; a forged sender must not be able to make the inbox mail a government address). Unauthenticated mail is still registered and paged. | ACK |
| Page | The function publishes to the alert topic with the sender, subject, designation and due dates. It never includes the message body. | EMR, IMA |
| Check hourly | The function compares the live receipt rule, domain identity, MX record and SES account status with the Terraform configuration. It also counts overdue register items. Each result is a metric with its own alarm. | RCV, TFG |

The triage windows are 2 hours for Emergency and Emergency Test, 24 hours for Important and 72 hours for general messages. They are set in `infrastructure/fedramp-inbox/logic.mjs` (`TRIAGE_HOURS`) and pinned by `tests/test_fedramp_inbox.py`.

## When a page arrives

Run the commands below from a checkout, using the operator's AWS credentials. The operators group policy `fedramp-inbox-operator` grants the access they need.

1. **Read the message.** `python3 scripts/fsi.py show <id>` prints the register item and the message as plain text. HTML is reduced to its text and is not rendered. Attachments are listed but not opened. If you need to open an attachment, do it in a disposable environment, never on the workstation that holds the deploy credentials.
2. **Confirm the sender if the page says NOT AUTHENTICATED,** or if an Emergency did not come from `fedramp_security@`. Do this through a channel you already trust, such as `help.fedramp.gov` or a known FedRAMP contact. Do not use contact details from the message itself. If the sender turns out not to be FedRAMP, close the item with `--outcome not-fedramp`. Under AFC-CSO-TFG, the inbox rules then no longer apply to that message.
3. **Triage the item.** Record the timeframe the message states, which takes precedence over the default due date: `python3 scripts/fsi.py triage <id> --respond-by 2026-11-10T15:00-05:00 --note "…"`. Important messages cannot be triaged without `--respond-by` (AFC-CSO-IMA). For Emergency messages, `--respond-by` replaces the Class C default.
4. **Complete the required actions** that the message lists (AFC-FRP-RQA). Reply to FedRAMP from your mail client, and copy the inbox address so the reply is on record. Then close the item: `python3 scripts/fsi.py close <id> --outcome completed --note "what was done, when, reply sent"`. The `close` command reports it when the item was closed after its due date.

`python3 scripts/fsi.py list` shows the open items, and `list --all` also shows the closed ones.

## Alarms

All three alarms page through the evidence-alert topic.

| Alarm (`samaydlette-com-evidence-watchdog-…`) | Fires when | Do this |
|---|---|---|
| `fsi-config` | The live receiving setup differs from Terraform in 2 of 3 hourly checks, or the check stopped reporting. Differences include an inactive or edited rule, a rule ahead of the inbox rule, a failed DKIM or MAIL FROM setup, the SES sandbox, or a changed MX record. | Read the latest `inbox check` line in the function's log; it names each problem. Fix the setup through Terraform and the reviewed deploy. Never fix it by hand in the console: the next deploy would undo the change, or this check would page about it. |
| `fsi-overdue` | An open item is past its triage window, an item is past its due date and not closed, an Important item was triaged without a timeframe, or an acknowledgement or page failed. | Run `python3 scripts/fsi.py list`. A failed acknowledgement while the account is in the SES sandbox is expected; see below. |
| `fsi-errors` | The function failed. Usually this means a page did not go out. | The message is already in the bucket. SES retries the function twice, and failed events go to `samaydlette-com-opa-compliance-dlq`. Check the function's log, fix the cause, and run `fsi.py list` to find the item that was missed. |

## The SES sandbox

A new SES account is in the sandbox. In the sandbox, SES sends only to verified addresses, so acknowledgements to FedRAMP fail. Each failure is recorded and counted by `fsi-overdue`, and the hourly check reports the sandbox in `fsi-config`. Receiving is not affected. To fix this, request production access in the SES console for us-east-2 (**Account dashboard → Request production access**), describing the use case as an automatic acknowledgement to a single government sender domain at very low volume.

## Changing the address (AFC-CSO-NOC)

1. Notify FedRAMP **before** you change the address. Use the "[CSP] Notification of Changes" form at `https://help.fedramp.gov/hc/en-us/requests/new?ticket_form_id=51829466938011`, and send from the old inbox if it still works.
2. In `data/cds/offering.json`, add a history entry: `{"address": "<new>", "since": "YYYY-MM-DD", "fedramp_notified": {"on": "YYYY-MM-DD", "channel": "help.fedramp.gov Notification of Changes form, ticket <n>"}}`. Then change `address` to the new value.
3. Open a PR. The unit-test job step **FedRAMP Security Inbox change notice (AFC-CSO-NOC)** fails if the address changed without a history entry, without the `fedramp_notified` marker, or with an edited history.
4. After the deploy, run the exercise below against the new address.

## The exercise

Run the exercise after the first deploy, after any address change, and once a year. It takes about five minutes.

```
python3 scripts/fsi.py exercise --reply-to <your SES-verified address> --smtp --record docs/exercises
```

The exercise invokes the inbox function with a synthetic Emergency Test from a FedRAMP address. This runs the real classifier with nothing bypassed. The exercise then checks that the register item exists, that the acknowledgement was sent (to your address, never to FedRAMP), and that the page was published. With `--smtp`, it also sends one real message to the inbox address from `fsi-exercise@samaydlette.com` and waits up to 3 minutes for SES to store it. The exercise writes an outcomes-only record (no addresses, no subjects) to `docs/exercises/fsi-exercise-<date>.json`. Commit that file.

When the page email and the acknowledgement arrive, close the item: `python3 scripts/fsi.py close exercise-<nonce> --outcome exercise-complete --note "page and ack received <time>"`. To check the overdue alarm as well, leave the item open for more than 2 hours. The `fsi-overdue` alarm should then fire.

While the account is in the sandbox, `--reply-to` must be a verified address, and the `--smtp` step sends to the inbox address. That address is in the verified domain, so the sandbox allows it.

## What this does not do

- It does not read or act on message content automatically. Deciding what a message requires, and completing it, is the operator's job. The system's job is to make sure the operator learns of the message and that the deadline cannot pass unnoticed.
- One person operates the system. If that person is unavailable, pages wait until they return; there is no second reader. The `fsi-overdue` alarm keeps paging, so an absence is visible but not covered. Naming a backup reader is the operator's decision.
- Federal holidays are not counted when the default due date is computed. Ignoring them can only make the default earlier, never later.
