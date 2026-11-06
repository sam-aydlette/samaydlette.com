# FedRAMP Security Inbox (simulated)

> **This inbox is a simulation.** By the operator's decision, the FedRAMP Security Inbox does not exist for this proof of concept. No mail is received and none is sent. Its published contact reads: "Hit me up on LinkedIn: https://www.linkedin.com/in/sa2/".

Rules: AFC-CSO-INB, TFG, RCV, CRA, EMR, IMA, ACK and NOC (FedRAMP Consolidated Rules 2026, AFC family).

## What is real and what is simulated

| Part | Real or simulated |
|---|---|
| Inbox logic (`scripts/_fsi.py`): classification, designators, deadlines, register, acknowledgement, paging | Real code, tested |
| Messages from FedRAMP | Simulated: synthetic messages in `data/fsi-simulation/messages.json` |
| Mail system (receiving, sending acknowledgements, delivering pages) | Simulated: outbound legs are recorded, never sent |
| Published contact (`data/cds/offering.json`, `fedramp_security_inbox.contact`, published in the CPO) | Real, and it says it is a simulation |
| Change-notice check (AFC-CSO-NOC, `scripts/check-fsi-notice.py`) | Real, runs on every pull request and push |

## What runs on every deploy

The deploy step "FedRAMP Security Inbox simulation (synthetic messages; nothing received or sent)" runs before the Security Decision Record is built. It calls `scripts/build-fsi-simulation.py`, which:

1. Runs each synthetic message through the inbox logic:
   - an Emergency Test from FedRAMP's Emergency sender;
   - an Important message that tries to inject a header;
   - a general message;
   - a forged @gsa.gov Emergency that fails SPF, DKIM and DMARC;
   - an auto-reply, bulk mail and a bounce;
   - a message with an unreadable From line and a FedRAMP envelope sender;
   - an Emergency from a non-designated sender;
   - a look-alike domain and a display-name spoof;
   - a message whose first acknowledgement attempt fails.
2. Compares every outcome with the expected one written beside the message:
   - classification, designation and sender checks;
   - whether the acknowledgement is sent or suppressed, and why;
   - the page;
   - the deadlines.
3. Checks each acknowledgement for header safety. Then it runs the messages again, and the retry pass must send only the failed acknowledgement and nothing twice.
4. Exercises the register:
   - overdue items;
   - an Important message refused triage until its stated timeframe is recorded;
   - an Emergency reported once past its deadline until it is closed.
5. Exits 1 and writes nothing if any outcome differs. That fails the deploy before anything is published.

On success, the deploy signs `fedramp-inbox-simulation.json` and publishes it at `/.well-known/fedramp-inbox-simulation.json`. The file is labelled `"simulation": true` and holds sender domains only. Its freshness is governed by `infrastructure/schemas/freshness-config.json`.

## Reading the published result

- `result` is `pass` on every published copy, because a failing run publishes nothing.
- `cases[].observed` shows what the logic did with each synthetic message.
- `register_check.checks[]` lists each register behaviour with its expected and observed values.
- `retry_pass` shows that redelivery sends nothing twice.

## Changing a simulated outcome or adding a case

Edit `data/fsi-simulation/messages.json`, including the `expected` block, and run:

    python3 scripts/build-fsi-simulation.py --output /tmp/fsi-sim.json
    python3 -m pytest tests/test_fedramp_inbox.py

`tests/fixtures/fsi/simulation-wrong-expectation.json` must stay identical to the messages file except for its one wrong expectation. A test enforces this.

## Changing the published contact (AFC-CSO-NOC)

1. Record the notice to the simulated FedRAMP (a real provider would use the "[CSP] Notification of Changes" form on help.fedramp.gov). Nothing is sent to anyone (DEC-194).
2. In `data/cds/offering.json`, append a `history` entry with the new contact, `since`, and `fedramp_notified: {"on": "YYYY-MM-DD", "channel": "..."}`.
3. Change `contact`.

`scripts/check-fsi-notice.py` fails the pull request if the contact changes without that entry, or if the history is rewritten.

## What a real inbox would need

A real inbox would need four things:

- a mail receiver for an address on the system's domain;
- storage for received messages;
- authenticated outbound mail for acknowledgements;
- delivery of pages to the operator.

`scripts/_fsi.py` is written to be the logic behind them. None of this is deployed, by decision.
