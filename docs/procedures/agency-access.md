# Agency Access to the Certification Package

This procedure covers how the certification package is made available, how an access request is decided, what happens when one is denied, and how the inventory of agencies with access is kept. It implements CDS-UTC-AGA, CDS-UTC-AAD, CDS-TRC-AAI and CDS-TRC-SSM. Decision records: DEC-165 (this procedure) and DEC-194 (no engagement).

**No engagement (DEC-194).** This system is a proof of concept. The operator does not engage FedRAMP or any federal agency about it: no real request is taken, decided, answered or notified. Every requester below is simulated, and the register `data/agency-access.json` may hold only entries marked `simulated: true` for an agency whose name ends "(simulated)"; `scripts/agency-access.py validate` fails the deploy on anything else. Anyone who really, really wants something can say hello on LinkedIn (the security contact in `/.well-known/security.txt`); the operator may consider it, with no obligation and no deadline.

**The package is public.** Every piece of certification data is served without authentication from the trust center (https://samaydlette.com/trust/) and listed, with its URL, media type, signature and human-readable view, in the signed manifest https://samaydlette.com/.well-known/trust-manifest.json. Nobody needs to ask, register or hold an account to read or download any of it.

**Decision by rule.** Nobody decides a request by hand. `scripts/agency-access.py` decides each access request on the day it arrives by fixed rules applied to what it asks for: a request for write access, for delivery other than HTTPS, for data beyond the public package, or from an agency that cannot be verified is denied, with the rule and its reason recorded; anything else is granted, because everything is already public. A withdrawal removes a grant from the inventory.

**Denial notice.** The automated notifier writes a notice of every denial to the simulated FedRAMP as a log entry, and the clock requires it within 5 business days (US federal holidays excluded). The deploy computes each deadline and fails when a notice is late or overdue. Nothing is sent to FedRAMP or anyone: the notice is the log entry.

**Inventory and history.** `scripts/agency-access.py inventory` prints the agencies and systems on record and the full history of requests, decisions, withdrawals and notices. With no real entries, it is empty.

**Exercise.** On every deploy, `scripts/agency-access.py exercise` runs the rules and the notifier over a scenario of plainly fictional agencies (`data/agency-access-exercise.json`) dated relative to that day, with a simulated notifier outage and a slow notifier queue, so the late and overdue notices it must catch occur. It fails the deploy unless every outcome is the expected one. The signed log, headed by the no-engagement statement, is published at https://samaydlette.com/.well-known/agency-access-exercise.json.

**Access records.** Viewers are never identified in the trust center's access records (CDS-TRC-ACL); beyond the 90-day raw records, only the published monthly access summaries are kept.

**Verification.** Machine-checked on every deploy and every night (`scripts/check-non-machine-vv.py`), and re-checked, with its sha256, in each Annual Security Review (`scripts/hold-security-review.py`); a change is a reviewed pull request.
