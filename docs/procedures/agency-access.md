# Agency Access to the Certification Package

This procedure covers how agencies obtain the FedRAMP certification package, how a request is decided, what happens when one is denied, and how the inventory of agencies with access is kept and supplied to FedRAMP. It implements CDS-UTC-AGA, CDS-UTC-AAD, CDS-TRC-AAI and CDS-TRC-SSM. Decision record: DEC-165.

**The package is public.** Every piece of certification data is served without authentication from the trust center (https://samaydlette.com/trust/) and listed, with its URL, media type, signature and human-readable view, in the signed manifest https://samaydlette.com/.well-known/trust-manifest.json. An agency does not need to ask, register or hold an account to read or download any of it, so no request for the package itself is ever pending.

**Self-service.** An agency that wants to be on record, so that it is counted in the access inventory and can be told about changes, files the "Agency access to the certification package" issue form in the public repository, or writes to the security contact in `/.well-known/security.txt` for a private request. The same form withdraws an earlier record. The register records agencies and systems, never people: no names, email addresses or phone numbers.

**Decision.** The operator decides each access request and records it in `data/agency-access.json`: who decided, on what date, and, for a denial, why. Because everything is public, a denial can only concern something beyond the public package (for example, a request for write access or for data the system does not hold).

**Denial notice.** FedRAMP is notified of every denial within 5 business days (US federal holidays excluded). The deploy runs `scripts/agency-access.py validate`, which computes each denial's deadline and fails the deploy when a notice is late or overdue. In this proof of concept nothing is sent to FedRAMP or anyone: the notice is the entry recorded in the register.

**Inventory and history.** `scripts/agency-access.py inventory` prints the agencies and systems on record today and the full history of requests, decisions, withdrawals and notices. It is supplied to FedRAMP on request, through the same form or the security contact, and is not otherwise published.

**Exercise.** No federal agency has filed a request. On every deploy, `scripts/agency-access.py exercise` runs the same code over a scenario of plainly fictional agencies (`data/agency-access-exercise.json`) dated relative to that day, including a late and an overdue denial notice that it must catch, and fails the deploy unless every outcome is the expected one. The signed log is published at https://samaydlette.com/.well-known/agency-access-exercise.json.

**Access records.** A party that asks for the access records that concern it receives the trust center's access summaries for the artifacts it names (CDS-TRC-ACL). Individual viewers are never identified in those records.

**Review cadence.** Annually with the [security review](../security-review.md).
