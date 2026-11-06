# Privacy Threshold Analysis (PTA)

## Purpose

Per OMB Circular A-130 and NIST SP 800-122, this Privacy Threshold Analysis records whether the system processes, stores, or transmits Personally Identifiable Information (PII) and, if so, whether a full Privacy Impact Assessment (PIA) is warranted.

## Determination

**The system does not process, store, or transmit PII.** A full PIA is not required at this time.

## Scope reviewed

The following surfaces of the system were examined for PII handling:

- **Public site content** (`website/**/*.html`): static personal-portfolio content, blog posts, research papers. No PII collected from readers.
- **Forms / interactive endpoints**: the base site has no forms, no comment systems, no contact submission forms, and no user accounts. The one interactive endpoint is the gated **Silk Reeling Mirror** app (see its dedicated bullet below), added under [SCN-2026-001](scn/SCN-2026-001-silk-reeling.md).
- **Silk Reeling Mirror app** (`infrastructure/silk-reeling.tf`, active in production — `create_silk_reeling = true` in the main deploy pipeline, live since 2026-06-03): a movement-feedback app gated by Amazon Cognito sign-in (`infrastructure/cognito.tf`).
  - **Authentication**: Amazon Cognito accounts that only the operator can create (`allow_admin_create_user_only`; no self-registration), with required TOTP MFA; the API Gateway JWT authorizer and the app both validate the token. No reader can sign up, so nothing is collected from the public.
  - **Pose input**: the camera feed and pose extraction run **client-side in the browser**; raw video never leaves the device. The per-frame body landmarks the browser extracts (33 points per frame, no images) are sent over TLS to the app Lambda, which scores them and writes the feedback text itself. Nothing is sent to a third party: the app's optional LLM-written feedback is disabled in this deployment, and the Anthropic interconnection it used was removed under [SCN-2026-006](scn/SCN-2026-006-remove-anthropic-interconnection.md).
  - **Persistence**: requests are stateless; pose frames are transient and not persisted. No user profile, history, or biometric template is stored.
- **Analytics**: none. No JavaScript analytics, no tracking pixels, no third-party tracking. CloudFront access logs record no IP address, user agent, referrer, cookies or query string, and are deleted after 90 days (`infrastructure/bootstrap/trust-access-logs.tf`, CDS-TRC-ACL).
- **Cookies**: none set by the site. The only cookies that could touch a reader's browser are AWS-default CloudFront request-routing cookies (no user identification, no persistence beyond request).
- **Lambda runtime KSI emitter**: processes only AWS configuration metadata (S3 bucket configuration, CloudFront distribution settings). No PII inputs, no PII outputs.
- **CI/CD chain**: GitHub Actions, AWS API calls, Sigstore signing. No PII transits this chain.
- **Published artifacts at `/.well-known/`**: KSI signal, VDR report, Security Decision Record, Certification Package Overview, IIW CSV, security.txt. None contains PII. Asset identifiers, system IDs, component names, and provenance are operational metadata, not PII.
- **Operator's name and email** in the Certification Package Overview (accountable official) and in `security.txt`: the operator is a public author and consents to publication of their name and contact email for system-administration purposes. This is professional contact information published deliberately, not PII collected from a third party.

## Federal customer data

There is no federal agency customer of this system today. No federal customer data is processed, stored, or transmitted.

## Re-assessment triggers

The PTA is reopened and re-determined if any of the following changes:

- The system adds end-user accounts, authentication, or any form-collected input
- The system adds analytics that collect identifiable visitor information
- The system onboards a federal agency customer
- The system begins processing customer data in any form
- The system handles employee or vendor PII

Per the FedRAMP 20x Significant Change Notifications rule, any change that introduces PII processing is a Transformative change (`SCN-TRF-*`) and triggers re-assessment of the PTA before the change deploys.

## Determination record

| Field | Value |
| --- | --- |
| System | samaydlette.com |
| Determination | No PII processed |
| Determination date | 2026-05-08 |
| Re-determined | 2026-06-07 — re-determination under [SCN-2026-001](scn/SCN-2026-001-silk-reeling.md) (Silk Reeling Mirror app). Determination unchanged: **no PII processed.** Pose video is processed client-side and never leaves the device; only derived non-PII metrics cross the boundary; the app credential is an operator-set shared secret, not third-party PII. No PIA triggered. |
| Reviewer | Sam Aydlette (operator) |
| Re-check | every deploy and night by machine (`scripts/check-non-machine-vv.py`), each Annual Security Review (`scripts/hold-security-review.py`), and any SCN that changes data processing |
| Full PIA required | No |

This determination is re-checked, with its sha256, in each Annual Security Review ([`docs/security-review.md`](security-review.md), `scripts/hold-security-review.py`), and re-determined in the pull request of any change to the system's data-processing posture.

## Reference

- NIST SP 800-122: *Guide to Protecting the Confidentiality of Personally Identifiable Information (PII)*
- OMB Circular A-130: *Managing Information as a Strategic Resource*
- [`docs/policies/pt-policy.md`](policies/pt-policy.md): the PT family policy that this PTA backs
