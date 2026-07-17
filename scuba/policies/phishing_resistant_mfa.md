# SRM-AUTH-01 — Phishing-resistant MFA for application access

**Maps to:** NIST 800-53 Rev5 **IA-2(1)** (→ projected to every framework via the hub).
**Severity:** high · **Customer responsibility**

## What it checks
Which **authenticator posture** the customer's application accounts operate.
Since 2026-06-22 the CSO enforces mandatory TOTP MFA at the identity provider
for every account (the POAM-021 closure), so single-factor access is not
possible — the old sole-customer risk-acceptance branch no longer exists.

```
auth.mfa_type == "webauthn" | "fido2" | "piv"   # phishing-resistant — target posture
auth.mfa_type == "totp"                         # CSO-enforced baseline — passes, flagged phishable
anything else                                   # FAIL — inconsistent with this CSO
```

## Why
TOTP satisfies IA-2(1)'s MFA requirement (and CMMC 3.5.3), but OTP codes are
phishable; M-22-09 and modern FedRAMP/CJIS posture prefer phishing-resistant
authenticators. The provider tracks the phishing-resistant direction under
POAM-025; the customer's share is enrolling WebAuthn/FIDO2 (or PIV-federated)
authenticators for their users when available.

## How to remediate
A **fail** means your configuration claims no MFA, which this CSO does not
permit — fix the config (or confirm you are assessing the right deployment).
A **pass on TOTP** is compliant today; to reach the target posture, enroll
WebAuthn/FIDO2 authenticators and set `auth.mfa_type = "webauthn"`.
