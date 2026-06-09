# SRM-AUTH-01 — Phishing-resistant MFA for application access

**Maps to:** NIST 800-53 Rev5 **IA-2(1)** (→ projected to every framework via the hub).
**Severity:** high · **Customer responsibility**

## What it checks
Whether access to the application is protected by **phishing-resistant MFA**
(WebAuthn/FIDO2 or PIV), or — for a sole operator-as-customer — whether the
single-factor residual risk has been explicitly accepted.

```
auth.phishing_resistant == true   # WebAuthn/FIDO2 or PIV
  OR
auth.risk_accepted == true        # sole-customer risk acceptance (POAM-021)
```

## Why
Single-factor / OTP authentication is phishable. M-22-09 and modern FedRAMP/CMMC
posture require phishing-resistant MFA for IA-2(1). A customer consuming this CSO
must either federate to an IdP that enforces phishing-resistant MFA (or use native
WebAuthn with FIPS-AAGUID attestation), or — if they are the sole user — accept the
residual risk explicitly. Onboarding additional users re-opens this.

## How to remediate a fail
Set `auth.phishing_resistant = true` after enabling WebAuthn/FIDO2 or IdP
federation, **or** record an explicit `auth.risk_accepted = true` with an
authorized acceptance.
