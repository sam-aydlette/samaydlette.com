# SRM-SC-01 — TLS in transit

**Maps to:** NIST 800-53 Rev5 **SC-8** (→ projected to every framework via the hub).
**Severity:** high · **Customer responsibility**

## What it checks
That the customer's endpoints enforce a TLS minimum version of **1.2 or 1.3**.

```
tls.min_version == "1.2"  OR  tls.min_version == "1.3"
```

## Why
Cryptographic protection of data in transit (SC-8). TLS below 1.2 is deprecated and
exposes data to downgrade/interception.

## How to remediate a fail
Configure your endpoint/CDN to a minimum TLS version of 1.2 (1.3 preferred) and set
`tls.min_version` accordingly.
