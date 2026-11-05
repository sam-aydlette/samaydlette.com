# Secure Configuration Guide

The Secure Configuration Guide for samaydlette.com (`SCG-CSO-RSC`) is published on the site in two forms, generated on every deploy from one source:

- **Human-readable:** https://samaydlette.com/.well-known/secure-configuration-guide.md
- **Machine-readable:** https://samaydlette.com/.well-known/secure-configuration-guide.json (signed; `secure-configuration-guide.bundle`)
- **Live comparison and export:** https://samaydlette.com/.well-known/security-settings.json (and `.md`): every setting read from the live accounts during the deploy and compared with the guide's recommended defaults.

The source is [`data/secure-configuration.json`](../../data/secure-configuration.json), with the per-service cryptographic module list in [`data/crypto-modules.json`](../../data/crypto-modules.json). `scripts/build-scg.py` publishes the guide and `scripts/check-secure-config.py` runs the comparison; the deploy fails on a changed default without a new version and changelog entry, on a deviation that no in-force decision covers, and on a setting it cannot read.

## What the guide covers

- **Top-level administrative accounts:** the AWS root user and the GitHub repository owner: how each is named, and how to securely access, configure, operate and decommission it; the settings only those accounts can operate and what each means for security.
- **Privileged accounts:** the operator IAM user, the three CI roles GitHub Actions assumes through OIDC (deploy, plan, nightly), and administration of the Silk Reeling user pool.
- **For every setting:** the recommended secure default, its security implication, and the API or CLI call that reads and changes it.
- **Versioning:** a version number and a release history of the recommended defaults; each release records a digest of the defaults it fixes.
- **Cryptographic modules:** the module each service uses to protect data, with its CMVP certificate where AWS publishes one, and the agency-tenant defaults.

## Accepted deviation

The recommended default for the AWS root user and the operator IAM user is phishing-resistant MFA (a FIDO2 security key or passkey). Both use virtual authenticator-app (TOTP) MFA; that deviation is an accepted finding, [DEC-150](../../data/decisions.json), extending DEC-025, and the published comparison shows it against that record on every deploy.
