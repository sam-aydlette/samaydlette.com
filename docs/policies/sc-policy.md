# SC — System and Communications Protection

Communications integrity:

- viewer ↔ CloudFront: TLS 1.2+ enforced via the CloudFront security policy
- CloudFront ↔ S3: TLS within the AWS network, Origin Access Control authentication via service principal + SourceArn condition
- Lambda ↔ AWS service APIs: TLS within the AWS network
- CI ↔ AWS APIs: TLS, with credentials scoped via IAM
- cosign ↔ Fulcio/Rekor: TLS, with OIDC-bound ephemeral identities

All cryptographic primitives in use rely on AWS-managed FIPS 140-validated modules (KMS for AWS-default encryption-at-rest, ACM for TLS termination) or the Sigstore chain (Fulcio for X.509 issuance, Rekor for transparency-log integrity). The list of cryptographic modules is auditable from the canonical inventory.

Several SC controls are inherited from AWS East/West Moderate FedRAMP authorization (Package ID: AGENCYAMAZONEW), notably the SC-12 family (cryptographic key establishment) and SC-45 (system time synchronization). SC-13 (cryptographic protection) operates against the AWS FIPS-validated modules in the AWS authorization.

**20x rule integration.** Using Cryptographic Modules (`UCM-*`) — covered by AWS KMS/ACM and Sigstore. Communication integrity (KSI-SVC-VCM).

**Review cadence.** Annually with the [security review](../security-review.md); after any Transformative change to the TLS or signing posture.
