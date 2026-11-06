# Terraform plan fixtures

Synthetic `terraform show -json`-shaped documents used by the OPA gate's test
and golden suites. **No real plan was run to produce these** (a real plan
would require cloud credentials); each file carries a `_fixture` block naming
what it models and why. Shapes mirror terraform 1.9.x with hashicorp/aws ≥ 4.x
split S3 sub-resources (`aws_s3_bucket_versioning`,
`aws_s3_bucket_server_side_encryption_configuration`,
`aws_s3_bucket_public_access_block`), modeled on the production stack's
resource layout as observed in the public CI logs. The AWS account id used in
ARNs is `123456789012`, the AWS documentation placeholder.

| Fixture | Models |
|---------|--------|
| `compliant-stack.json` | Fully compliant bucket + CloudFront + KMS key, provider-4.x split sub-resources |
| `s3-missing-tags.json` | Governance tags missing on a bucket |
| `s3-versioning-disabled.json` | Versioning sub-resource `Suspended` |
| `s3-encryption-disabled.json` | No SSE sub-resource |
| `s3-public-access-open.json` | Public-access block with one flag false |
| `cloudfront-insecure-protocol.json` | `viewer_protocol_policy = allow-all` |
| `cloudfront-weak-tls.json` | `minimum_protocol_version = TLSv1_2016` |
| `missing-classification.json` | Taggable resource without the six classification axes |
| `data-source-website-bucket.json` | Production shape: bucket is a data source, only sub-resources planned |
| `s3-computed-bucket-name.json` | Bucket name unknown until apply; join only possible via `configuration` references |
| `delete-only.json` | Non-compliant resource being destroyed (must not gate) |
| `service-stack-compliant.json` | Every service type the runtime emitter re-validates (IAM role + inline policy, Cognito, KMS, log group, API stage + routes, Lambda, SNS, SQS, alarm, schedule, CloudTrail), compliant |
| `service-stack-computed-key.json` | As above with a log group KMS key unknown until apply: deferred to the runtime check, not failed |
| `iam-admin-wildcard.json` | Inline role policy allowing `*` on `*` |
| `iam-oidc-trust-unscoped.json` | GitHub OIDC trust with no subject condition |
| `cognito-mfa-optional.json` | User pool MFA `OPTIONAL` |
| `kms-rotation-disabled.json` | Symmetric customer key without rotation |
| `log-group-unencrypted.json` | Log group with no customer key, known at plan time |
| `apigw-route-unauthorized.json` | `/api` route without an authorizer |
| `log-read-grant-curious-carl.json` | Curious Carl (simulated), an intern, granted log reads by an inline policy and by the CloudTrail bucket's policy; the deploy's two allowlisted log readers alongside, which must not fire |
| `empty.json`, `garbage.json` | Malformed input; must yield an explicit `input_error`, never a silent pass |

`tests/fixtures/resources/` holds the same resources flattened into the
single-resource `{"resource": ...}` input shape — the contract the **runtime
Lambda** feeds the compiled policy — derived mechanically from these plans.
`tests/fixtures/html/` holds the Section-508 fixture pages.
