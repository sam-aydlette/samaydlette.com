# Annual Security Review

This document satisfies KSI-PIY-06 — persistent review of the effectiveness of investments in achieving security objectives.

## Scope

"Investments" here means the time spent and the recurring costs paid for security controls. The review answers: are the chosen controls producing security outcomes proportionate to their cost?

## Review template

```
## YYYY: Annual security review

### Recurring costs (USD/year)
- Lambda compliance executions: $X
- EventBridge rules: $X
- CloudWatch logs: $X
- Other (TLS, DNS, S3 storage): $X
- Total compliance overhead: $X

### Time invested (hours)
- Compliance pipeline maintenance: <approx>
- Incident response: <approx, may be 0>
- Documentation review: <approx>
- Recovery tabletops: <approx>

### Controls in place vs. controls considered
See README "Conscious Trade-offs for Budget Reality" for the live decision table.
Changes from prior year:
- <added>
- <removed>
- <re-evaluated>

### Effectiveness signals
- Number of incidents this year: <count>
- Drift events caught by runtime KSI emitter: <count>
- OPA gate failures caught pre-deploy: <count>
- Sigstore-verified deploys: <count, should equal deploy count>
- Dependabot PRs merged / dismissed: <ratio>

### Decisions for next year
- Controls to add: <list, justified>
- Controls to remove: <list, justified>
- Cost target: <$/year>
- Documentation updates needed: <list>
```

## 2026: First entry

### Recurring costs (USD/year)

- Lambda compliance executions: ~$12
- EventBridge rules: ~$36
- CloudWatch logs: ~$77
- TLS certificate (ACM): $0 (free)
- DNS (Route 53 hosted zone + queries): ~$6
- S3 storage + requests: ~$12
- CloudFront (Price Class 100): ~$10–30 depending on traffic
- **Total compliance overhead:** ~$125
- **Total infrastructure:** ~$160–180

### Time invested (hours)

- Initial build of canonical inventory + KSI signal infrastructure: ~40 hours
- OSCAL Rev 5 generator: ~16 hours
- Documentation set (this doc and siblings): ~6 hours
- Incident response: 0 hours (no incidents)

### Controls in place vs. considered

See README "Conscious Trade-offs for Budget Reality." Excluded controls (WAF, multi-AZ, S3 access logging) remain consciously excluded for the same reasons. New for 2026: deploy-time KSI signal signing via Sigstore keyless; runtime KSI emitter; OSCAL Rev 5 SSP generator.

### Effectiveness signals

- Incidents: 0
- Drift events caught by runtime emitter: 0 (not yet running on schedule at time of first review; deploys to date have been hand-triggered)
- OPA gate failures caught pre-deploy: substantial (the accessibility cascade was caught and fixed during initial build, after fixing the subshell-scope bug in `terraform-plan.sh`)
- Sigstore-verified deploys: equal to deploy count
- Dependabot: enabled this year; baseline established

### Decisions for next year

- Continue current control set
- Verify runtime emitter has produced at least one drift signal event in a controlled test (deliberately misconfigure a non-production resource and confirm the daily Lambda flags it)
- Close [POAM-001](poam.md) by completing the GitHub OIDC migration; until then, hold to the 90-day key-rotation cadence below
- Consider whether OSCAL artifact should be signed independently or covered by the same Sigstore bundle as the KSI signal
- Cost target: maintain ~$125/year compliance overhead

## AWS access key rotation log

Rotation cadence: 90 days. Active compensating control while [POAM-001](poam.md) remains open. Procedure in the [Secure Configuration Guide](policies/secure-configuration-guide.md). Emergency rotations (suspected compromise) are logged here too with the trigger noted.

| Rotation date | Trigger | Outcome | Notes |
| --- | --- | --- | --- |
| _Pending first rotation_ | _scheduled_ | _—_ | First rotation due 90 days from initial key issuance. |
