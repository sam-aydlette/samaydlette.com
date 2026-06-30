# Resource Tagging Standard

Every information resource in this system carries a small, governed set of
classification tags at the asset level. The tags are operator-facing and
intentionally few; the machine-readable risk inputs the pipeline needs — the
CVSS Environmental requirements (CR/IR/AR), the VER internet-reachability axis
(IRV), and the multi-agency scope flag (m) — are **derived** from these tags
rather than tagged directly. This keeps the inputs auditable (a tag carries a
clear chain of thought) and keeps a single source of truth.

This standard is the asset-metadata layer the deterministic VDR PAIN classifier
reads (see `scripts/build-vdr-report.py` and the governed
`infrastructure/schemas/vdr-pain-config.json`). It is **not** itself a FedRAMP
requirement; it is a method for assigning the asset half of the PAIN score
systematically. The remediation-deadline numbers it ultimately selects are
fixed by FedRAMP (VDR-TFR-PVR); nothing here calibrates them.

## The six axes

| Tag | Axis | Allowed values | Derives |
|-----|------|----------------|---------|
| `data_sensitivity`    | privacy / confidentiality       | `public`, `internal`, `pii`, `cui` | **CR** + reconciles with the FIPS-199 confidentiality category |
| `mission_criticality` | integrity + availability        | `low`, `moderate`, `high`          | **IR** and **AR** |
| `internet_reachable`  | reachability                    | `true`, `false`                    | **IRV** (VER-EVA-EIR) |
| `agency_scope`        | blast radius                    | `single`, `multi`                  | **m** (the scope term in PAIN) |
| `owner`               | accountability                  | governed role label                | operational; routing of remediation |
| `archetype`           | role lens (optional, auditable) | see catalog below                  | the chain-of-thought label only; never scored directly |

### Allowed-value notes

- **`data_sensitivity`.** This system holds **no PII and no CUI** — every value
  in use today is `public` (public web content, software packages, public DNS,
  the private site bucket, low-sensitivity operational logs) or `internal`
  (credentials, IAM authorization material, the audit trail, the identity
  provider — the moderate-confidentiality assets). The `pii` and `cui` values
  exist so the standard generalizes to a real estate; using them here would be
  dishonest. `data_sensitivity` is **derived** from the component's FIPS-199
  confidentiality category in the canonical inventory (`not-applicable/low →
  public`, `moderate → internal`, `high → cui`), so the two cannot drift.
- **`mission_criticality`** is the high-water mark of the integrity and
  availability requirements. Deriving **both** IR and AR from one knob is
  deliberately conservative: it never *under*-states availability. This system's
  high-water mark is `moderate` (driven by integrity — defacement is the worst
  realistic outcome); availability is genuinely low everywhere (a personal site
  tolerates downtime within its declared RTO), so no asset is `high`.
- **`agency_scope`** is **hardwired `single`** for every resource. This is a
  single-operator proof of concept with **no federal data and no agency
  sponsor**, so the multi-agency blast-radius term `m` is always 0. The `multi`
  value and the scope machinery exist in the method for a real multi-tenant
  estate; this system has no subject for them. This is an honest-gap stance, not
  a limitation to be engineered around.
- **`owner`** is a governed **role** label (e.g. `platform-operator`), never a
  personal identifier. One operator owns everything today; the role label keeps
  the record accurate and public-safe if that ever changes.

## Archetype catalog (role lens)

The archetype is the auditable label for *why* a resource carries the
criticality it does. It is classified by role/usage, not by intrinsic kind — the
control-plane lens first (anything that holds credentials, actuates config, or
secures the estate is classified by that function), then by the data it holds.
Only the archetypes this estate actually contains are listed; the full memo
catalog is deliberately not imported.

| Archetype | Lens | Members here |
|-----------|------|--------------|
| `public-edge`         | data    | CloudFront, the public API Gateway, public HTML, public DNS, ACM |
| `app-tier`            | data    | the Silk Reeling app Lambda, its software dependencies |
| `identity-secrets`    | control | Cognito user pool, Secrets Manager, KMS keys, IAM roles/policies |
| `security-tooling`    | control | the internal compliance Lambda, audit/log stores |
| `internal-tooling`    | data    | private object storage, the EventBridge schedule, read-only external services |
| `platform-foundation` | control | DNS, TLS certificates (reachability/foundation, metadata only) |

## Source of truth and enforcement

The **live AWS resource tag is authoritative.** The canonical inventory
(`scripts/build-ksi-signal.py`) projects each resource's classification onto its
component (`attributes.classification`), so every derived risk input traces back
to the tag. A future build-time gate (PR-D) applies these keys as real AWS
resource tags on every taggable resource, fails the build if any required key is
missing, and reconciles the live tags against this projected classification so a
tag cannot drift from reality — the same fail-closed pattern the reconciliation
gate already uses for live-resource completeness.

### Fail-safe

Missing or unknown classification **must not** lower risk. An untagged or
unknown-type resource resolves to the conservative default
(`data_sensitivity: cui`, `mission_criticality: high`, `internet_reachable:
true`, `agency_scope: single`) so it scores loudly and surfaces itself for
classification rather than hiding. Silence never makes a resource look safer
than it is.

## Review cadence

Annually with the security review, and after any Transformative change that adds
a resource type or changes a resource's reachability, data sensitivity, or
criticality.
