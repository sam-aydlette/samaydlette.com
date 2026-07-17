# KSI Signal Reference

This document describes the **KSI signal** this repository emits. It is a developer-facing reference: schema, component vocabulary, join semantics, provenance, verification, and the normalization decisions that make the signal compose across CSPs and across systems within a portfolio.

The emitter is [`scripts/build-ksi-signal.py`](../scripts/build-ksi-signal.py). The runtime emitter is [`infrastructure/lambda/index.js`](../infrastructure/lambda/index.js). The schema is at [`infrastructure/schemas/ksi-signal.schema.json`](../infrastructure/schemas/ksi-signal.schema.json) and republished at `https://samaydlette.com/.well-known/ksi-signal.schema.json`.

## What this is

The KSI signal is a validation report informed by a **canonical inventory** of this system's components. Two distinct layers, bundled into one document for self-containment:

- The signal's `components[]` field is a snapshot of the canonical inventory. Every component named in canonical form: PURL for software ecosystems, native cloud ID paired with a normalized type for cloud resources, content hash for static artifacts, HBOM reference for hardware. The naming convention is what makes the inventory canonical — two systems naming the same thing produce bit-identical identifiers.
- The signal's `validations[]` field is the validation report. Each result carries a `component_refs[]` array naming the inventory components it evaluated. Validations stay attached to the components they evaluated, by reference.

The distinction matters. The canonical inventory is the architectural layer; the KSI signal is one of many reports that could ride on top of it. SBOMs, vulnerability scans, license reports, configuration drift reports — anything that names components — could reference the same inventory using the same identifiers. What composes across systems is whatever is built on the canonical inventory layer, not just this specific report. The value of the layer is that the join works for *any* report referencing it.

A validation report that says only "system X passed check Y" composes across systems poorly: two CSPs reporting the same check tell you nothing about whether they evaluated the same components, and two consumers reconciling inventory across a portfolio have no shared identifiers to join on. The KSI signal closes that gap by referencing components from a canonical inventory. A consumer aggregating signals across CSPs answers portfolio-level questions ("which of my systems contain a particular library", "which of my object stores have a public-access-block failure") with a join, not a reconciliation project.

The shape is intended to be CSP-agnostic. This repository implements one CSP (AWS); the same shape carries to others.

## Top-level structure

```json
{
  "$schema": "https://samaydlette.com/.well-known/ksi-signal.schema.json",
  "signal_version": "1.0.0",
  "signal_id": "<uuid>",
  "emitted_at": "<RFC 3339>",
  "emitter": "deploy" | "runtime",
  "csp": "aws",
  "system_id": "urn:samaydlette:website-prod",
  "provenance": { ... },
  "components": [ ... ],
  "validations": [ ... ]
}
```

| Field | Purpose |
|------|---------|
| `signal_version` | Semantic version of the signal contract. Breaking changes increment major. |
| `signal_id` | Unique per emission. Two signals with the same `signal_id` are the same observation. |
| `emitted_at` | RFC 3339 timestamp. |
| `emitter` | `deploy` (CI emitter, signed) or `runtime` (Lambda re-validator, currently unsigned). |
| `csp` | Free-form. Recommended values: `aws`, `azure`, `gcp`, `oracle`, `ibm`, `alibaba`. |
| `system_id` | Stable identifier for the system this signal describes. URN form recommended. |
| `provenance` | Builder, source, attestation. |
| `components` | Every component this emitter is aware of, with global identifiers. |
| `validations` | Validation results, each naming the components it evaluated. |

## Component vocabulary

A component has a normalized `type` drawn from a small enum, an optional `native_id` (CSP's own identifier), and a `global_id` block carrying one or more cross-CSP identifiers.

| `type` | Meaning | `native_id` | `global_id` keys |
|--------|---------|-------------|------------------|
| `object_store` | S3 bucket, Azure Blob container, GCS bucket | ARN / resource ID | — |
| `cdn_distribution` | CloudFront distribution, Azure Front Door, Cloud CDN | ARN / resource ID | — |
| `function` | Lambda, Azure Functions, Cloud Functions | ARN / resource ID | — |
| `compute_instance` | EC2 instance, Azure VM, Compute Engine VM | ARN / resource ID | — |
| `container_image` | OCI container image | (registry path) | `image_digest` (`sha256:<hex>`) |
| `npm_package` | Software dependency | — | `purl` (`pkg:npm/<name>@<version>`) |
| `html_artifact` | Static HTML file (or any content-addressable static blob) | — | `sha256` (hex) |
| `hbom_ref` | Hardware component referenced from a CycloneDX HBOM | — | `hbom_ref` (`<bom-ref>@<bom-uri>`) |

A component must carry at least one of `native_id` or `global_id`. Both are allowed where both are meaningful (e.g., a container image with both registry path and digest).

Free-form `attributes` are permitted and consumers should treat unknown keys as opaque. Common keys: `name`, `region`, `tls_min_version`, `encryption_algorithm`, `public_access_blocked`, `runtime`, `path`, `size_bytes`, `integrity`.

## Validation join semantics

```json
{
  "validation_id": "v-0001",
  "policy": { "id": "terraform.compliance", "version": "1.0" },
  "result": "pass" | "fail",
  "component_refs": ["aws::object_store::website", "..."],
  "violations": [
    { "type": "...", "message": "...", "severity": "LOW|MEDIUM|HIGH|CRITICAL", "resource": "..." }
  ]
}
```

`component_refs` names `component_id` values from this signal's `components[]` array (which is the canonical-inventory snapshot). This is the field that makes the signal compose: validations stay attached to the inventory components they evaluated, by reference. A portfolio consumer joining a set of signals on `component_refs` can answer:

- Which validations covered component `X`? (filter `validations[]` where `component_refs` contains `X`'s id.)
- Which components were covered by validation policy `P`? (filter `validations[]` where `policy.id == P`, then collect `component_refs`.)
- Which systems in the portfolio have a particular component? (filter signals where `components[]` contains a matching `purl` / `image_digest` / `native_id` / `sha256`.)
- Which validation failures are open against component `X` across the portfolio? (join on `X`, filter by `result: fail`.)

These queries are the actual job of an Authorizing Official, an SRE handling a CVE drop, or a portfolio risk function. The schema does not require any particular query layer; it requires only that signals conform.

## Provenance and signing

```json
"provenance": {
  "builder": {
    "id": "https://github.com/sam-aydlette/samaydlette.com/.github/workflows/deploy-with-opa.yml",
    "run_id": "<github actions run id>",
    "version": "github-actions"
  },
  "source": {
    "repository": "https://github.com/sam-aydlette/samaydlette.com",
    "commit": "<git sha>",
    "ref": "refs/heads/main"
  },
  "attestation": {
    "format": "sigstore-bundle",
    "url": "https://samaydlette.com/.well-known/ksi-signal.bundle",
    "verification": {
      "tool": "cosign",
      "certificate_identity_regexp": "https://github.com/sam-aydlette/samaydlette.com/.github/workflows/.+",
      "certificate_oidc_issuer": "https://token.actions.githubusercontent.com"
    }
  }
}
```

The deploy-time signal is signed via Sigstore keyless using the GitHub Actions OIDC identity. No signing key is held anywhere. The signing certificate, signature, and Rekor inclusion proof are bundled and published as a sidecar at `/.well-known/ksi-signal.bundle`.

The `provenance.attestation` block is populated by the emitter *before* signing, so the cosign signature covers it. A consumer reads the URL and verification parameters from inside the signed signal and uses them to fetch and verify the bundle.

The runtime signal (Lambda emitter) is currently not signed; it is implicitly trusted via S3 + IAM. See "Limitations" below.

## Verification

```bash
curl -O https://samaydlette.com/.well-known/ksi-signal.json
curl -O https://samaydlette.com/.well-known/ksi-signal.bundle

cosign verify-blob \
  --bundle ksi-signal.bundle \
  --certificate-identity-regexp 'https://github.com/sam-aydlette/samaydlette.com/.github/workflows/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ksi-signal.json
```

This checks three things:

1. The signature is valid for the signal's bytes.
2. The signing certificate was issued by Fulcio to the named GitHub Actions identity.
3. The signature appears in the public Rekor transparency log.

None of these checks depend on a privately-held key or trust root. The certificate authority is public, the identity is public, and the log is append-only and globally readable.

The signal can also be schema-validated independently:

```bash
curl -O https://samaydlette.com/.well-known/ksi-signal.json
curl -O https://samaydlette.com/.well-known/ksi-signal.schema.json
python3 -c "import json, jsonschema; jsonschema.validate(json.load(open('ksi-signal.json')), json.load(open('ksi-signal.schema.json'))); print('valid')"
```

## OSCAL Rev 5 SSP

Alongside the KSI signal, every deploy emits a NIST OSCAL System Security Plan in the FedRAMP Rev 5 Moderate baseline shape, published at `/.well-known/oscal-ssp.json`. The two artifacts are two views of the same underlying state:

- The **KSI signal** is the wire format. It carries the canonical inventory and the validation report, in the shape FedRAMP 20x intends. It is the artifact that composes across CSPs.
- The **OSCAL SSP** is the human-and-tool-friendly compliance artifact. It re-expresses the same state in NIST 800-53 Rev 5 control vocabulary, suitable for ingestion by GRC tooling, FedRAMP assessors, or any consumer that already speaks OSCAL.

Generation is deterministic. The generator [`scripts/build-oscal-ssp.py`](../scripts/build-oscal-ssp.py) reads two inputs:

1. The live KSI signal (`infrastructure/ksi-signal.json` post-build) — provides component definitions and the canonical-inventory snapshot.
2. The FedRAMP KSI catalog (`infrastructure/schemas/ksi-catalog.json`, sourced from FRMR.KSI) — provides the KSI → NIST 800-53 control mapping.

For every in-scope KSI, the generator iterates the controls listed in the catalog and emits one OSCAL `implemented-requirement` per unique control. Each requirement carries:

- `props.implementation-status` — `implemented` | `partial` | `not-applicable`. Differentiated per control rather than mass-assigned. The status is resolved from a per-control override (for ~30 load-bearing controls the system actively implements) or from a family-level fallback (for the rest), and is downgraded to `partial` automatically if a contributing KSI shows failing validations in the live signal.
- `props.control-origination` — `sp-system` | `sp-corporate` | `shared` | `inherited` | `not-applicable`, with the FedRAMP namespace `https://fedramp.gov/ns/oscal`. Distinguishes controls implemented in this system's code (`sp-system`), at the operator/organization level (`sp-corporate`, e.g., training, IR planning), shared with AWS (`shared`, e.g., TLS configuration), or fully inherited from AWS (`inherited`, e.g., physical security, hardware maintenance).
- `statements[].remarks` — actual implementation prose describing how the control is met, with a footer naming the contributing KSIs so a reader can trace back to the catalog. Statements are either explicit per-control overrides (~30 controls) or family-level fall-throughs that name how the family is addressed at the operator/inherited level. No mass-assigned "implemented via KSI-X" default — every control gets specific prose.
- `links` — to the live KSI signal (as `evidence`), the Sigstore bundle (as `evidence`), the runtime KSI signal (as `evidence`), and the documentation file recording the implementation rationale (as `reference`).

The status distribution on the current SSP is roughly half-implemented, one-third partial, and one-sixth not-applicable, reflecting the honest reality that most controls in a one-CSP, one-operator, no-customer-data system are either inherited, partial-by-virtue-of-being-self-attested, or N/A by virtue of system simplicity.

The SSP is not currently signed independently; it references the signed KSI signal as evidence. Closing that loop in a later iteration would sign the SSP with the same Sigstore chain, producing two signed artifacts that both reduce to the same source-of-truth.

```bash
# Fetch and inspect the SSP at any time:
curl -s https://samaydlette.com/.well-known/oscal-ssp.json | jq '{
  uuid: ."system-security-plan".uuid,
  oscal_version: ."system-security-plan".metadata."oscal-version",
  controls: (."system-security-plan"."control-implementation"."implemented-requirements" | length),
  components: (."system-security-plan"."system-implementation".components | length),
  ksi_signal_id: ."system-security-plan".metadata.props[0].value
}'
```

The `ksi_signal_id` returned is the `signal_id` of the KSI signal the SSP was generated from. Two consumers comparing the SSP and the signal can confirm they match by that field; mismatch means one was published without the other being regenerated, which the CI pipeline does not allow under normal operation.

## Cross-CSP composition: the normalization decisions

The canonical inventory composes across CSPs because the schema makes a small number of explicit normalization decisions. The signal composes because it embeds the inventory. These decisions are worth naming so a consumer can judge whether they hold up under contact with a second CSP.

**1. Software components are identified by Package URL.** PURL is global by construction. A consumer querying `pkg:npm/left-pad@1.3.0` across all signals gets exactly the systems that include it, regardless of CSP.

**2. Container images are identified by OCI digest.** `sha256:<hex>` serves the same role as PURL: a global, content-addressable identifier that does not depend on which registry hosts the image.

**3. Cloud resources are identified by normalized type plus native ID.** Cloud resources have no global identifier today. The schema does not invent a synthetic cross-CSP ID — that requires either a registry (operationally expensive) or a hashing scheme (loses the round-trip to the CSP's own tooling). Instead, each CSP's native shape projects into a small normalized `type` vocabulary (`object_store`, `cdn_distribution`, `function`, `compute_instance`) and the native ID stays alongside. The type is the join key for portfolio reasoning; the native ID stays specific because anyone querying the CSP's API needs it.

**4. Static artifacts are identified by SHA-256.** No PURL ecosystem exists for arbitrary static content. The bytes' hash is a perfectly good global identifier.

**5. Hardware components are identified by HBOM reference.** Per [CycloneDX HBOM](https://cyclonedx.org/capabilities/hbom/) and [CISA's 2023 HBOM Framework](https://www.cisa.gov/resources-tools/resources/hardware-bill-materials-hbom-framework-supply-chain-risk-management). The slot is reserved in the schema; this repository's static-site infrastructure does not exercise it.

**What is deliberately not normalized:** regions, account / subscription identifiers, tag schemas, IAM principal naming, and policy semantics. These vary across CSPs in ways that have no clean projection. They live in `attributes`, free-form, opaque to the schema. Policy alignment in particular is a different problem than the inventory problem and is not solved here. The `policy.id` and `policy.version` fields make the question askable; answering it is the job of the policy authors.

## Limitations

- **One CSP.** This repository implements AWS only. The schema's normalization decisions are designed to extend to others; this implementation does not definitively prove that they will, but it does provide a viable starting point.
- **Runtime signal not signed.** The deploy-time signal is signed via Sigstore. The runtime signal is trusted implicitly through S3 + IAM. Closing this loop in a portfolio context would use either a KMS-backed asymmetric key or a federated OIDC identity to the runtime emitter.
- **Daily runtime cadence.** EventBridge supports rates as fast as one minute. The current cadence is a cost decision, not a technical limit.
- **Hardware (HBOM) coverage is unexercised.** The schema slot exists; this site has no hardware to inventory.
- **Policy alignment across CSPs.** Two CSPs reporting `encryption_disabled` may mean slightly different things. The `policy.id` / `policy.version` fields make this question traceable but do not solve it.

## Related files

| File | Purpose |
|------|---------|
| [`infrastructure/schemas/ksi-signal.schema.json`](../infrastructure/schemas/ksi-signal.schema.json) | The KSI signal schema. Self-publishes at `/.well-known/`. |
| [`infrastructure/schemas/ksi-catalog.json`](../infrastructure/schemas/ksi-catalog.json) | FedRAMP KSI catalog (FRMR.KSI source). Drives the KSI→NIST control mapping in the OSCAL generator. |
| [`scripts/build-ksi-signal.py`](../scripts/build-ksi-signal.py) | Deploy-time KSI emitter. |
| [`scripts/build-oscal-ssp.py`](../scripts/build-oscal-ssp.py) | OSCAL Rev 5 SSP generator. Runs after the KSI emitter; consumes the live signal + the catalog. |
| [`scripts/terraform-plan.sh`](../scripts/terraform-plan.sh) | OPA gate; produces `validations.json` consumed by the emitter. |
| [`infrastructure/lambda/index.js`](../infrastructure/lambda/index.js) | Runtime KSI emitter. |
| [`infrastructure/policy/`](../infrastructure/policy/) | Source-of-truth policy packages for both enforcement points: the deploy gate evaluates them with the OPA CLI; CI compiles the same source to Wasm (`opa build -t wasm`) and the runtime emitter executes it via `@open-policy-agent/opa-wasm`. There is no JavaScript port of the rules; a CI parity test (`scripts/policy-parity-test.js`) proves the two evaluators agree on the full fixture corpus. |
| [`.github/workflows/deploy-with-opa.yml`](../.github/workflows/deploy-with-opa.yml) | CI pipeline: gate → apply → build signal → cosign sign → build SSP → publish. |
