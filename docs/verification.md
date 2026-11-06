# Verify the published evidence yourself

Everything this system claims is published under
[`/.well-known/`](https://samaydlette.com/.well-known/) and **signed by the exact
GitHub Actions workflow that produced it.** You do not have to trust this repo's
word for any of it — you can reproduce the verification from the public internet,
with no credentials and no AWS access.

That reproducibility is the whole point. Continuous authorization only becomes
*reciprocity* when a second party can take the provider's evidence and reach the
same verdict independently. This is that handshake.

## One command

From a clone of this public repo:

```
scripts/verify-published.sh                 # verify the live site
make verify-published                       # same, via make
scripts/verify-published.sh https://host/.well-known   # any other base
```

It fetches the live artifacts and runs three layers of checks, then prints
`PASS` / `FAIL`.

## What each layer proves — and how independent it is

**1. Signatures + provenance — fully independent.** `cosign` confirms each
artifact was produced by this repo's *pinned* workflow identity, recorded in the
public Sigstore/Rekor transparency log. The trust roots are Sigstore and a
public identity string — not this repo, and not the verifier script. You can run
these two commands with nothing but `cosign` installed:

```
IDENTITY='https://github.com/sam-aydlette/samaydlette.com/.github/workflows/deploy-with-opa.yml@refs/heads/main'
ISSUER='https://token.actions.githubusercontent.com'

# the canonical inventory (Sigstore bundle)
cosign verify-blob --bundle ksi-signal.bundle \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" ksi-signal.json

# a derived artifact (inline-DSSE in-toto attestation)
cosign verify-blob-attestation --new-bundle-format --type slsaprovenance1 \
  --bundle security-decision-record.json.intoto.jsonl \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" security-decision-record.json
```

**Bundle format.** Every `.bundle` is a standard Sigstore bundle
(`application/vnd.dev.sigstore.bundle.v0.3+json`), not cosign's older
`base64Signature`/`cert`/`rekorBundle` layout, so any Sigstore verifier can
check it, not only cosign. cosign 2.4 or newer reads it with the command above;
older releases cannot. With sigstore-python instead:

```
python -m pip install sigstore
sigstore verify identity --bundle ksi-signal.bundle \
  --cert-identity "$IDENTITY" --cert-oidc-issuer "$ISSUER" ksi-signal.json
```

**More than one publisher identity, and why.** Each file is signed by the
workflow that wrote it last, so a verifier accepts exactly the workflows that
write that file. The deploy workflow writes everything it builds. It cannot run
unattended (it applies Terraform and is deliberately bound to a reviewed
environment), so three unattended workflows rewrite a few files between deploys
and sign them with their own identities:

| Files | Also written and signed by |
|---|---|
| `vdr-*` (the VDR, its attestation, trend ledger and CR26 vulnerability reports) | `evidence-nightly.yml`, twice a day, to stay inside the 24-hour freshness policy |
| `security-decision-record*`, `certification-package-overview*`, `ongoing-certification-report*` | `package-maintenance.yml`, daily, to keep the package inside its two-week window |
| `ocr-issue*`, `snapshot-*`, `quarterly-reviews*`, `quarterly-review-*` (the quarterly issue index, issued reports, snapshot indexes, Quarterly Reviews) | `package-maintenance.yml` only |
| `incident-*` (the incident log, delivery log and reports) | `incident-reports.yml`, twice a day and whenever the incident register changes |
| `simulated-assessment.*` | `simulated-assessor.yml` only (the deploy relays it unchanged) |

```
NIGHTLY='https://github.com/sam-aydlette/samaydlette.com/.github/workflows/evidence-nightly.yml@refs/heads/main'
MAINTENANCE='https://github.com/sam-aydlette/samaydlette.com/.github/workflows/package-maintenance.yml@refs/heads/main'
INCIDENT='https://github.com/sam-aydlette/samaydlette.com/.github/workflows/incident-reports.yml@refs/heads/main'
ASSESSOR='https://github.com/sam-aydlette/samaydlette.com/.github/workflows/simulated-assessor.yml@refs/heads/main'
```

Verifying one of those files means accepting **either** the deploy identity or
the one in its row, which is what `scripts/verify-published.sh` does (its
`signers_for` function). The table is `scripts/_signers.py`; a test derives each
file's writers from the workflows' publish steps and fails when the table, the
assessor guide, the trust manifest, the script or this page disagrees. All of
these are pinned workflows in this public repository running on `main`, so the
claim being made is unchanged: the evidence came from this repo's CI, not from
someone holding a key. Prefer the exact identities above to a regular
expression over every workflow in the repository, which would also accept a
file signed by a workflow that never writes it.

**2. Provenance claims — dependency-free.** `scripts/verify-attestation.py` reads
the in-toto predicate (no cosign, no third-party libraries) and checks it binds
each artifact's sha256 to the canonical inventory (`signal_id` + hash), the
generator, and a commit.

**3. Cross-artifact consistency — AWS-free.** `scripts/reconcile.py` (without
`--live`) checks the published set is internally coherent: every artifact carries
the same inventory `signal_id` and commit, the POA&M matches, and every VDR
finding resolves to a remediation item (invariants **b–h**).

## Honest scope

The two **live-state** reconciliation invariants — **(a)** live-resource
completeness and **(i)** live-tag ↔ inventory equality — require AWS credentials
and **cannot** be reproduced by an external party. Those are the provider's to
run in CI, and they are, on every deploy. This verifier says so rather than
implying an outsider can check them. Everything else here, a stranger can.

## Two signature formats (Task 15 note)

The canonical inventory is signed with the legacy `cosign sign-blob` **Sigstore
bundle** (`ksi-signal.bundle`); the derived OSCAL/VDR artifacts use the newer
`cosign attest-blob --new-bundle-format` **inline-DSSE in-toto attestation**
(`*.intoto.jsonl`). Both are Sigstore-signed against the same pinned identity, so
both verify with `cosign`; the difference is that the DSSE form also carries a
machine-readable SLSA provenance predicate that a non-cosign consumer can act on
(layer 2 above). Converging the inventory onto the DSSE form is a tracked
follow-up; keeping the `.bundle` in the meantime costs nothing and stays
verifiable, so it is not urgent.
