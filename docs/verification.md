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
  --bundle oscal-ssp.json.intoto.jsonl \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" oscal-ssp.json
```

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
