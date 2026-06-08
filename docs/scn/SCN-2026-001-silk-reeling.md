# SCN-2026-001 — Significant Change Notification & Security Impact Analysis
## "Silk Reeling Mirror" gated application

| | |
| --- | --- |
| **SCN ID** | SCN-2026-001 |
| **System** | samaydlette.com (FedRAMP 20x KSI Certification + OSCAL Rev 5 Moderate SSP) |
| **SCN type** | **Adaptive** (`SCN-ADP`) |
| **Status** | Implemented — **live in production** since 2026-06-03 (PR #82); latest redeploy 2026-06-06. The `create_silk_reeling` Terraform variable defaults to `false`, but the production deploy pipeline sets it `true`, so the app is active (`/silk-reeling/` serves the Basic Auth gate). |
| **Date initiated** | 2026-06-07 |
| **Approver** | Sam Aydlette — System Owner / Authorizing Operator |
| **Authoritative source** | CR26 corpus (`consolidated_rules_2026/2026-markdown`) |

This document is the human-readable SCN record (`SCN-CSO-INF`) and the copy of the
security impact analysis (`SCN-CSO-INF` item 9). Its machine-readable counterpart is
the row for `SCN-2026-001` in [`scn-register.csv`](scn-register.csv) (`SCN-CSO-HRM`).
The git history of this change is the SCN audit record (`SCN-CSO-MAR`).

**Retroactive categorization note.** The Silk Reeling app was introduced into the repo
over an earlier series of commits that were not individually tagged `SCN-Type: adaptive`.
Git history is immutable and `main` is published, so those commits are not rewritten;
this SCN record is the authoritative, durable categorization of the change as **Adaptive**,
and the commit that lands this record carries the `SCN-Type: adaptive` tag. The app was
deployed to production on 2026-06-03 (PR #82) and iteratively redeployed (latest
2026-06-06) before this formal record was created. That ordering is consistent with an
Adaptive change, which requires **no advance notice** — notification is due within 10
business days *after* finishing (`SCN-ADP-NTF`); this record and the push that publishes
it fall well within that window (~3 business days after go-live). Going forward, the SCN
register is established so future categorized changes are recorded at the time of change.

---

## 1. Categorization (SCN-CSO-EVA)

Running the SCN-CSO-EVA decision tree:

| Gate | Determination |
| --- | --- |
| Significant change? | **Yes** — net-new service component, new public ingress, new external egress. Not day-to-day care/feeding. |
| FedRAMP Certification *class* change (impact-level change)? | **No** — boundary impact level is unchanged; **no federal customer data** is introduced or re-categorized. No new assessment required. |
| Routine recurring? | **No** — not regular, automated maintenance. |
| Transformative? | **No** — but it brushes two transformative tests (see below). |
| **Result** | **Adaptive** (`SCN-ADP`). |

**Why this is the upper edge of Adaptive, not the middle.** Two `SCN-TRF-TPR`
transformative examples are in play: *"addition of a critical third-party service that
handles a significant portion of information"* (the new Anthropic interconnection,
POAM-020) and *"adding a new AI-based capability that impacts federal customer data in
a different way"* (a new AI capability). **Both transformative examples are gated on
federal customer data, of which this system has none.** That single fact keeps the
change Adaptive. **Two things would flip it to Transformative:** (a) onboarding any
agency / federal data while the external Anthropic interconnection is live, or (b) the
change materially altering the customer-responsibility model. Both are recorded as
re-assessment triggers in the [PTA](../privacy-threshold-analysis.md).

---

## 2. Required information (SCN-CSO-INF)

1. **Service Offering FedRAMP ID:** `<FR-CERT-ID>`
2. **Assessor name:** N/A — sole-operator self-attestation; no 3PAO engaged (permissible for an Adaptive change).
3. **Related vulnerability:** None — this is a proactive feature addition, not a vulnerability response.
4. **SCN type & categorization:** Adaptive — see §1.
5. **Short description:** Adds the gated "Silk Reeling Mirror" app — a public, HTTP-Basic-Auth-gated API Gateway HTTP API → Python 3.13 ZIP Lambda serving a browser SPA; the Lambda calls the Anthropic API to generate movement-feedback text. Pose extraction runs client-side in the browser.
6. **Reason for change:** New self-service capability addition to the site.
7. **Summary of customer impact:** New customer/operator-responsibility control — the **operator-set HTTP Basic Auth credential** (POAM-021). SAML federation to an IdP is the recommended stronger control (not implemented; no IdP). No change to existing customers' configuration responsibilities.
8. **Plan & timeline (incl. verification of impacted KSIs/controls):** see §4.
9. **Copy of the business/security impact analysis:** §3–§5 of this document.
10. **Name & title of approver:** Sam Aydlette — System Owner / Authorizing Operator.

Per **SCN-ADP-NTF**, all necessary parties are notified within 10 business days after
finishing the change. **This system has no agency sponsor and no customers, so there are
no necessary parties to notify** — the notification requirement is satisfied ceremonially
by the public GitHub push that publishes this record and the updated certification data
(KSI signal / OSCAL SSP / VDR report) at `/.well-known/` (`SCN-CSO-NOM`). There is no
separate notification action; the push *is* the notification.

---

## 3. Architecture change — delta to the authorization boundary

The change moves the system from a *static-site + internal-monitoring* posture to one
with a *public authenticated API, an external AI interconnection, and a client-side ML
bundle*. New components (from `infrastructure/silk-reeling.tf`):

| New component | Type | Boundary effect |
| --- | --- | --- |
| `aws_lambda_function.silk_reeling` | Python 3.13 **ZIP** Lambda (numpy + anthropic SDK; ML runs in browser) | New compute; **egresses to the public internet** (Anthropic) — unlike the existing daily KSI Lambda. |
| `aws_apigatewayv2_api` (HTTP API, `$default`, **no authorizer**) | New **public ingress** | New internet-facing attack surface; replaces a blocked Function URL. |
| In-Lambda **HTTP Basic Auth** (constant-time compare) | New auth mechanism | Single-factor shared-credential gate. |
| `aws_kms_key` (CMK, rotation on) + 2 Secrets Manager secrets | New crypto + secret material | No automatic rotation (POAM-019). |
| **Anthropic API interconnection** | New **external, non-FedRAMP-authorized** dependency | Headline change — derived metrics cross the boundary. |
| CloudWatch log group (7-day retention); CloudFront `/silk-reeling/*` behavior | Logging / CDN | API GW access logging deferred (POAM-024). |
| Browser SPA (client-side pose extraction) | Static artifact + **its own JS dependency set** | New client-side dependency surface. |

This is not a container deployment: the Lambda is a ZIP package (`runtime =
python3.13`, `filename`/`source_code_hash`), so there is **no container image** in the
inventory and no container-image scan is applicable.

---

## 4. Security impact analysis — control families touched

| Control(s) | Impact | Disposition |
| --- | --- | --- |
| **RA-5 / VDR-CSO-DET, VDR-BES** | New PyPI + client-JS dependency surface previously covered by no SCA source | **Remediated** — Syft SBOM + Grype SCA of the built `_pkg` (Python) and the frontend lockfile (JS), feeding `build-vdr-report.py` via `--grype`. Runs on every deploy **and on a daily schedule** (`cron` in the deploy workflow), so CVEs newly disclosed against unchanged, already-deployed dependencies are caught within ~1 day against a fresh Grype DB — continuous detection, not point-in-time. Grype findings are marked internet-reachable (the app Lambda is public via API Gateway), pulling them onto the tighter Class C SLAs. The scanned components are also added to the canonical inventory (CM-8). See [supply-chain.md](../supply-chain.md). |
| SA-9 / CA-3 | New external interconnection to non-authorized Anthropic; boundary-crossing data flow | POAM-020 (risk-accepted). Modeled in the OSCAL SSP `system-implementation` (interconnection component), `data-flow`, and `network-architecture`. |
| AC-3, IA-2, IA-2(2), AC-7 | Single-factor shared-credential Basic Auth; no MFA, no lockout | POAM-021, POAM-022 (risk-accepted). |
| SC-5, AC-7 | No brute-force / rate-limit / WAF on a public Basic Auth endpoint | POAM-023 (risk-accepted, operational requirement). |
| AU-2, AU-3, AU-12 | API Gateway access logging not enabled | POAM-024 (risk-accepted); Lambda + CloudFront logs give partial coverage. |
| SC-7 | New public ingress + new internet egress; boundary diagram updated | Documented in the SSP `network-architecture`. |
| SC-8, SC-13 / using-cryptographic-modules | TLS to Anthropic; FIPS-validated module posture | TLS 1.2+ enforced; covered by the crypto-module rule. |
| SC-12, SC-28 | New CMK + secrets; no automatic rotation | POAM-019 (risk-accepted; manual rotation). |
| CM-2, CM-3, CM-4, CM-6 | New baseline components; this SIA is the CM-4 analysis; secure-config baseline updated | SCG updated ([secure-configuration-guide.md](../policies/secure-configuration-guide.md)). |
| RA-3 | This SIA is the risk-assessment update | This document. |
| PL-2, PL-8 | SSP reflects the new boundary + components; generator now emits `data-flow` + `network-architecture` | Updated in `scripts/build-oscal-ssp.py`. |
| PT-* / Privacy | No PII crosses the boundary; PTA re-determined | [privacy-threshold-analysis.md](../privacy-threshold-analysis.md). |

### Verification plan (Adaptive requires post-implementation verification)

The app is live in production (`create_silk_reeling = true` in the main pipeline). The
following runs on each deploy and was confirmed against the current production
deployment to close the Adaptive post-implementation verification:

1. OPA gate + Checkov + tfsec pass (or every finding maps to a POA&M).
2. Syft/Grype SCA runs over the built Lambda+SPA artifact; the VDR aggregator emits an
   updated `vdr-report.json` with **no KEV-listed CVE unremediated** (`VDR-BES`: do not
   activate new resources with Known Exploited Vulnerabilities).
3. KSI signal and OSCAL SSP re-emit and reflect the new components.
4. Manual secure-configuration verification of the deployed resources (the Adaptive
   "verification of existing functionality and secure configuration after
   implementation" obligation).

### Verification result — COMPLETE (2026-06-08, prod commit `354da59`)

Post-implementation verification was performed against the published certification data
at `/.well-known/` and the live endpoint. **Outcome: pass.**

- **VDR gate:** `vdr-report.json` shows **KEV 0, blocking 0**. Grype SCA covers the
  deployed Python (23 PyPI components) and JS (npm) dependency sets — both inventoried in
  the KSI signal, currently **CVE-free**. Grype findings are marked internet-reachable
  (tighter Class C SLAs). (Steps 1–2.)
- **Inventory / SSP (CM-8, PL-2, SA-9):** the published KSI signal carries the app's
  dependency components (CM-8 complete); the OSCAL SSP renders `data-flow` and the
  `network-architecture` Anthropic/API-Gateway addendum, so the interconnection is
  actually modeled. (Step 3.)
- **Secure configuration / functionality:** the endpoint serves the access-control gate
  (`401 Basic realm="Silk Reeling Mirror"`); the documented resource baseline is in
  effect. (Step 4.)

Two defects found *by* this verification were remediated under `SCN-Type:
routine-recurring` (commit `354da59`) before this result was recorded: a hyphen/underscore
mismatch that had suppressed the SSP `data-flow`/`network-architecture` rendering, and a
Syft over-scan that had flooded the VDR with out-of-boundary build-tool (esbuild Go
binary) findings. Both are confirmed fixed in the prod state above. This closes the
Adaptive post-implementation verification obligation for SCN-2026-001.

---

## 5. New risks / vulnerabilities summary (SCN-ADP-NTF)

- **POAM-019 (SC-12/SC-28):** Secrets Manager auto-rotation not enabled — manual rotation; risk-accepted, Low.
- **POAM-020 (SA-9/CA-3):** External interconnection to the non-FedRAMP-authorized Anthropic API — derived non-PII metrics only, over TLS; risk-accepted as an **open operational requirement** (Bedrock in-boundary remediation considered and deliberately deferred by the operator).
- **POAM-021 (IA-2(2)/AC-7):** Single-factor shared-credential Basic Auth — risk-accepted, Low.
- **POAM-022 (IA-2/AC-3):** API Gateway route has no authorizer (app-layer Basic Auth is the gate) — risk-accepted, Low.
- **POAM-023 (AC-7/SC-5):** No brute-force / rate-limit protection on the Basic Auth endpoint — risk-accepted, Low.
- **POAM-024 (AU-2/AU-3):** API Gateway access logging not enabled — risk-accepted, Low.
- **New-ecosystem SCA blind spot (RA-5/VDR-CSO-DET):** the new Python + client-JS dependency set had no detection source. **Remediated** by adding Syft/Grype SCA over the built artifact, feeding the VDR aggregator — run on every deploy **and on a daily schedule** (continuous detection against a fresh Grype DB), with findings marked internet-reachable and the scanned components added to the canonical inventory (CM-8). A complementary recommendation — enable Dependabot `pip`/`npm` in the `silk-reeling-mirror` source repo, where the manifests live — remains tracked in [supply-chain.md](../supply-chain.md).

No new KEV-listed or N4+/likely-exploitable vulnerabilities are known at the time of
this analysis; the activation gate (§4 step 2) enforces this at deploy time.
