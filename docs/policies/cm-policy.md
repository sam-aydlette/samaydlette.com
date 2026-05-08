# CM — Configuration Management

Configuration management is GitOps. Every change to infrastructure or content reaches `main` through a pull request that triggers the OPA gate, the Terraform plan, the apply, the canonical inventory build, the Sigstore signing, and the publish. The PR is the change request, the review (when applicable), the approval, and the audit record. Branch protection on `main` is enforced.

Each change carries a **Significant Change Notification (SCN) category** tag — Adaptive, Routine Recurring, or Transformative — per the criteria in `SCN-CSO-EVA`. The tag lives in the PR description for PR-mediated changes and in the commit message for direct pushes to `main`. The default if unspecified is Routine Recurring; the operator is required to upgrade the categorization explicitly when the change meets Adaptive or Transformative criteria. The CI workflow validates the tag on every PR and every push to `main` — it fails the build only on a malformed value (a recognized `SCN-Type:` line with a value that isn't one of the three). Missing tags are treated as Routine Recurring per the default. Audit records of these evaluations are the git history (`SCN-CSO-MAR`).

The canonical inventory at `/.well-known/ksi-signal.json` is the authoritative system inventory (CM-8 family). It is generated automatically from Terraform state, Lambda package locks, and content hashes — see [`docs/ksi-signal.md`](../ksi-signal.md). Each component carries a normalized identifier (PURL/ARN/SHA-256/HBOM ref), a security category (per FIPS 199), and an information-flow tag (per `MAS-CSO-FLO`).

**20x rule integration.** Significant Change Notifications (full SCN-* family — `SCN-CSO-MAR`/`INF`/`HIS`/`HRM`/`ARI`/`NOM`/`EMG`/`EVA` plus the Adaptive/Routine-Recurring/Transformative tier rules; transformative timeframes are 30/10/5 business days per `SCN-TRF-NIP`/`NFP`/`NAF`). Minimum Assessment Scope (`MAS-CSO-IIR`/`FLO`/`TPR`/`MDI` — third-party AWS resources documented per `MAS-CSO-TPR`). KSI-CMT (Change Management).

**Review cadence.** Continuous; effectiveness review monthly via the no-out-of-band-commits check on `main`.
