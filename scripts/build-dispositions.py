#!/usr/bin/env python3
# =============================================================================
# BEYOND-MODERATE CONTROL DISPOSITIONS  (Phase 2 / residue reduction)
# =============================================================================
# Controls that GovRAMP, TX-RAMP, and CMMC require ABOVE the FedRAMP Moderate
# baseline surfaced as residue when each spoke was first projected. This file
# dispositions every one of them the disciplined way: does it apply (else N/A
# with rationale), is it implemented (with the real evidence named), or is it a
# documented partial/POA&M. The spoke projections read these alongside the
# Moderate hub, so residue shrinks to only what is honestly still open.
#
# Each statement points at evidence that already exists in this system
# (Sigstore bundles, the Syft SBOM, ACM, CloudWatch, AWS IAM/Shield, the GitHub
# repo, the ConMon/RA/SA policies). Output: data/dispositions/beyond-moderate.json
# =============================================================================

import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "data" / "dispositions" / "beyond-moderate.json"

# control-id (Rev 5) -> (status, origination, statement)
DISP = {
    # --- Not applicable: the system genuinely does not do the thing ---
    "ac-3.14": ("not-applicable", "sp-system",
        "No individual data subjects. The system has a single operator and holds no end-user personally identifiable information, so individual-access mechanisms do not apply."),
    "pe-8.3": ("not-applicable", "inherited",
        "Physical access is inherited from AWS; the system maintains no visitor access records of its own."),
    "si-12.1": ("not-applicable", "sp-system",
        "The system processes no personally identifiable information, so there are no PII elements to limit."),
    "si-12.2": ("not-applicable", "sp-system",
        "No PII is used in testing, training, or research; the system processes no PII at all."),
    "si-12.3": ("not-applicable", "sp-system",
        "No PII is stored, so there is no PII disposal obligation."),
    "sc-19": ("not-applicable", "sp-system",
        "No Voice over IP technologies are used anywhere in the system."),
    "si-4.14": ("not-applicable", "inherited",
        "No wireless networks. The system is cloud-hosted on AWS; wireless intrusion detection does not apply and is inherited where relevant."),
    "sc-7.27": ("not-applicable", "sp-system",
        "Standalone system with no external system interconnections to classify or manage."),
    "ia-12.4": ("not-applicable", "sp-system",
        "No end users to identity-proof. The sole operator's identity is managed through AWS IAM and the GitHub deploy identity."),
    "mp-6.2": ("not-applicable", "inherited",
        "No physical media. Media sanitization and its testing are inherited from AWS."),
    "pe-14.2": ("not-applicable", "inherited",
        "Physical environment monitoring is inherited from AWS data-center operations."),
    "ac-10": ("not-applicable", "sp-system",
        "Application authentication is HTTP Basic, which is sessionless, and there is a single operator account. There is no session state to limit."),

    # --- Implemented / inherited: already true, with the evidence named ---
    "ac-17.9": ("implemented", "inherited",
        "Administrative reach is AWS IAM and the GitHub deploy identity, both of which support immediate revocation. No long-lived access keys are used."),
    "sc-6": ("implemented", "inherited",
        "Resource availability is provided by AWS: Shield Standard on CloudFront absorbs volumetric denial of service, and Lambda runs under account concurrency limits."),
    "sc-7.13": ("implemented", "sp-system",
        "Security functions are isolated from application functions: the OPA gate, scanners, and Sigstore signing run in GitHub Actions CI, and the runtime KSI validator is a separate Lambda from the application Lambda."),
    "cp-9.3": ("implemented", "sp-system",
        "The canonical source of truth is the GitHub repository, administratively and geographically separate from the AWS deployment, and S3 versioning retains prior object states."),
    "sc-7.23": ("implemented", "inherited",
        "CloudFront returns standardized error responses and does not leak verbose protocol-validation feedback to senders."),
    "cm-14": ("implemented", "sp-system",
        "Published artifacts are Sigstore keyless-signed and the deploy verifies signatures, so only signed components are accepted (CM-5(3) / signed components)."),
    "sa-10.1": ("implemented", "sp-system",
        "Software and firmware integrity is verifiable: every published artifact carries a Sigstore bundle and a Syft SBOM, checkable with cosign."),
    "sc-12.2": ("implemented", "inherited",
        "Symmetric key management is AWS-managed: S3 server-side encryption uses AES-256 with AWS-managed keys; the system manages no symmetric keys of its own."),
    "sc-12.3": ("implemented", "inherited",
        "Asymmetric key management for TLS is handled by AWS Certificate Manager, which provisions and rotates the certificate keys."),
    "au-9.2": ("implemented", "inherited",
        "Audit records are written to CloudWatch Logs, a service separate from the application compute, providing off-box retention."),
    "cm-10.1": ("implemented", "sp-corporate",
        "Open-source components are inventoried by the Syft SBOM on every deploy and governed by the documented supply-chain policy."),
    "ca-2.2": ("implemented", "sp-corporate",
        "Specialized assessment is covered by the annual security review plus the per-deploy VDR aggregator, which classifies findings on the FedRAMP 20x PAIN scale."),
    "ir-7.2": ("implemented", "sp-corporate",
        "Incident-response coordination with AWS as the underlying provider is documented in the incident response plan."),
    "sa-4.8": ("implemented", "sp-corporate",
        "A continuous monitoring plan is maintained and published; it is the acquisition-time ConMon plan this enhancement asks for."),
    "sa-9.4": ("implemented", "sp-corporate",
        "Consistency of interests with the external provider (AWS) is addressed through the documented use of the AWS authorization package and operator policy."),
    "cp-2.2": ("implemented", "inherited",
        "Capacity is handled by serverless auto-scaling: Lambda and CloudFront scale with demand under AWS-managed capacity."),
    "sa-11.8": ("implemented", "sp-corporate",
        "Dynamic code analysis runs in CI as a scheduled monthly OWASP ZAP baseline scan (.github/workflows/zap-dast.yml) against the live site, with findings tracked via the ZAP issue and triaged into the POA&M. The scan covers the unauthenticated static surface today; authenticated coverage of the Basic-Auth-gated taiji application is a tracked follow-up. SAST (Checkov, tfsec) and SCA (Syft/Grype) run on every deploy alongside it."),
    "ra-5.8": ("implemented", "sp-corporate",
        "Historic audit records are retained in CloudWatch and the daily Grype re-scan catches newly disclosed CVEs against deployed dependencies; review for prior exploitation is part of the security-review cadence."),

    # --- Partial / planned: honestly still open, pointing at tracked work ---
    "ra-5.6": ("planned", "sp-system",
        "The VDR aggregator runs every deploy and daily, but automated cross-run trend analysis depends on the first-detected ledger tracked as an open POA&M item."),
}

# CJIS-specific items in the GovRAMP+CJIS matrix that are not standard 800-53
# controls, and the Rev 4 controls with no Rev 5 successor. Dispositioned N/A at
# the spoke level (they cannot live in an 800-53 hub).
SPOKE_NA = {
    "ia-0": "No Criminal Justice Information is processed; the CJIS overlay does not apply (Originating Agency Identifier).",
    "ia-5.j": "No Criminal Justice Information is processed; CJIS authenticator additions do not apply.",
    "ia-5.k": "No Criminal Justice Information is processed; CJIS authenticator additions do not apply.",
    "ia-5.l": "No Criminal Justice Information is processed; CJIS authenticator additions do not apply.",
    "ia-5.m": "No Criminal Justice Information is processed; CJIS authenticator additions do not apply.",
    "ia-5.n": "No Criminal Justice Information is processed; CJIS authenticator additions do not apply.",
    "ia-5.o": "No Criminal Justice Information is processed; CJIS authenticator additions do not apply.",
}

# CMMC requirements whose disposition is best expressed against the requirement,
# not an 800-53 control (3.12.4 has no Table D-1 mapping; the system satisfies it
# directly by producing the SSP).
CMMC_DISP = {
    "3.12.4": ("implemented", "The system produces a NIST OSCAL Rev 5 System Security Plan on every deploy, published at /.well-known/oscal-ssp.json; the SSP requirement is satisfied directly even though Table D-1 lists no 800-53 mapping."),
}


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "_note": "Dispositions for controls required by GovRAMP/TX-RAMP/CMMC above the FedRAMP Moderate baseline. Read by the spoke projections alongside the Moderate hub.",
        "controls": {c: {"status": s, "origination": o, "statement": t} for c, (s, o, t) in DISP.items()},
        "spoke_not_applicable": SPOKE_NA,
        "cmmc_requirement_dispositions": {r: {"status": s, "statement": t} for r, (s, t) in CMMC_DISP.items()},
    }
    OUT.write_text(json.dumps(doc, indent=2) + "\n")
    from collections import Counter
    by = Counter(s for s, _, _ in DISP.values())
    print(f"wrote {len(DISP)} Rev5 dispositions -> {OUT.relative_to(REPO)}")
    print(f"  by status: {dict(by)}")
    print(f"  spoke-level N/A (CJIS + no-successor): {len(SPOKE_NA)}")
    print(f"  CMMC requirement dispositions: {len(CMMC_DISP)}")


if __name__ == "__main__":
    main()
