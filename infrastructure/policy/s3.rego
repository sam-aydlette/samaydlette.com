# =============================================================================
# S3 BUCKET SECURITY POLICY
# =============================================================================
# Checks S3 buckets for required security settings. Reads only the uniform
# `resources` set from policy.gate — never raw input — so the same rules
# gate a terraform plan at deploy time and live GetBucket* API responses at
# runtime.
#
# CONTROL TRACEABILITY: each rule's METADATA block carries its violation id,
# severity, and its (PROPOSED) NIST 800-53 / FedRAMP KSI lineage. The
# violation object is built from rego.metadata.rule(), so the annotation is
# the single source of truth — and scripts/check-policy-annotations.py diffs
# every annotation against the KSI catalog in CI, failing the build if a rule
# claims a control its declared KSIs do not carry.
# =============================================================================

package policy.terraform.s3

import data.policy.gate

# METADATA
# title: S3 bucket versioning enabled
# description: Buckets must version objects so content can be recovered to a prior state.
# custom:
#   id: versioning_disabled
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [cp-9, cp-10, si-12]
#   ksi_ids: [KSI-RPL-ABO]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_s3_bucket"
	not r.versioning_enabled
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"S3 bucket versioning must be enabled for compliance",
	)
}

# METADATA
# title: S3 bucket server-side encryption enabled
# description: Buckets must encrypt objects at rest (AES256 or aws:kms).
# custom:
#   id: encryption_disabled
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [sc-28, sc-28.1]
#   ksi_ids: [KSI-SVC-SIN]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_s3_bucket"
	not r.encryption_enabled
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"S3 bucket server-side encryption must be enabled",
	)
}

# METADATA
# title: S3 bucket public access fully blocked
# description: >-
#   All four public-access-block flags must be set. Evaluated at both deploy
#   time (from the plan's aws_s3_bucket_public_access_block join) and at
#   runtime (the Lambda populates it from GetPublicAccessBlock API calls).
# custom:
#   id: public_access_not_fully_blocked
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [sc-7, sc-7.7]
#   ksi_ids: [KSI-CNA-ULN]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_s3_bucket"
	not r.public_access_blocked
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"S3 bucket must block all public access (ACLs, policy, ignore, restrict)",
	)
}
