# =============================================================================
# S3 BUCKET SECURITY POLICY
# =============================================================================
# Checks S3 buckets for required security settings. Reads only the uniform
# `resources` set from policy.gate — never raw input — so the same rules
# gate a terraform plan at deploy time and live GetBucket* API responses at
# runtime.
# =============================================================================

package policy.terraform.s3

import data.policy.gate

# Flag S3 buckets that don't have versioning turned on
violations contains violation if {
	some r in gate.resources
	r.type == "aws_s3_bucket"
	not r.versioning_enabled
	violation := {
		"id": "versioning_disabled",
		"type": "versioning_disabled",
		"category": "infrastructure",
		"severity": "MEDIUM",
		"resource": r.name,
		"address": gate.address_of(r),
		"message": "S3 bucket versioning must be enabled for compliance",
	}
}

# Flag S3 buckets that don't have encryption turned on
violations contains violation if {
	some r in gate.resources
	r.type == "aws_s3_bucket"
	not r.encryption_enabled
	violation := {
		"id": "encryption_disabled",
		"type": "encryption_disabled",
		"category": "infrastructure",
		"severity": "HIGH",
		"resource": r.name,
		"address": gate.address_of(r),
		"message": "S3 bucket server-side encryption must be enabled",
	}
}

# Flag S3 buckets that don't have public access fully blocked. Evaluated at
# both deploy time (from the plan's aws_s3_bucket_public_access_block join)
# and at runtime (the Lambda populates it from GetPublicAccessBlock API
# calls).
violations contains violation if {
	some r in gate.resources
	r.type == "aws_s3_bucket"
	not r.public_access_blocked
	violation := {
		"id": "public_access_not_fully_blocked",
		"type": "public_access_not_fully_blocked",
		"category": "infrastructure",
		"severity": "HIGH",
		"resource": r.name,
		"address": gate.address_of(r),
		"message": "S3 bucket must block all public access (ACLs, policy, ignore, restrict)",
	}
}
