# =============================================================================
# KEYS, CERTIFICATES AND DNSSEC
# =============================================================================
# Customer-managed KMS keys (rotation, enabled state), the ACM certificate
# (issued, not about to expire) and the hosted zone's DNSSEC signing status.
#
# Runtime-only facts, written by the emitter where Terraform has no attribute:
#   aws_acm_certificate.values.not_after   (DescribeCertificate NotAfter)
#   aws_route53_zone.values.dnssec_status  (GetDNSSEC Status.ServeSignature)
# The plan carries the certificate and zone as data sources without these
# facts, so those two rules bite only on live state.
# =============================================================================

package policy.terraform.keys

import data.policy.gate

ns_per_day := 86400000000000

# The evaluation time is data (data.runtime.evaluated_at), never time.now_ns(),
# so the Go and Wasm evaluators agree; without it no expiry is computed.
evaluated_at_ns := time.parse_rfc3339_ns(data.runtime.evaluated_at)

# METADATA
# title: Symmetric KMS keys rotate
# description: Automatic annual rotation must be on for every symmetric customer-managed key.
# custom:
#   id: kms_rotation_disabled
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [sc-12]
#   ksi_ids: [KSI-SVC-ASM]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_kms_key"
	gate.value(r, "customer_master_key_spec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT"
	gate.attribute_read_ok(r, "enable_key_rotation")
	gate.value(r, "enable_key_rotation", false) != true
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"Symmetric KMS key must have automatic rotation enabled",
	)
}

# METADATA
# title: KMS keys are enabled
# description: A disabled or pending-deletion key breaks the encryption and signing that depend on it.
# custom:
#   id: kms_key_disabled
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [sc-12]
#   ksi_ids: [KSI-SVC-ASM]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_kms_key"
	gate.value(r, "is_enabled", true) == false
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		"KMS key is disabled or pending deletion",
	)
}

# METADATA
# title: TLS certificate is issued
# description: The certificate serving the site must be in the ISSUED state.
# custom:
#   id: certificate_not_issued
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [sc-8, sc-23]
#   ksi_ids: [KSI-SVC-SIN]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_acm_certificate"
	status := gate.value(r, "status", null)
	status != null
	status != "ISSUED"
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		sprintf("TLS certificate status is %s, not ISSUED", [status]),
	)
}

# METADATA
# title: TLS certificate is not about to expire
# description: >-
#   The certificate must stay valid for at least
#   data.config.gate.tls.min_days_to_expiry days past the evaluation time
#   (ACM renews 60 days ahead, so a shorter horizon means renewal failed).
# custom:
#   id: certificate_expiring
#   category: infrastructure
#   severity: HIGH
#   nist_controls: [sc-8, sc-23]
#   ksi_ids: [KSI-SVC-SIN]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_acm_certificate"
	not_after := time.parse_rfc3339_ns(gate.value(r, "not_after", null))
	not_after - evaluated_at_ns < data.config.gate.tls.min_days_to_expiry * ns_per_day
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		sprintf(
			"TLS certificate expires within %d days",
			[data.config.gate.tls.min_days_to_expiry],
		),
	)
}

# METADATA
# title: Hosted zone answers are DNSSEC-signed
# description: The hosted zone must be serving DNSSEC signatures.
# custom:
#   id: dnssec_not_signing
#   category: infrastructure
#   severity: MEDIUM
#   nist_controls: [sc-20, sc-21]
#   ksi_ids: [KSI-SVC-SIN]
violations contains violation if {
	some r in gate.resources
	r.type == "aws_route53_zone"
	status := gate.value(r, "dnssec_status", null)
	status != null
	status != "SIGNING"
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		r.name,
		gate.address_of(r),
		sprintf("Hosted zone DNSSEC status is %s, not SIGNING", [status]),
	)
}
