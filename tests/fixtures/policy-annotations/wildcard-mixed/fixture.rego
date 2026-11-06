# Known-bad fixture for scripts/check-policy-annotations.py: "*" mixed with a type
package policy.terraform.fixture

# METADATA
# title: Fixture rule
# description: A rule whose annotation fails for one reason.
# custom:
#   id: fixture_rule
#   category: infrastructure
#   severity: LOW
#   nist_controls: [au-12]
#   ksi_ids: [KSI-MLA-LET]
#   resource_types: ["*", aws_s3_bucket]
violations contains msg if {
	some r in input.resources
	r.type == "aws_s3_bucket"
	msg := r.name
}
