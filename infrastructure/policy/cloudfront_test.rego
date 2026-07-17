package cloudfront_test

import data.policy.terraform.cloudfront

# =============================================================================
# TLS ordered-minimum tests (parameters as data)
# =============================================================================

_cf(mpv) := {"resource": {
	"type": "aws_cloudfront_distribution", "name": "cdn",
	"viewer_protocol_policy": "redirect-to-https",
	"minimum_protocol_version": mpv,
}}

weak_tls(v) := [x | some x in v; x.id == "weak_tls"]

# The configured floor passes.
test_tls_at_minimum_passes if {
	count(weak_tls(cloudfront.violations)) == 0 with input as _cf("TLSv1.2_2021")
}

# Anything ranked below the floor fails.
test_tls_below_minimum_fails if {
	count(weak_tls(cloudfront.violations)) > 0 with input as _cf("TLSv1_2016")
}

# A version the order list has never heard of fails closed.
test_tls_unknown_version_fails if {
	count(weak_tls(cloudfront.violations)) > 0 with input as _cf("TLSvFuture_9999")
}

# A hypothetical STRONGER policy passes once the order list knows it — a data
# change, not a logic change. This is the property the old equality pin
# (`!= "TLSv1.2_2021"`) inverted: a stronger policy used to FAIL the gate.
test_tls_stronger_than_minimum_passes if {
	count(weak_tls(cloudfront.violations)) == 0 with input as _cf("TLSv1.3_2030")
		with data.config.gate.tls.order as [
			"SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016",
			"TLSv1.2_2018", "TLSv1.2_2019", "TLSv1.2_2021", "TLSv1.3_2030",
		]
}

# Raising the floor via config alone changes enforcement with no .rego edit.
test_tls_floor_raised_by_config_alone if {
	count(weak_tls(cloudfront.violations)) > 0 with input as _cf("TLSv1.2_2021")
		with data.config.gate.tls.order as [
			"SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016",
			"TLSv1.2_2018", "TLSv1.2_2019", "TLSv1.2_2021", "TLSv1.3_2030",
		]
		with data.config.gate.tls.minimum as "TLSv1.3_2030"
}

test_insecure_protocol_fails if {
	some v in cloudfront.violations with input as {"resource": {
		"type": "aws_cloudfront_distribution", "name": "cdn",
		"viewer_protocol_policy": "allow-all",
		"minimum_protocol_version": "TLSv1.2_2021",
	}}
	v.id == "insecure_protocol" with input as {"resource": {
		"type": "aws_cloudfront_distribution", "name": "cdn",
		"viewer_protocol_policy": "allow-all",
		"minimum_protocol_version": "TLSv1.2_2021",
	}}
}
