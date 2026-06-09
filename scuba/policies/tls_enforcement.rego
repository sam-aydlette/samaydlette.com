# SCuBA policy: TLS in transit. Maps to NIST 800-53 Rev5 SC-8.
package scuba.tls_enforcement

import future.keywords.if

default pass := false

pass if input.tls.min_version == "1.2"
pass if input.tls.min_version == "1.3"

detail := sprintf("TLS minimum version is %v (>= 1.2 required).", [input.tls.min_version]) if input.tls.min_version
detail := "No TLS minimum version configured — SC-8 not satisfied." if not input.tls.min_version

result := {"pass": pass, "detail": detail}
