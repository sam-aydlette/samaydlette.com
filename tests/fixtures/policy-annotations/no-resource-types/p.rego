package policy.fixture

# METADATA
# custom:
#   id: fixture
#   category: infrastructure
#   severity: HIGH
#   nist_controls: []
#   ksi_ids: [KSI-SCR-MON]
violations contains v if {
	some v in input.nothing
}
