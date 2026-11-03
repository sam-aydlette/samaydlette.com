# Fixture for tests/test_check_wasm_safe.py: every sprintf form here must pass.
# A comment may mention sprintf(fmt, [x]) or "%.2f" without failing the check.
package fixture.clean

import rego.v1

single := sprintf("%s has %d item(s)", ["bucket", 3])

backtick := sprintf(`%s: raw string`, ["x"])

percent_literal := sprintf("100%%. done for %s", ["x"])

width_only := sprintf("%5d|%-8s", [1, "a"])

multiline := sprintf(
	"value %s is not allowed (got '%s')",
	["a", "b"],
)

concat_of_literals := sprintf(
	concat(" ", [
		"Live %s configuration for %s could not be read;",
		"this resource is UNASSESSED.",
	]),
	["x", "y"],
)

escaped := sprintf("quote \" then %s", ["x"])
