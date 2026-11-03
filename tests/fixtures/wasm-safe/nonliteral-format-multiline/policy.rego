# Fixture: a non-literal format that begins on the line after sprintf(. Must fail.
package fixture.nonliteral_multiline

import rego.v1

fmt := input.format

msg := sprintf(
	fmt,
	["x"],
)
