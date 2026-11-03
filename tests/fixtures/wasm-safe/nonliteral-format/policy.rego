# Fixture: the sprintf format comes from data, not a literal. Must fail.
package fixture.nonliteral

import rego.v1

msg := sprintf(input.format, ["x"])
