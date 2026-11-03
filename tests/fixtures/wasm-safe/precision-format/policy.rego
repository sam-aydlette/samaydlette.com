# Fixture: a literal format carrying a precision specifier. Must fail.
package fixture.precision

import rego.v1

msg := sprintf("ratio %.5f for %s", [0.5, "x"])
