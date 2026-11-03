# Fixture: a concat format with a non-literal element. Must fail.
package fixture.concat_nonliteral

import rego.v1

msg := sprintf(concat(" ", ["prefix", input.suffix]), ["x"])
