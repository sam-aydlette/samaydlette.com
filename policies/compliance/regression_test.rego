# Unit tests for policies/compliance/regression.rego.
package compliance.regression_test

import data.compliance.regression

items(previous, current) := out if {
	out := regression.result.items with input as {"previous": previous, "current": current}
}

test_no_change_is_no_regression if {
	count(items({"rule": {"A": "Implemented"}}, {"rule": {"A": "Implemented"}})) == 0
}

test_implemented_moving_away_is_a_regression if {
	items({"ksi": {"K": "Implemented"}}, {"ksi": {"K": "Not Demonstrated"}}) == [{"kind": "ksi", "id": "K", "from": "Implemented", "to": "Not Demonstrated"}]
}

test_a_removed_implemented_item_is_a_regression if {
	items({"rule": {"A": "Implemented"}}, {"rule": {}}) == [{"kind": "rule", "id": "A", "from": "Implemented", "to": "Removed"}]
}

test_moves_among_unmet_statuses_are_not_regressions if {
	count(items({"rule": {"A": "Not Demonstrated", "B": "Impractical"}}, {"rule": {"A": "Impractical"}})) == 0
}

test_an_improvement_is_not_a_regression if {
	count(items({"rule": {"A": "Not Demonstrated"}}, {"rule": {"A": "Implemented"}})) == 0
}
