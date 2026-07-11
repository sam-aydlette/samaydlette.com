package policy_test.accessibility

import data.policy.accessibility
import data.terraform.compliance

# =============================================================================
# Scanner-facts decision tests. The scanner produces facts; these tests pin
# the DECISION over a fixed facts document (mirrors of real pa11y output over
# tests/fixtures/html/ — see tests/fixtures/a11y/).
# =============================================================================

_clean_page := {"file_name": "compliant.html", "file_path": "../website/compliant.html", "issues": []}

_alt_error := {
	"code": "WCAG2AA.Principle1.Guideline1_1.1_1_1.H37",
	"type": "error",
	"message": "Img element missing an alt attribute.",
	"selector": "html > body > img",
	"context": "<img src=\"diagram.png\">",
}

_warning_issue := {
	"code": "WCAG2AA.Principle1.Guideline1_4.1_4_3.G18",
	"type": "warning",
	"message": "Check contrast manually.",
	"selector": "html > body > p",
	"context": "<p>x</p>",
}

_bad_page := {"file_name": "missing-alt.html", "file_path": "../website/missing-alt.html", "issues": [_alt_error, _warning_issue]}

_scan(pages) := {"accessibility_scan": {
	"scanner": {"name": "pa11y", "version": "9.1.1", "standard": "WCAG2AA"},
	"pages": pages,
}}

# A clean scan is compliant.
test_clean_scan_compliant if {
	compliance.compliant == true with input as _scan([_clean_page])
}

# An error-type issue fails the gate; the must-fire case for the defect class
# the old lookahead-regex rule silently missed (A3): a page with an image
# missing alt text MUST produce a violation.
test_missing_alt_must_fire if {
	some v in accessibility.violations with input as _scan([_clean_page, _bad_page])
	v.id == "a11y_error" with input as _scan([_clean_page, _bad_page])
	compliance.compliant == false with input as _scan([_clean_page, _bad_page])
}

# The violation is per (page, code) and carries the WCAG code.
test_violation_carries_code if {
	vs := accessibility.violations with input as _scan([_bad_page])
	count(vs) == 1
	some v in vs
	v.code == "WCAG2AA.Principle1.Guideline1_1.1_1_1.H37"
	v.resource == "missing-alt.html"
	v.address == "../website/missing-alt.html"
}

# Which issue types gate is configuration, not logic: failing on warnings too
# is a config change with no .rego edit.
test_fail_on_is_config_driven if {
	count(accessibility.violations) == 2 with input as _scan([_bad_page])
		with data.config.gate.accessibility.fail_on as ["error", "warning"]
}

# page_reports mirrors the validations.json accessibility entry shape.
test_page_reports_shape if {
	reports := compliance.page_reports with input as _scan([_clean_page, _bad_page])
	count(reports) == 2
	some r in reports
	r.file_name == "missing-alt.html"
	r.kind == "accessibility"
	r.compliant == false
	count(r.violations) == 1
}

# A code-scoped exception accepts one finding without silencing the page: the
# alt-text error is NOT suppressed by an exception naming a different code.
test_code_scoped_exception_is_precise if {
	compliance.compliant == false with input as _scan([_bad_page])
		with data.exceptions as [{
			"resource": "missing-alt.html",
			"rule_id": "a11y_error",
			"code": "WCAG2AA.Principle1.Guideline1_4.1_4_3.G18.Fail",
			"justification": "test", "expiry": "2099-01-01", "ticket": "TEST-2",
		}]
		with data.runtime as {"evaluated_at": "2026-07-10T00:00:00Z"}
}

test_code_scoped_exception_suppresses_its_finding if {
	report := compliance.compliance_report with input as _scan([_bad_page])
		with data.exceptions as [{
			"resource": "missing-alt.html",
			"rule_id": "a11y_error",
			"code": "WCAG2AA.Principle1.Guideline1_1.1_1_1.H37",
			"justification": "test", "expiry": "2099-01-01", "ticket": "TEST-2",
		}]
		with data.runtime as {"evaluated_at": "2026-07-10T00:00:00Z"}
	report.compliant == true
	count(report.excepted) == 1
}
