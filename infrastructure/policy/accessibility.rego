# =============================================================================
# SECTION 508 ACCESSIBILITY POLICY
# =============================================================================
# Checks HTML content for accessibility compliance. These rules trace to
# Section 508 / WCAG rather than NIST 800-53, so their METADATA carries
# `framework: section-508` and empty nist_controls/ksi_ids — the annotation
# checker exempts rules with no declared KSIs from the catalog diff.
# =============================================================================

# METADATA
# title: Section 508 accessibility checks
# schemas:
#   - input: schema.gate_input
package policy.accessibility

import data.policy.gate

# METADATA
# title: HTML language declaration present
# custom:
#   id: missing_language_declaration
#   category: accessibility
#   severity: HIGH
#   framework: section-508
#   nist_controls: []
#   ksi_ids: []
violations contains violation if {
	gate.is_html_input
	input.html_content != ""
	not contains(input.html_content, "html lang=")
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		input.file_name,
		input.file_name,
		sprintf("HTML file %s missing language declaration (html lang attribute)", [input.file_name]),
	)
}

# METADATA
# title: Images carry alt text
# custom:
#   id: missing_alt_text
#   category: accessibility
#   severity: HIGH
#   framework: section-508
#   nist_controls: []
#   ksi_ids: []
violations contains violation if {
	gate.is_html_input
	input.html_content != ""
	contains(input.html_content, "<img")
	img_without_alt := regex.find_all_string_submatch_n(
		`<img[^>]*(?:(?!alt=)[^>])*>`,
		input.html_content, -1,
	)
	count(img_without_alt) > 0
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		input.file_name,
		input.file_name,
		sprintf("HTML file %s contains images without alt text", [input.file_name]),
	)
}

# METADATA
# title: Main heading present
# custom:
#   id: missing_main_heading
#   category: accessibility
#   severity: MEDIUM
#   framework: section-508
#   nist_controls: []
#   ksi_ids: []
violations contains violation if {
	gate.is_html_input
	input.html_content != ""
	not contains(input.html_content, "<h1")
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		input.file_name,
		input.file_name,
		sprintf("HTML file %s missing main heading (h1 element)", [input.file_name]),
	)
}

# METADATA
# title: No empty alt attributes on meaningful images
# custom:
#   id: empty_alt_text
#   category: accessibility
#   severity: MEDIUM
#   framework: section-508
#   nist_controls: []
#   ksi_ids: []
violations contains violation if {
	gate.is_html_input
	input.html_content != ""
	contains(input.html_content, `alt=""`)
	not contains(input.html_content, "decorative")
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		input.file_name,
		input.file_name,
		sprintf("HTML file %s contains images with empty alt text", [input.file_name]),
	)
}

# METADATA
# title: DOCTYPE declaration present
# custom:
#   id: missing_doctype
#   category: accessibility
#   severity: LOW
#   framework: section-508
#   nist_controls: []
#   ksi_ids: []
violations contains violation if {
	gate.is_html_input
	input.html_content != ""
	not contains(input.html_content, "<!DOCTYPE html>")
	violation := gate.make_violation(
		rego.metadata.rule().custom,
		input.file_name,
		input.file_name,
		sprintf("HTML file %s missing DOCTYPE declaration", [input.file_name]),
	)
}
