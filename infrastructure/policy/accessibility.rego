# =============================================================================
# SECTION 508 ACCESSIBILITY POLICY
# =============================================================================
# Checks HTML content for accessibility compliance.
# =============================================================================

# METADATA
# title: Section 508 accessibility checks
# schemas:
#   - input: schema.gate_input
package policy.accessibility

import data.policy.gate

# Flag HTML files that don't have a language declaration
violations contains violation if {
	gate.is_html_input
	input.html_content != ""
	not contains(input.html_content, "html lang=")
	violation := {
		"id": "missing_language_declaration",
		"type": "missing_language_declaration",
		"category": "accessibility",
		"severity": "HIGH",
		"resource": input.file_name,
		"address": input.file_name,
		"message": sprintf("HTML file %s missing language declaration (html lang attribute)", [input.file_name]),
	}
}

# Flag HTML files that have images without alt text
violations contains violation if {
	gate.is_html_input
	input.html_content != ""
	contains(input.html_content, "<img")
	img_without_alt := regex.find_all_string_submatch_n(
		`<img[^>]*(?:(?!alt=)[^>])*>`,
		input.html_content, -1,
	)
	count(img_without_alt) > 0
	violation := {
		"id": "missing_alt_text",
		"type": "missing_alt_text",
		"category": "accessibility",
		"severity": "HIGH",
		"resource": input.file_name,
		"address": input.file_name,
		"message": sprintf("HTML file %s contains images without alt text", [input.file_name]),
	}
}

# Flag HTML files that don't have proper heading structure
violations contains violation if {
	gate.is_html_input
	input.html_content != ""
	not contains(input.html_content, "<h1")
	violation := {
		"id": "missing_main_heading",
		"type": "missing_main_heading",
		"category": "accessibility",
		"severity": "MEDIUM",
		"resource": input.file_name,
		"address": input.file_name,
		"message": sprintf("HTML file %s missing main heading (h1 element)", [input.file_name]),
	}
}

# Flag HTML files that have empty alt attributes (alt="" with no text)
violations contains violation if {
	gate.is_html_input
	input.html_content != ""
	contains(input.html_content, `alt=""`)
	not contains(input.html_content, "decorative")
	violation := {
		"id": "empty_alt_text",
		"type": "empty_alt_text",
		"category": "accessibility",
		"severity": "MEDIUM",
		"resource": input.file_name,
		"address": input.file_name,
		"message": sprintf("HTML file %s contains images with empty alt text", [input.file_name]),
	}
}

# Flag HTML files missing proper document structure
violations contains violation if {
	gate.is_html_input
	input.html_content != ""
	not contains(input.html_content, "<!DOCTYPE html>")
	violation := {
		"id": "missing_doctype",
		"type": "missing_doctype",
		"category": "accessibility",
		"severity": "LOW",
		"resource": input.file_name,
		"address": input.file_name,
		"message": sprintf("HTML file %s missing DOCTYPE declaration", [input.file_name]),
	}
}
