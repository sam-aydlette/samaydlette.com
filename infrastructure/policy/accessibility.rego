# =============================================================================
# ACCESSIBILITY DECISION POLICY
# =============================================================================
# THE PATTERN: SCANNERS PRODUCE FACTS, OPA DECIDES. Accessibility conformance
# is checked by a real scanner (pa11y running WCAG 2 AA via HTML_CodeSniffer
# in headless Chromium — tools/a11y/scan.js), which renders each page and
# emits a JSON facts document. This package makes the pass/fail decision over
# those facts: which issue types fail the gate is configuration
# (data.config.gate.accessibility.fail_on), and accepted findings go through
# the exceptions register like any other violation.
#
# This replaced five string/regex checks that ran inside Rego. String
# matching cannot see a rendered page (contrast, ARIA name computation,
# label association), and one of the regexes used RE2-unsupported lookahead
# syntax — the rule could never fire, and the gate silently passed pages
# with missing alt text for as long as the rule existed. A policy engine is
# the right place to DECIDE about accessibility facts and the wrong tool to
# DISCOVER them.
#
# These rules trace to Section 508 / WCAG rather than NIST 800-53, so their
# metadata carries `framework: section-508` and empty nist_controls/ksi_ids —
# the annotation checker exempts rules with no declared KSIs from the KSI
# catalog diff. (Note: a comment line must not BEGIN with the word METADATA,
# which OPA reserves as the annotation-block marker.)
# =============================================================================

# METADATA
# title: Section 508 accessibility decision over scanner facts
# schemas:
#   - input: schema.gate_input
package policy.accessibility

import data.policy.gate

# Issue types that fail the gate — an organization-defined parameter. pa11y
# classifies issues as error / warning / notice; the shipped config fails on
# "error" (WCAG 2 AA conformance failures) and treats the advisory types as
# non-blocking.
fail_on_types := {t | some t in data.config.gate.accessibility.fail_on}

gating_issues(page) := [issue |
	some issue in page.issues
	issue.type in fail_on_types
]

# One violation per (page, WCAG rule code): granular enough that an exception
# can accept a specific finding (rule_id + resource + code) without silencing
# everything else on the page, and stable across runs for the same defect.
# METADATA
# title: Page free of gating accessibility issues
# description: Every scanned page must be free of issues whose type is in the configured fail_on set.
# custom:
#   id: a11y_error
#   category: accessibility
#   severity: HIGH
#   framework: section-508
#   nist_controls: []
#   ksi_ids: []
violations contains violation if {
	gate.is_scan_input
	some page in input.accessibility_scan.pages
	some code in {i.code | some i in gating_issues(page)}
	issues := [i | some i in gating_issues(page); i.code == code]
	violation := object.union(
		gate.make_violation(
			rego.metadata.rule().custom,
			page.file_name,
			page.file_path,
			sprintf("%s: %d gating issue(s) for %s — e.g. %s", [page.file_name, count(issues), code, issues[0].message]),
		),
		{"code": code},
	)
}
