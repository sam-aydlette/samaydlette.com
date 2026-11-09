# =============================================================================
# STATUS REGRESSIONS (design principle 9)
# =============================================================================
# Compares this assessment's rule and KSI statuses with the previous one.
# scripts/build-sdr.py collects the two sets; this module decides; the deploy
# publishes the result and raises an issue for its owner to fix or accept.
#
# A regression is anything that was Implemented and no longer is, including a
# rule or KSI that has disappeared. Only Implemented counts as met, so moves
# among the other statuses are not regressions.
#
# Entry point: data.compliance.regression.result = {"items": [...]}
# input: {"previous": {kind: {id: status}}, "current": {kind: {id: status}}}
# =============================================================================

package compliance.regression

met := "Implemented"

regressions contains {"kind": kind, "id": id, "from": met, "to": now} if {
	some kind, statuses in input.previous
	some id, status in statuses
	status == met
	now := object.get(object.get(input.current, kind, {}), id, "Removed")
	now != met
}

result := {"items": sort([r | some r in regressions])}
