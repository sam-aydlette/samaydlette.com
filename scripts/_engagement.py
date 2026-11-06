"""No engagement (DEC-194): the one statement, and the screen that keeps text honest to it.

The operator does not engage FedRAMP or any federal agency about this system:
no submission, notice, invitation, access grant, meeting or commitment. Every
counterparty a FedRAMP process names is simulated. The trust page, the CPO
(providerExtensions.engagement), the OCR, the Quarterly Review output and every
simulated output's header carry STATEMENT, verbatim, so nobody has to infer it.

`invitations(text)` is the phrase screen: wording that offers to invite,
notify, register, serve or answer a real agency or FedRAMP. A mention that
names the party as simulated ("FedRAMP (simulated)", "the simulated FedRAMP")
is not an offer, and is allowed. tests/test_engagement.py runs it over the
records, the decisions, the procedures, the trust page and the generated
outputs.
"""

import re

DECISION = "DEC-194"
STATEMENT = ("No engagement (DEC-194): this is a proof of concept. The operator does not engage FedRAMP or any "
             "federal agency about this system, and makes them no submission, notice, invitation, access grant "
             "or commitment. Every FedRAMP, agency, assessor and attendee you see here is simulated, and nothing "
             "is sent to anyone. Anyone who really, really wants something can say hello on LinkedIn "
             "(https://www.linkedin.com/in/sa2/); the operator may consider it, with no obligation and no deadline.")
SHORT = "Simulated (DEC-194): no real FedRAMP, agency or person took part, and nothing was sent to anyone."

# A party named as simulated is not a real party.
_REAL_PARTY = (r"(?<!simulated )(?<!fictional )(?:FedRAMP|(?:an |any |federal |the )?agenc(?:y|ies))"
               r"(?! \(simulated\))(?![- ](?:access|exercise|customer data|information|user))")
_PATTERNS = [
    # inviting or registering a real party
    rf"\binvit\w*\s+(?:{_REAL_PARTY})",
    rf"(?:{_REAL_PARTY})\s+(?:can|may|should)\s+(?:file|register|request|ask|use the|attend|submit|sign up)",
    rf"(?:{_REAL_PARTY})\s+that wants",
    # notifying or serving a real party
    rf"\bnotif(?:y|ies|ied)\s+(?:{_REAL_PARTY})",
    rf"\b(?:supplies|supply|provides|provide|sends?)\s+(?:it |them |the \w+ )?to\s+(?:{_REAL_PARTY})\s+on request",
    r"\b(?:registration|access|feedback)\s+form\b",
    r"\bregister(?:ed)? (?:parties|for (?:a|the) (?:Quarterly )?Review)",
    r"\bjoin link\b",
    # promising a real party an answer
    r"\b(?:on|upon) request\b",
    r"\bthe answer comes within\b",
    r"\bparties who registered\b",
    r"\bissues/new\?template=",
]
_SCREEN = re.compile("|".join(f"(?:{p})" for p in _PATTERNS), re.IGNORECASE)


def invitations(text):
    """Every phrase in `text` that offers engagement with a real agency or FedRAMP."""
    return [m.group(0) for m in _SCREEN.finditer(text or "")]


def strings(value):
    """Every string inside a JSON value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)


def require_none(value, what):
    """Fail closed when any string in `value` offers engagement."""
    hits = sorted({h for s in strings(value) for h in invitations(s)})
    if hits:
        raise SystemExit(f"::error::{what} offers engagement with a real agency or FedRAMP ({DECISION}): "
                         f"{'; '.join(hits)[:300]} (fail-closed)")
    return value
