# SCuBA policy: phishing-resistant MFA for application access.
# Maps to NIST 800-53 Rev5 IA-2(1). Evaluated locally by the customer against
# their own configuration; nothing leaves their environment.
#
# Since 2026-06-22 the CSO enforces mandatory TOTP MFA at the identity provider
# for every account (POAM-021 closed), so single-factor access is not possible
# and the old sole-customer risk-acceptance branch is gone. The customer's
# remaining responsibility is authenticator POSTURE: TOTP meets IA-2(1) but is
# phishable; WebAuthn/FIDO2/PIV is the phishing-resistant target (M-22-09;
# tracked directionally with POAM-025).
package scuba.phishing_resistant_mfa

import future.keywords.if
import future.keywords.in

default pass := false

phishing_resistant if input.auth.mfa_type in {"webauthn", "fido2", "piv"}

# Phishing-resistant authenticators: the target posture.
pass if phishing_resistant

# TOTP: the CSO-enforced baseline. Meets IA-2(1) (MFA for privileged/all
# accounts); flagged as phishable so the upgrade path stays visible.
pass if input.auth.mfa_type == "totp"

detail := "Phishing-resistant MFA (WebAuthn/FIDO2/PIV) enforced — target posture." if phishing_resistant

detail := "TOTP MFA enforced (the CSO baseline) — meets IA-2(1); TOTP is phishable, WebAuthn/FIDO2 is the recommended upgrade (M-22-09)." if {
	input.auth.mfa_type == "totp"
}

detail := "No MFA claimed — inconsistent with this CSO (the identity provider enforces TOTP for every account since 2026-06-22); correct your configuration or verify you are assessing the right deployment." if {
	not phishing_resistant
	not input.auth.mfa_type == "totp"
}

result := {"pass": pass, "detail": detail}
