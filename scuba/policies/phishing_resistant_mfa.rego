# SCuBA policy: phishing-resistant MFA for application access.
# Maps to NIST 800-53 Rev5 IA-2(1). Evaluated locally by the customer against
# their own configuration; nothing leaves their environment.
package scuba.phishing_resistant_mfa

import future.keywords.if

default pass := false

# Pass if the customer enforces phishing-resistant MFA (WebAuthn/FIDO2 or PIV)...
pass if input.auth.phishing_resistant == true

# ...or has explicitly accepted the single-factor residual risk (valid only for a
# sole operator-as-customer; onboarding real users re-opens this — see POAM-021).
pass if input.auth.risk_accepted == true

detail := "Phishing-resistant MFA (WebAuthn/PIV) enforced." if input.auth.phishing_resistant == true

detail := "Single-factor auth; residual risk accepted by the sole customer (POAM-021)." if {
	input.auth.phishing_resistant != true
	input.auth.risk_accepted == true
}

detail := "Single-factor auth and risk NOT accepted — IA-2(1) not satisfied." if {
	input.auth.phishing_resistant != true
	input.auth.risk_accepted != true
}

result := {"pass": pass, "detail": detail}
