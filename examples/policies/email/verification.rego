# Denies emails to addresses that email verification marks as undeliverable
# or disposable.
#
# input.emailVerification is missing when verification is disabled or the
# provider couldn't be reached. Comparing with "== false" (instead of using
# "not") keeps those emails flowing, so an outage at the verification
# provider doesn't block sign-ups.
package cognito_custom_sender_email_policy

import rego.v1

allow := {
	"action": "allow",
	"allow": {
		"srcAddress": "ACME <no-reply@example.com>",
		"providers": {"ses": {"templateId": "acme-code", "templateData": {}}},
	},
}

deny(reason) := {"action": "deny", "reason": reason}

# "else" picks the first matching rule, so two matching denials can't
# conflict
result := deny("email address is not deliverable") if {
	input.emailVerification.valid == false
} else := deny("disposable email addresses are not allowed") if {
	input.emailVerification.disposable == true
	input.trigger == "CustomEmailSender_SignUp"
} else := allow
