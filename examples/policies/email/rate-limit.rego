# Denies sign-up emails to unconfirmed users while a class is near its
# global limit, even when the limits run in "count" mode.
#
# input.rateLimit is set when APP_EMAIL_RATE_LIMIT_ENABLED=true. Emails the
# limiter throttles never reach the policy.
package cognito_custom_sender_email_policy

import rego.v1

allow := {
	"action": "allow",
	"allow": {
		"srcAddress": "ACME <no-reply@example.com>",
		"providers": {"ses": {"templateId": "acme-code", "templateData": {}}},
	},
}

result := {"action": "deny", "reason": "sign-up email volume is unusually high"} if {
	input.rateLimit.class == "signup"
	input.rateLimit.global.degraded
	input.rateLimit.lowTrust
} else := allow
