# Sends every email with one Amazon SES template.
#
# The decrypted code (or temporary password) is added to the template data
# as "code", so the template can render it with {{code}}.
package cognito_custom_sender_email_policy

import rego.v1

result := {
	"action": "allow",
	"allow": {
		"srcAddress": "ACME <no-reply@example.com>",
		# dstAddress defaults to the user's email attribute
		"providers": {"ses": {
			"templateId": "acme-code",
			"templateData": {"trigger": input.trigger},
		}},
	},
}
