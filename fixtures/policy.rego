package cognito_custom_sender_email_policy

import rego.v1

# default to sending message
result := {
	"action": "allow",
	"allow": {
		"templateID": "test",
		"templateData": {},
		"srcAddress": "ACME <noreply@example.com>",
		"dstAddress": "me@example.com",
	},
}
