# A v2-style policy that v3 rejects: the top-level templateID was removed.
package cognito_custom_sender_email_policy

import rego.v1

result := {
	"action": "allow",
	"allow": {
		"srcAddress": "ACME <no-reply@example.com>",
		"templateID": "acme-code",
		"templateData": {},
	},
}
