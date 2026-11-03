# Defines a template for both providers, so the email can still be sent when
# the first provider in APP_EMAIL_PROVIDERS fails or SES sending is paused.
#
# Deploy with APP_EMAIL_PROVIDERS=ses,sendgrid.
package cognito_custom_sender_email_policy

import rego.v1

data_for_templates := {"appName": "ACME", "trigger": input.trigger}

result := {
	"action": "allow",
	"allow": {
		"srcAddress": "ACME <no-reply@example.com>",
		"providers": {
			"ses": {
				"templateId": "acme-code",
				"templateData": data_for_templates,
			},
			"sendgrid": {
				"templateId": "d-0123456789abcdef0123456789abcdef",
				"templateData": data_for_templates,
			},
		},
	},
}
