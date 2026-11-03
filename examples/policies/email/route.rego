# Picks the template by message type and the branding by app client, so one
# user pool can serve several apps.
package cognito_custom_sender_email_policy

import rego.v1

# one SES template per message type
templates := {
	"CustomEmailSender_SignUp": "acme-welcome",
	"CustomEmailSender_ResendCode": "acme-welcome",
	"CustomEmailSender_ForgotPassword": "acme-reset-password",
	"CustomEmailSender_AdminCreateUser": "acme-invitation",
	"CustomEmailSender_Authentication": "acme-sign-in-code",
	"CustomEmailSender_AccountTakeOverNotification": "acme-security-alert",
}

# a default keeps the result defined for triggers Cognito adds later
default template := "acme-code"

template := templates[input.trigger]

# branding per app client; unknown clients (and admin-created users, whose
# client ID is CLIENT_ID_NOT_APPLICABLE) get the default brand
brands := {
	"web-app-client-id": {"appName": "ACME", "from": "ACME <no-reply@example.com>"},
	"mobile-app-client-id": {"appName": "ACME Mobile", "from": "ACME Mobile <no-reply@m.example.com>"},
}

default brand := {"appName": "ACME", "from": "ACME <no-reply@example.com>"}

brand := brands[input.callerContext.clientId]

result := {
	"action": "allow",
	"allow": {
		"srcAddress": brand.from,
		"providers": {"ses": {
			"templateId": template,
			"templateData": {
				"appName": brand.appName,
				"locale": object.get(input.clientMetadata, "locale", "en"),
			},
		}},
	},
}
