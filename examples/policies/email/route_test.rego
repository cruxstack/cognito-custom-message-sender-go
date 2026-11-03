# Unit tests for route.rego. Run them with:
#
#   opa test examples/policies/email/route.rego examples/policies/email/route_test.rego
package cognito_custom_sender_email_policy_test

import rego.v1

import data.cognito_custom_sender_email_policy as policy

test_sign_up_uses_welcome_template_and_client_brand if {
	r := policy.result with input as {
		"trigger": "CustomEmailSender_SignUp",
		"callerContext": {"clientId": "mobile-app-client-id"},
		"clientMetadata": {"locale": "fr"},
	}
	r.action == "allow"
	r.allow.srcAddress == "ACME Mobile <no-reply@m.example.com>"
	r.allow.providers.ses.templateId == "acme-welcome"
	r.allow.providers.ses.templateData == {"appName": "ACME Mobile", "locale": "fr"}
}

test_unknown_trigger_and_client_use_defaults if {
	r := policy.result with input as {
		"trigger": "CustomEmailSender_SomethingNew",
		"callerContext": {"clientId": "CLIENT_ID_NOT_APPLICABLE"},
		"clientMetadata": {},
	}
	r.allow.srcAddress == "ACME <no-reply@example.com>"
	r.allow.providers.ses.templateId == "acme-code"
	r.allow.providers.ses.templateData.locale == "en"
}
