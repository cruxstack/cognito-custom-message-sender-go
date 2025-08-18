package cognito_custom_sender_email_policy

import rego.v1

# map between client-id to template-id
template_map := {
  "xxxx1111": "template-01",
  "xxxx2222": "template-02",
}

template_id = id if {
  id := template_map[input.callerContext.clientId]
}

# fallback template-id if client-id is missing from `template_map`
template_id = "default-template" if {
  not template_map[input.callerContext.clientId]
}

result := deny_result if {
  input.emailVerification != null
  input.emailVerification.valid == false
}

result := allow_result if {
  not deny_result
}

allow_result := {
  "action": "allow",
  "allow": {
    "srcAddress": "ACME <noreply@example.org>",
    "dstAddress": input.userAttributes.email,
    "providers": {
      "ses": {
        "templateId": template_id,
        "templateData": {
          "clientId": input.callerContext.clientId
        }
      }
    }
  }
}

deny_result := {
  "action": "deny",
  "reason": "email verification failed"
} if {
  input.emailVerification != null
  input.emailVerification.valid == false
}
