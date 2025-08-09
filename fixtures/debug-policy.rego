package cognito_custom_sender_email_policy

# map between client-id to template-id
template_map := {
  "xxxx1111": "template-01",
  "xxxx2222": "template-02",
}

template_id = id {
  id := template_map[input.callerContext.clientId]
}

# fallback template-id if client-id is missing from `template_map`
template_id = "default-template" {
  not template_map[input.callerContext.clientId]
}

result := deny_result {
  input.emailVerification != null
  input.emailVerification.valid == false
}

result := allow_result {
  not deny_result
}

allow_result := {
  "action": "allow",
  "allow": {
    "templateID": template_id,
    "templateData": {
      "clientId": input.callerContext.clientId
    },
    "srcAddress": "ACME <noreply@example.org>",
    "dstAddress": input.userAttributes.email
  }
}

deny_result := {
  "action": "deny",
  "reason": "email verification failed"
} {
  input.emailVerification != null
  input.emailVerification.valid == false
}
