package cognito_custom_sender_email_policy

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
    "templateID": "default-template",
    "templateData": {},
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
