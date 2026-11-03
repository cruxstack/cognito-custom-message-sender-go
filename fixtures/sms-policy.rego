package cognito_custom_sender_sms_policy

import rego.v1

# default to sending the message; {####} is replaced with the code
default result := {
  "action": "allow",
  "allow": {
    "message": "Your code is: {####}",
    "messageType": "Transactional",
    "senderId": "",
    "shortCode": "",
  },
}

# block when the phone number had more than 5 attempts in the throttle period
result := {
  "action": "block",
  "block": {"reason": "rate limit exceeded"},
} if {
  input.history.recentAttempts > 5
}
