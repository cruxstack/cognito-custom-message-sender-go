# Policies

Every message is decided by a [Rego](https://www.openpolicyagent.org/docs/policy-language)
policy that you write. The policy receives the Cognito event (plus
verification and rate limit results) as `input` and returns whether to send
and how.

- The email policy is read from `APP_EMAIL_SENDER_POLICY_PATH` and must define
  `data.cognito_custom_sender_email_policy.result`.
- The SMS policy is read from `APP_SMS_SENDER_POLICY_PATH` and must define
  `data.cognito_custom_sender_sms_policy.result`.

Policies are compiled when the function starts, so a syntax error stops the
function from starting instead of failing on the first message. Email
policies must use Rego v1 syntax (`import rego.v1` is optional but harmless).

The [`examples/policies`](../examples/policies) directory has complete,
tested policies to start from.

## Email policy input

```jsonc
{
  "trigger": "CustomEmailSender_SignUp",
  "userPoolId": "us-east-1_EXAMPLE",
  "region": "us-east-1",
  "userName": "8a1b2c3d-0000-4000-8000-000000000001",
  "callerContext": {
    "awsSdkVersion": "aws-sdk-unknown-unknown",
    "clientId": "1example23456789"
  },
  "userAttributes": {
    "sub": "8a1b2c3d-0000-4000-8000-000000000001",
    "email": "user@example.com",
    "email_verified": "false",
    "cognito:user_status": "UNCONFIRMED"
  },
  // {} when the event has none
  "clientMetadata": { "locale": "en" },

  // set when APP_EMAIL_VERIFICATION_ENABLED=true and the address could be
  // checked; unset when the verification provider couldn't be reached
  "emailVerification": {
    "provider": "sendgrid", // offline, sendgrid, or allowlist
    "valid": true,          // false only when the address is undeliverable
    "verdict": "Risky",     // Valid, Risky, or Invalid
    "score": 0.5,           // 0 to 1
    "disposable": true,     // sendgrid only
    "role": false,          // sendgrid only (admin@, support@, ...)
    "raw": "{...}"          // the provider's raw response, as a JSON string
  },

  // set when APP_EMAIL_RATE_LIMIT_ENABLED=true; see rate-limiting.md
  "rateLimit": {
    "class": "signup",
    "decision": "sent", // sent, deduped, exempt, or fail_open
    "reason": "",
    "exempt": false,
    "deduped": false,
    "failOpen": false,
    "lowTrust": true,
    "destination": [
      { "window": "1h", "count": 2, "max": 3, "exceeded": false },
      { "window": "1d", "count": 2, "max": 10, "exceeded": false }
    ],
    "user": [],
    "global": {
      "mode": "count",
      "windows": [{ "window": "1h", "count": 812, "max": 1000, "exceeded": false }],
      "degraded": true,
      "wouldThrottle": true
    }
  }
}
```

`trigger` is the Cognito trigger source:

| Trigger                                         | Sent when                                                | Has a code               |
| ----------------------------------------------- | -------------------------------------------------------- | ------------------------ |
| `CustomEmailSender_SignUp`                      | A user signs up.                                         | yes                      |
| `CustomEmailSender_ResendCode`                  | A user asks for a new confirmation code.                 | yes                      |
| `CustomEmailSender_ForgotPassword`              | A user asks to reset their password.                     | yes                      |
| `CustomEmailSender_UpdateUserAttribute`         | A user changes their email address.                      | yes                      |
| `CustomEmailSender_VerifyUserAttribute`         | A user verifies a new email address.                     | yes                      |
| `CustomEmailSender_AdminCreateUser`             | An administrator creates a user.                         | yes (temporary password) |
| `CustomEmailSender_Authentication`              | A user signs in with an email OTP or email MFA.          | yes                      |
| `CustomEmailSender_AccountTakeOverNotification` | Threat protection detects a risky sign-in.               | no                       |

Throttled emails (and SMS) never reach the policy. Rate limit windows are reported in
their largest whole unit (`24h` is reported as `1d`), and counts are empty
when the email was exempt, deduped, or the store failed.

## Email policy result

To send:

```jsonc
{
  "action": "allow",
  "allow": {
    // required; a display name is optional
    "srcAddress": "ACME <no-reply@example.com>",
    // optional; defaults to the user's email attribute
    "dstAddress": "user@example.com",
    // required; a template for at least one provider in APP_EMAIL_PROVIDERS
    "providers": {
      "ses": {
        "templateId": "acme-welcome",      // an SES template name
        "templateData": { "appName": "ACME" }
      },
      "sendgrid": {
        "templateId": "d-0123456789abcdef", // a SendGrid dynamic template ID
        "templateData": { "appName": "ACME" }
      }
    }
  }
}
```

The decrypted code (or temporary password) is added to the template data as
`code`, replacing any `code` the policy sets, so templates render it with
`{{code}}`. Providers are tried in the order of `APP_EMAIL_PROVIDERS`;
providers the result has no template for are skipped.

To not send:

```json
{ "action": "deny", "reason": "invalid email address" }
```

`block` is accepted as an alias for `deny`. A denied email is logged with its
reason and the function returns success, so Lambda doesn't retry it.

The function returns an error, so Lambda retries the event, when the result
is undefined, has an action other than `allow`, `deny`, or `block`, or is
missing a required field. Run your policy through `devtool eval` (below)
before you deploy it.

## SMS policy

The SMS policy input has the same `trigger`, `userPoolId`, `region`,
`userName`, `callerContext`, `userAttributes`, and `clientMetadata` fields
(with `CustomSMSSender_*` triggers), plus:

```jsonc
{
  "phoneNumberData": {
    "number": "+12065550100", // E.164
    "country": "US",
    "countryCallingCode": "1",
    "nationalNumber": "2065550100",
    "carrierCode": null,
    "isValid": true,
    "isPossible": true
  },
  // set when APP_SMS_HISTORY_TABLE_NAME is configured: SMS to this number
  // within APP_SMS_THROTTLE_PERIOD, including this one
  "history": { "recentAttempts": 2 },

  // set when APP_SMS_RATE_LIMIT_ENABLED=true; the same fields as for email
  "rateLimit": { "class": "authentication", "decision": "sent" /* ... */ }
}
```

To send, return the message; the first `{####}` is replaced with the code:

```jsonc
{
  "action": "allow",
  "allow": {
    "message": "Your ACME code is {####}",
    "messageType": "Transactional", // or Promotional; default Transactional
    "senderId": "",                 // optional AWS.SNS.SMS.SenderID
    "shortCode": ""                 // optional AWS.MM.SMS.OriginationNumber
  }
}
```

To not send, return `{"action": "deny", "reason": "..."}` or, as policies for
the Node.js sender did, `{"action": "block", "block": {"reason": "..."}}`.

## Writing robust policies

- **Always define a result.** An undefined result is an error. Use `default`
  values or an `else` chain that ends in an unconditional value, and give
  lookup tables a default so a new trigger or app client doesn't break the
  policy:

  ```rego
  default template := "acme-code"

  template := templates[input.trigger]
  ```

- **Don't define one rule twice with different values.** Two `result` rules
  that both match with different values are an evaluation error. Chain them
  with `else`, which picks the first match:

  ```rego
  result := deny("undeliverable address") if {
  	input.emailVerification.valid == false
  } else := allow
  ```

- **Decide what a missing value means.** `not input.emailVerification.valid`
  is true when verification is disabled or unavailable, which would deny
  every email during a verification outage. `input.emailVerification.valid ==
  false` only matches a real verdict.

- **Keep secrets out of policies.** The policy is packaged with the function;
  template data is sent to your email provider.

## Testing policies

Evaluate a policy against sample events without AWS credentials or network
calls:

```sh
go run ./cmd/devtool eval \
  -email-policy examples/policies/email/route.rego \
  -events examples/events/email.json
```

Each event prints its decision and the outcome (`send`, `denied`, or the
error the function would return). Add `-show-input` to see the exact input
document, and `-verify=false` to leave out the offline verification result.
Events can be a single event object or an array; real events are logged at
`APP_LOG_LEVEL=debug`.

Policies can also have Rego unit tests, run with the
[OPA CLI](https://www.openpolicyagent.org/docs/cli):

```sh
opa test examples/policies/email/route.rego examples/policies/email/route_test.rego
```

See [`route_test.rego`](../examples/policies/email/route_test.rego). The
example policies and their tests run in CI (`make test-policies`).

## Examples

| Policy                                                                 | Shows                                                       |
| ---------------------------------------------------------------------- | ----------------------------------------------------------- |
| [`email/basic.rego`](../examples/policies/email/basic.rego)            | One SES template for every email.                           |
| [`email/route.rego`](../examples/policies/email/route.rego)            | Templates by trigger, branding by app client, defaults.     |
| [`email/failover.rego`](../examples/policies/email/failover.rego)      | Templates for SES and SendGrid, for provider failover.      |
| [`email/verification.rego`](../examples/policies/email/verification.rego) | Denying undeliverable and disposable addresses.          |
| [`email/rate-limit.rego`](../examples/policies/email/rate-limit.rego)  | Denying low-trust sign-ups while traffic is unusually high. |
| [`sms/throttle.rego`](../examples/policies/sms/throttle.rego)          | Blocking SMS after five attempts in the throttle period.    |
