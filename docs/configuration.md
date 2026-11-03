# Configuration

The function is configured with environment variables. They are validated
when the function starts: an unknown value, a missing required value, or a
variable removed in v3 stops the function from starting, and the error lists
every problem at once.

Booleans are `true` or `false`. Durations are Go durations such as `30s`,
`15m`, or `720h`. Lists are comma-separated.

## General

| Variable           | Description                                                                         | Default    |
| ------------------ | ----------------------------------------------------------------------------------- | ---------- |
| `APP_KMS_KEY_ID`   | ARN of the KMS key the user pool encrypts codes with (the pool's `KMSKeyID`).       | required   |
| `APP_LOG_LEVEL`    | `debug`, `info`, `warn`, or `error`. `debug` logs every event, including attributes. | `info`     |
| `APP_SEND_ENABLED` | `false` logs each message instead of sending it (a dry run).                        | `true`     |

## Email sender

| Variable                          | Description                                                                                         | Default    |
| --------------------------------- | --------------------------------------------------------------------------------------------------- | ---------- |
| `APP_EMAIL_SENDER_ENABLED`        | Handle `CustomEmailSender_*` events.                                                                | `true`     |
| `APP_EMAIL_SENDER_POLICY_PATH`    | Path to the email policy, relative to the working directory (`/var/task` in Lambda).                | required   |
| `APP_EMAIL_PROVIDERS`             | Providers to send with, in order: `ses`, `sendgrid`. More than one enables failover.                | `ses`      |
| `APP_EMAIL_HEALTH_CHECK_TTL`      | How long an SES account health check is cached. Only used when SES is followed by another provider. | `30s`      |
| `APP_EMAIL_VERIFICATION_ENABLED`  | Verify the address before the policy runs and pass the result as `input.emailVerification`.        | `true`     |
| `APP_EMAIL_VERIFICATION_PROVIDER` | `offline` (syntax check, no network) or `sendgrid` (SendGrid Email Address Validation).             | `offline`  |
| `APP_EMAIL_VERIFICATION_ALLOWLIST`| Domains that are treated as valid without verification (exact match).                               |            |
| `APP_EMAIL_RATE_LIMIT_ENABLED`    | Enable [rate limiting](rate-limiting.md).                                                           | `false`    |
| `APP_EMAIL_RATE_LIMIT_TABLE_NAME` | DynamoDB table for rate limit counters.                                                             | required when enabled |
| `APP_EMAIL_RATE_LIMIT_CONFIG`     | JSON that overrides the default limits; see [rate limiting](rate-limiting.md#configuration).        | defaults   |

## SMS sender

| Variable                     | Description                                                       | Default               |
| ---------------------------- | ----------------------------------------------------------------- | --------------------- |
| `APP_SMS_SENDER_ENABLED`     | Handle `CustomSMSSender_*` events. See [SMS sender](sms.md).      | `false`               |
| `APP_SMS_SENDER_POLICY_PATH` | Path to the SMS policy.                                           | required when enabled |
| `APP_SMS_RATE_LIMIT_ENABLED` | Enable [rate limiting](rate-limiting.md) for SMS.                 | `false`               |
| `APP_SMS_RATE_LIMIT_TABLE_NAME` | DynamoDB table for rate limit counters; can be the email table. | required when enabled |
| `APP_SMS_RATE_LIMIT_CONFIG`  | JSON that overrides the default SMS limits.                       | defaults              |
| `APP_SMS_HISTORY_TABLE_NAME` | DynamoDB table for the [SMS history](sms.md#history-table) (`input.history`). | unset (history off) |
| `APP_SMS_HISTORY_TTL`        | How long history records are kept.                                | `720h`                |
| `APP_SMS_THROTTLE_PERIOD`    | The window `input.history.recentAttempts` counts over.            | `15m`                 |

## SendGrid

| Variable                                  | Description                                                                 | Default                    |
| ----------------------------------------- | --------------------------------------------------------------------------- | -------------------------- |
| `APP_SENDGRID_API_HOST`                   | API host for sending and verification. EU accounts use `https://api.eu.sendgrid.com`. | `https://api.sendgrid.com` |
| `APP_SENDGRID_EMAIL_SEND_API_KEY`         | API key with Mail Send access.                                              | required when `sendgrid` is in `APP_EMAIL_PROVIDERS` |
| `APP_SENDGRID_EMAIL_VERIFICATION_API_KEY` | API key with Email Address Validation access.                               | required when the verification provider is `sendgrid` |

Lambda environment variables are visible to anyone who can read the
function's configuration. Restrict `lambda:GetFunctionConfiguration`, or
encrypt the variables with a KMS key.

## Provider failover

AWS can pause SES sending for an account at any time, for example while a
bounce or complaint rate is reviewed. With more than one provider in
`APP_EMAIL_PROVIDERS`, each email is sent with the first provider that
succeeds:

1. Providers the policy result has no template for are skipped.
2. Before sending, SES checks the account with `GetAccount` (cached for
   `APP_EMAIL_HEALTH_CHECK_TTL`). When sending is paused, SES is tried last
   instead of first. When the check itself fails, SES is assumed healthy.
3. If a provider returns an error, the next one is tried.
4. If every provider fails, the function returns an error, so Lambda retries
   the event and, after the last retry, sends it to the function's failure
   destination.

The policy has to return a template for each provider that should be able to
send; see [`failover.rego`](../examples/policies/email/failover.rego).

## IAM permissions

The execution role needs only the statements for the features you enable.

```jsonc
[
  // always: decrypt codes
  { "Effect": "Allow", "Action": "kms:Decrypt", "Resource": "arn:aws:kms:us-east-1:111122223333:key/EXAMPLE" },

  // email with ses (GetAccount only when ses is followed by another provider)
  { "Effect": "Allow", "Action": ["ses:SendEmail", "ses:GetAccount"], "Resource": "*" },

  // email or sms rate limiting
  {
    "Effect": "Allow",
    "Action": ["dynamodb:UpdateItem", "dynamodb:PutItem", "dynamodb:BatchGetItem"],
    "Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/EXAMPLE-rate-limit"
  },

  // sms
  { "Effect": "Allow", "Action": "sns:Publish", "Resource": "*" },

  // sms history
  {
    "Effect": "Allow",
    "Action": ["dynamodb:PutItem", "dynamodb:Query"],
    "Resource": [
      "arn:aws:dynamodb:us-east-1:111122223333:table/EXAMPLE-sms-history",
      "arn:aws:dynamodb:us-east-1:111122223333:table/EXAMPLE-sms-history/index/*"
    ]
  }
]
```

`ses:SendEmail` can be scoped to your sending identities and templates. The
Lambda also needs the usual `AWSLambdaBasicExecutionRole` permissions to
write logs, and Cognito needs `lambda:InvokeFunction` on the function.

## Lambda settings

- **Runtime:** `provided.al2023`, handler `bootstrap`, `arm64` or `x86_64`.
- **Timeout:** 10 seconds is plenty; a warm function handles most events in well under a second.
- **Asynchronous invocation:** Cognito invokes custom sender triggers
  asynchronously. Codes expire within minutes, so consider
  `MaximumEventAgeInSeconds` of about 300, and an on-failure destination to
  keep events that still fail after the retries.
- **Logs:** JSON on stdout. Every record for an event carries `request_id`,
  `trigger`, `user_pool_id`, and `client_id`; email addresses and phone
  numbers are masked.
