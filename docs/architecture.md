# Architecture

One Lambda function serves both custom sender triggers. Cognito invokes it
asynchronously with an event that holds the user's attributes and an
encrypted code; the function decides, with your policy, whether and how to
deliver the code, then sends it.

```text
Cognito ─▶ handler ─┬─▶ email: rate limit ─▶ verify ─▶ policy ─▶ decrypt ─▶ mailer ─▶ SES / SendGrid
          (routes   │          (DynamoDB)    (SendGrid)  (Rego)    (KMS)     (failover)
          by trigger)
                    └─▶ sms:   rate limit ─▶ history ─▶ policy ─▶ decrypt ─▶ publisher ─▶ SNS
                               (DynamoDB)    (DynamoDB)  (Rego)    (KMS)
```

The order is deliberate: cheap checks run first, and the code is decrypted
only for messages that will be sent, so throttled or denied messages cost no
KMS call.

## Packages

| Package              | Responsibility                                                                                     |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| `main.go`            | Lambda entry point: logging, configuration, `app.New`, `lambda.Start`.                             |
| `cmd/devtool`        | Local CLI: `eval` policies against events, `run` events through the full sender.                   |
| `internal/app`       | Composition root. Builds every dependency from the configuration; options replace AWS clients and stores in tests and the devtool. |
| `internal/config`    | Reads and validates environment variables. No other package reads the environment.                |
| `internal/handler`   | Decodes the event, adds log context, and routes by trigger to the email or SMS sender.             |
| `internal/cognito`   | The custom sender event type and trigger constants.                                                |
| `internal/email`     | The email pipeline, its policy input, and validation of the policy result.                         |
| `internal/sms`       | The SMS pipeline, policy input and result, SMS history, phone parsing, and the SNS publisher.      |
| `internal/policy`    | Compiles and evaluates Rego policies; validates actions.                                           |
| `internal/mailer`    | Email delivery: the SES and SendGrid providers, the failover chain, and the dry-run mailer.        |
| `internal/verify`    | Email verification: offline, SendGrid, and the allowlist.                                          |
| `internal/ratelimit` | Email and SMS rate limiting with fixed-window counters in DynamoDB.                                |
| `internal/decrypt`   | Decrypts codes with the AWS Encryption SDK and KMS.                                                |
| `internal/sendgrid`  | A minimal client for the SendGrid Mail Send and Email Address Validation APIs.                     |
| `internal/logging`   | The JSON log handler with per-event context, and masking of emails and phone numbers.              |

Dependencies point one way: `app` knows every package; the senders depend
on small interfaces (`mailer.Mailer`, `verify.Verifier`, `decrypt.Decrypter`,
`email.RateLimiter`, `sms.RateLimiter`, `sms.Publisher`, `sms.HistoryStore`) rather than on
configuration or AWS clients, which keeps them testable with fakes.

## Failure handling

Cognito invokes the function asynchronously, so a returned error makes
Lambda retry the event (twice by default) and then send it to the
function's failure destination, if one is configured. The function returns
an error only when a retry could help or the event should be kept:

| Situation                                                | Result                         |
| -------------------------------------------------------- | ------------------------------ |
| Email or SMS throttled by a rate limit                   | logged, success                |
| Message denied by the policy                             | logged, success                |
| SMS to an invalid phone number                           | logged, success                |
| Event for a disabled sender or an unknown trigger        | logged, success                |
| Email verification provider unavailable                  | logged, policy runs without it |
| Rate limit store unavailable                             | per `failMode`: sent or dropped |
| SMS history unavailable                                  | logged, `recentAttempts` is 0  |
| Policy result undefined or invalid                       | error                          |
| KMS decryption failed                                    | error                          |
| Every email provider failed, or SNS publish failed       | error                          |

Retries don't double count: the rate limiter recognizes a retried event by
its ciphertext and doesn't count it again.

## Design notes

- **Configuration fails fast.** Invalid values and removed variables stop the
  function at startup, where a deployment check notices, instead of changing
  behavior at send time.
- **Policies are compiled once,** at startup, and evaluated per event.
- **Failover never drops a message because of a health check.** An unhealthy
  provider is moved to the end of the chain rather than skipped, and a
  failed health check counts as healthy.
- **Personal data stays out of logs** unless `APP_LOG_LEVEL=debug`: addresses
  and phone numbers are masked, and rate limit counters store SHA-256 hashes.
- **Rate limit metrics** are written as CloudWatch Embedded Metric Format log
  records, so they need no extra API calls or permissions.
