# Cognito Custom Message Sender

## What

An AWS Lambda function that sends policy-driven emails in response to AWS
Cognito events. It supports AWS SES and SendGrid for delivery, with optional
SendGrid email verification, automatic failover between providers, and built-in
email rate limiting.

## Why

AWS Cognito's built-in email templates are limited. This solution lets you:

- **Share a single user pool across multiple sites/apps** while sending
  site-specific emails based on client ID
- **Use dynamic email templates** with custom data driven by OPA/Rego policies
- **Choose your email provider** (SES or SendGrid) per deployment
- **Automatic failover** between providers when SES is suspended or unavailable
- **Validate email addresses** before sending (built-in RFC 5322 format
  validation, or SendGrid's API for advanced checks like disposable/role-based
  detection)
- **Rate limit emails** per destination address, per user, and per message
  class, backed by DynamoDB

## How It Works

1. Cognito triggers the Lambda with a Custom Email Sender event
2. If rate limiting is enabled, the email is counted and throttled emails stop
   here (see [Email Rate Limiting](#email-rate-limiting))
3. An OPA/Rego policy evaluates the event and returns:
   - **Allow**: with template ID, template data, and addresses
   - **Deny**: with a reason (email is not sent)
4. If allowed, the Lambda decrypts the verification code using KMS
5. The email is sent via SES or SendGrid

## Deployment

### 1. Build

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bootstrap main.go
```

### 2. Package

```bash
zip deployment.zip bootstrap policy.rego
```

### 3. Deploy

Deploy as an AWS Lambda with `provided.al2023` runtime. Configure:

- **IAM permissions**: KMS decrypt, SES send (if using SES), DynamoDB (if
  rate limiting is enabled)
- **Environment variables**: see table below
- **Cognito**: set as Custom Email Sender trigger

### Environment Variables

| Variable                                  | Description                                        | Default                      |
| ----------------------------------------- | -------------------------------------------------- | ---------------------------- |
| `APP_EMAIL_SENDER_POLICY_PATH`            | Path to the Rego policy file.                      | **required**                 |
| `APP_KMS_KEY_ID`                          | KMS key ARN for decrypting Cognito codes.          | **required**                 |
| `APP_EMAIL_PROVIDER`                      | Email provider: `ses` or `sendgrid`.               | `ses`                        |
| `APP_SEND_ENABLED`                        | `true` to send emails, `false` for dry-run.        | `true`                       |
| `APP_LOG_LEVEL`                           | Log level: `debug`, `info`, `warn`, `error`.       | `info`                       |
| `APP_EMAIL_VERIFICATION_ENABLED`          | `false` to disable email verification.             | `true`                       |
| `APP_EMAIL_VERIFICATION_PROVIDER`         | Verification provider: `sendgrid` or `offline`.    | `offline`                    |
| `APP_EMAIL_VERIFICATION_WHITELIST`        | Comma-separated domains that skip verification.    | `""`                         |
| `APP_SENDGRID_API_HOST`                   | SendGrid API base URL.                             | `https://api.sendgrid.com`   |
| `APP_SENDGRID_EMAIL_SEND_API_KEY`         | SendGrid API key for sending.                      | **required if sendgrid**     |
| `APP_SENDGRID_EMAIL_VERIFICATION_API_KEY` | SendGrid API key for verification.                 | **required if sendgrid verification** |
| `APP_EMAIL_FAILOVER_ENABLED`              | Enable automatic provider failover.                | `false`                      |
| `APP_EMAIL_FAILOVER_PROVIDERS`            | Comma-separated failover providers (e.g., `sendgrid`). | **required if failover**  |
| `APP_EMAIL_FAILOVER_CACHE_TTL`            | Health check cache duration (Go duration format).  | `30s`                        |
| `APP_EMAIL_RATE_LIMIT_ENABLED`            | Enable email rate limiting.                        | `false`                      |
| `APP_EMAIL_RATE_LIMIT_TABLE_NAME`         | DynamoDB table for rate limit counters.            | **required if rate limiting** |
| `APP_EMAIL_RATE_LIMIT_CONFIG`             | Rate limit settings as JSON (see below).           | built-in defaults            |

## Provider Failover

AWS can suspend SES sending at any time for compliance reasons. Enable automatic
failover to ensure emails continue to be delivered via an alternative provider.

### How It Works

1. Before each send, the system checks SES account status via the `GetAccount` API
2. The result is cached (default 30s) to avoid excessive API calls
3. If SES is unhealthy (`SendingEnabled=false`), it fails over to the next provider
4. If a provider fails to send, it tries the next one in the chain
5. If all providers fail, a warning is logged (no Lambda retry to avoid cascading failures)

### Configuration Example

```bash
# Primary provider
APP_EMAIL_PROVIDER=ses

# Enable failover with SendGrid as backup
APP_EMAIL_FAILOVER_ENABLED=true
APP_EMAIL_FAILOVER_PROVIDERS=sendgrid
APP_EMAIL_FAILOVER_CACHE_TTL=30s

# SendGrid credentials (required when in failover chain)
APP_SENDGRID_EMAIL_SEND_API_KEY=SG.xxxx
```

### Policy Requirements

When failover is enabled, your policy **must** return template configurations for
all providers in the failover chain. If a provider's config is missing, it will
be skipped with a warning.

```rego
result := {
  "action": "allow",
  "allow": {
    "srcAddress": "noreply@example.com",
    "dstAddress": input.userAttributes.email,
    "providers": {
      "ses": {
        "templateId": "ses-verification-template",
        "templateData": {"appName": "MyApp"}
      },
      "sendgrid": {
        "templateId": "d-abc123def456",
        "templateData": {"appName": "MyApp"}
      }
    }
  }
}
```

### IAM Permissions

When failover is enabled, add SESv2 `GetAccount` permission:

```json
{
  "Effect": "Allow",
  "Action": ["ses:SendTemplatedEmail", "sesv2:GetAccount"],
  "Resource": "*"
}
```

## Email Rate Limiting

Rate limiting caps how many emails one address, one user, or one message class
can receive in a time window. It is off by default.

### Why

With passwordless sign-in (`USER_AUTH` with `EMAIL_OTP`), anyone who has a
public app client ID can make Cognito send a code to any registered address.
Repeated requests can flood an inbox, add email provider cost, and hurt the
sender's reputation.

- Cognito's built-in cap is per requester IP: "Email MFA messages sent to one
  email address hourly per requester IP address: 5-20"
  ([quotas](https://docs.aws.amazon.com/cognito/latest/developerguide/quotas.html)).
  Requests from many IPs are not capped together.
- AWS WAF rate-based rules can't count by a field in a JSON request body, so
  they can't count by destination address.
- The custom email sender sees every email Cognito sends, with the destination
  address, whatever the client or IP.

### How It Works

For each event, the Lambda:

1. **Classifies** the trigger into a message class.
2. **Checks exemptions** (exempt classes and domains are sent without counting).
3. **Detects retries** with a conditional write keyed on the SHA-256 of the
   encrypted code. Lambda retries carry the same ciphertext, so a retry is sent
   without being counted again.
4. **Increments counters** in DynamoDB with atomic `UpdateItem` `ADD` calls,
   run in parallel. Throttled attempts still count.
5. **Decides**. A throttled email is logged and dropped, and the function
   returns success.

Cognito invokes the custom email sender asynchronously
([Lambda triggers](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-working-with-lambda-triggers.html)),
so the function can't fail or change the Cognito API call. The caller always
sees "code sent", including when the email is throttled.

| Class             | Trigger sources                                                        | Default destination limits |
| ----------------- | ---------------------------------------------------------------------- | -------------------------- |
| `authentication`  | `CustomEmailSender_Authentication`                                     | 5 per 15m, 20 per 24h      |
| `signup`          | `CustomEmailSender_SignUp`, `CustomEmailSender_ResendCode`             | 3 per 1h, 10 per 24h       |
| `forgot_password` | `CustomEmailSender_ForgotPassword`                                     | 5 per 1h                   |
| `attribute`       | `CustomEmailSender_UpdateUserAttribute`, `_VerifyUserAttribute`        | 5 per 1h                   |
| `notification`    | `CustomEmailSender_AccountTakeOverNotification`                        | 3 per 1h                   |
| `admin`           | `CustomEmailSender_AdminCreateUser`                                    | exempt                     |

Unknown trigger sources are sent, logged, and reported with class `unknown`.

### Limits

- **Destination limits** count per normalized address. Addresses are trimmed
  and lowercased, `+tag` suffixes are removed, and dots are removed from Gmail
  local parts (`googlemail.com` is treated as `gmail.com`). Counter keys use
  the SHA-256 of the normalized address; the address itself is never stored.
- **User limits** (optional) count per user, keyed on the `sub` attribute or
  the Cognito `userName`, hashed the same way.
- **Global limits** (optional) count all emails in a class. In `count` mode
  (the default) they log and emit a metric but never block. In `enforce` mode
  they throttle. Global counters are split across shards that are summed on
  read, so a burst doesn't overload one DynamoDB item.
- **Priority degrade**: in `enforce` mode, once a class's global count passes
  `degradeFraction` of its max, low-trust recipients are throttled first. A
  recipient is low trust when `cognito:user_status` is `UNCONFIRMED` or
  `email_verified` isn't `"true"`. Cognito doesn't document which attributes
  each trigger includes, so a missing `email_verified` counts as unverified.

Windows are fixed and aligned to the Unix epoch (a `24h` window resets at
00:00 UTC), so up to twice a limit can be sent across a window boundary. An
email is throttled when its count, including itself, is greater than `max`.

### Configuration

Set `APP_EMAIL_RATE_LIMIT_ENABLED=true` and
`APP_EMAIL_RATE_LIMIT_TABLE_NAME`. `APP_EMAIL_RATE_LIMIT_CONFIG` is optional
JSON that overrides the defaults. Fields you omit keep their defaults, but an
entry under `classes` replaces that class's defaults entirely. The config is
validated at startup, and an invalid config stops the Lambda from starting.
When rate limiting is disabled the config isn't read.

| Field                    | Description                                                                    | Default                      |
| ------------------------ | ------------------------------------------------------------------------------ | ---------------------------- |
| `failMode`               | `open` sends when DynamoDB fails; `closed` drops the email.                    | `open`                       |
| `timeout`                | Deadline for all rate limit calls per email (Go duration, at most `10s`).      | `1s`                         |
| `dedupeTtl`              | How long retry markers are kept (Go duration, at least `1m`).                  | `6h`                         |
| `metricNamespace`        | CloudWatch namespace for metrics.                                              | `CognitoCustomMessageSender` |
| `userKey`                | User limit key: `sub` or `userName`.                                           | `sub`                        |
| `normalize.stripPlusTag` | Remove `+tag` from the local part.                                             | `true`                       |
| `normalize.stripGmailDots` | Remove dots from Gmail local parts.                                          | `true`                       |
| `exempt.domains`         | Destination domains that are never counted (exact match).                      | `[]`                         |
| `exempt.classes`         | Classes that are never counted.                                                | `["admin"]`                  |
| `global.mode`            | Global limit mode: `count` or `enforce`.                                       | `count`                      |
| `global.shards`          | Shards per global counter (1-100).                                             | `4`                          |
| `global.degradeFraction` | Fraction of a global max where low-trust recipients are throttled (0-1].       | `0.8`                        |
| `classes.<class>.destination` | List of `{"window", "max"}` limits per address.                           | see table above              |
| `classes.<class>.user`   | List of `{"window", "max"}` limits per user.                                   | `[]`                         |
| `classes.<class>.global` | List of `{"window", "max"}` limits for the whole class.                        | `[]`                         |
| `classes.<class>.globalMode` | Overrides `global.mode` for one class.                                     | unset                        |

A window is a positive integer followed by `s`, `m`, `h`, or `d` (for example
`15m`, `24h`, `7d`). `max` must be a positive integer, and windows can't repeat
within one list.

```json
{
  "failMode": "open",
  "metricNamespace": "CognitoCustomMessageSender",
  "exempt": { "domains": ["example.com"], "classes": ["admin"] },
  "global": { "mode": "enforce", "shards": 4, "degradeFraction": 0.8 },
  "classes": {
    "authentication": {
      "destination": [{ "window": "15m", "max": 5 }, { "window": "24h", "max": 20 }],
      "user": [{ "window": "1h", "max": 10 }],
      "global": [{ "window": "1h", "max": 5000 }]
    },
    "signup": {
      "destination": [{ "window": "1h", "max": 3 }, { "window": "24h", "max": 10 }],
      "global": [{ "window": "1h", "max": 1000 }],
      "globalMode": "count"
    }
  }
}
```

Global limits have no defaults because they depend on normal traffic. Run in
`count` mode first, then set a max above the observed peak before switching to
`enforce`.

### Retries and Failures

- **Retries:** the first attempt is counted; Lambda retries of the same event
  are sent without counting again. Events with no code (account takeover
  notifications) are counted on every attempt.
- **Store errors:** if DynamoDB errors, throttles, or exceeds `timeout`, the
  email is sent (`failMode: open`) or dropped (`failMode: closed`), and the
  error is logged. A limit that is known to be exceeded still throttles when
  another counter fails.
- **Throttles never return an error,** so Lambda doesn't retry them.

Cognito codes expire within minutes, so a late email is rarely useful. Consider
lowering the function's asynchronous retry settings
([`maximum_event_age_in_seconds`, `maximum_retry_attempts`](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html)).

### DynamoDB Table

The table needs a string partition key named `pk` and TTL enabled on the `ttl`
attribute. On-demand capacity is recommended. Items are small counters and
retry markers that expire one hour after their window ends.

```json
{
  "Effect": "Allow",
  "Action": ["dynamodb:UpdateItem", "dynamodb:PutItem", "dynamodb:BatchGetItem"],
  "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/cognito-email-rate-limit"
}
```

### Metrics

Each email writes one [CloudWatch Embedded Metric Format](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html)
record to the function's log, so metrics need no extra API calls. Records are
written at any `APP_LOG_LEVEL`. Dimensions are `class` and `decision`; no
dimension identifies an address.

| Metric                         | Description                                                                   |
| ------------------------------ | ----------------------------------------------------------------------------- |
| `EmailRateLimitDecision`       | One per email, by class and decision.                                         |
| `EmailRateLimitGlobalExceeded` | Emails that global limits throttle (`enforce`) or would throttle (`count`).   |

| Decision                | Meaning                                                        |
| ----------------------- | -------------------------------------------------------------- |
| `sent`                  | Within limits. The policy can still deny the email.            |
| `throttled_destination` | Dropped: a destination limit was exceeded.                     |
| `throttled_user`        | Dropped: a user limit was exceeded.                            |
| `throttled_global`      | Dropped: a global limit or priority degrade applied.           |
| `deduped`               | A Lambda retry; sent without counting.                         |
| `exempt`                | Exempt class or domain, or unknown trigger; sent.              |
| `fail_open`             | The store failed; sent.                                        |
| `fail_closed`           | The store failed; dropped.                                     |

Throttle logs include the masked address (`u***@example.com`) and its hash.

### Trade-offs

- A throttled recipient gets no email, while the API call that triggered it
  still succeeds. Users who request many codes may need to wait for the window
  to reset.
- Fixed windows allow short bursts at window boundaries.
- Address hashes are unsalted SHA-256, so someone with table access can test
  whether a known address appears.
- Each counted email adds one conditional write and one update per configured
  window (plus one batch read for global limits), run in parallel after the
  retry check.

## Writing Policies

The Rego policy receives an `input` object:

```jsonc
{
  "trigger": "CustomEmailSender_SignUp",
  "callerContext": {
    "awsSdkVersion": "aws-sdk-unknown-unknown",
    "clientId": "xxxxxxxxxxxxxxxxxx"
  },
  "userAttributes": {
    "email": "user@example.org",
    "email_verified": "false",
    "sub": "uuid"
  },
  "clientMetadata": {
    "key": "value"
  },
  // present if APP_EMAIL_VERIFICATION_ENABLED=true
  "emailVerification": {
    "valid": true,
    "score": 0.97,
    "raw": "{...}"
  },
  // present if APP_EMAIL_RATE_LIMIT_ENABLED=true
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

Throttled emails never reach the policy. `rateLimit` lets a policy add its own
deny on top, for example while global limits are in `count` mode. Windows are
reported in their largest whole unit (`24h` is reported as `1d`). Counts are
empty when the email was exempt, deduped, or the store failed.

The policy must return `data.cognito_custom_sender_email_policy.result`:

**Allow:**

```json
{
  "action": "allow",
  "allow": {
    "srcAddress": "noreply@example.org",
    "dstAddress": "user@example.org",
    "providers": {
      "ses": {
        "templateId": "your-ses-template",
        "templateData": { "code": "123456" }
      },
      "sendgrid": {
        "templateId": "d-xxxxxxxxxx",
        "templateData": { "code": "123456" }
      }
    }
  }
}
```

**Deny:**

```json
{
  "action": "deny",
  "reason": "email verification failed"
}
```

### Example: Route by Client ID

```rego
package cognito_custom_sender_email_policy
import rego.v1

templates := {
  "app-client-id-1": "d-template-for-app1",
  "app-client-id-2": "d-template-for-app2",
}

result := {
  "action": "allow",
  "allow": {
    "srcAddress": "noreply@example.com",
    "dstAddress": input.userAttributes.email,
    "providers": {
      "sendgrid": {
        "templateId": templates[input.callerContext.clientId],
        "templateData": {}
      }
    }
  }
}
```

### Example: Deny When Global Limits Would Throttle

```rego
package cognito_custom_sender_email_policy
import rego.v1

result := {
  "action": "deny",
  "reason": "global email rate limit"
} if {
  input.rateLimit.global.wouldThrottle
}

result := {
  "action": "allow",
  "allow": {
    "srcAddress": "noreply@example.com",
    "dstAddress": input.userAttributes.email,
    "providers": {
      "ses": {
        "templateId": "verification-template",
        "templateData": {}
      }
    }
  }
} if {
  not input.rateLimit.global.wouldThrottle
}
```

### Example: Deny on Failed Email Verification

```rego
package cognito_custom_sender_email_policy
import rego.v1

result := {
  "action": "deny",
  "reason": "invalid email address"
} if {
  input.emailVerification != null
  not input.emailVerification.valid
}

result := {
  "action": "allow",
  "allow": {
    "srcAddress": "noreply@example.com",
    "dstAddress": input.userAttributes.email,
    "providers": {
      "ses": {
        "templateId": "verification-template",
        "templateData": {}
      }
    }
  }
} if {
  not result.action == "deny"
}
```

---

# Development

## Project Structure

```
├── cmd/debug/          # Debug CLI for local testing
├── e2e/                # End-to-end tests
├── fixtures/           # Test data and policies
├── internal/
│   ├── config/         # Environment configuration
│   ├── encryption/     # KMS decryption
│   ├── opa/            # Policy evaluation
│   ├── providers/      # Email providers (SES, SendGrid)
│   ├── ratelimit/      # Email rate limiting (DynamoDB and in-memory stores)
│   ├── sender/         # Core send logic
│   ├── types/          # Shared and Cognito event types
│   └── verifier/       # Email verification
└── main.go             # Lambda entrypoint
```

## Running Tests

```bash
# All tests
make test

# Unit tests only
make test-unit

# E2E tests only
make test-e2e
```

E2E tests are fully offline using:
- httptest mock server for SendGrid API
- Passthrough decrypter in place of KMS
- Mock email provider to capture sends
- In-memory rate limit store

The DynamoDB rate limit store tests run against
[DynamoDB Local](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html)
and are skipped unless `RATELIMIT_DYNAMODB_ENDPOINT` is set:

```bash
docker run --rm -d -p 8000:8000 amazon/dynamodb-local
make test-dynamodb
```

## Debug Mode

Test locally without real credentials:

```bash
# Using make (loads .env automatically)
make debug

# Or with custom fixtures
go run ./cmd/debug -data path/to/events.json -policy path/to/policy.rego
```

Debug mode:
- Loads `.env` file
- Mocks KMS decryption when `APP_KMS_KEY_ID=MOCKED_KEY_ID`
- Dry-runs email sends by default (`APP_SEND_ENABLED=false`)
- Uses an in-memory rate limit store when rate limiting is enabled without
  `APP_EMAIL_RATE_LIMIT_TABLE_NAME`

| Variable              | Description                            | Default                    |
| --------------------- | -------------------------------------- | -------------------------- |
| `APP_DEBUG_MODE`      | Enable debug mode.                     | `false`                    |
| `APP_DEBUG_DATA_PATH` | Path to JSON file with Cognito events. | `fixtures/debug-data.json` |

## Deprecated Variables

| Deprecated             | Use Instead                               |
| ---------------------- | ----------------------------------------- |
| `APP_SENDGRID_API_KEY` | `APP_SENDGRID_EMAIL_VERIFICATION_API_KEY` |
| `KMS_KEY_ID`           | `APP_KMS_KEY_ID`                          |
