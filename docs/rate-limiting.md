# Rate limiting

Rate limiting caps how many emails or SMS one destination, one user, or one
message class can receive in a time window. Email and SMS are limited
separately, with their own settings, and both are off by default.

## Why

Anyone who has a public app client ID can make Cognito send a code to any
registered address or phone number, for example with passwordless sign-in
(`USER_AUTH` with `EMAIL_OTP` or `SMS_OTP`), sign-up, or password reset.

- **Email:** repeated requests can flood an inbox, add provider cost, and
  hurt the sender's reputation.
- **SMS:** every message costs money, and SMS pumping (toll fraud) uses
  exactly these flows to send messages to premium-rate numbers the attacker
  is paid for.

The built-in protections don't cover this:

- Cognito's built-in caps are per requester IP (for example, "Email MFA
  messages sent to one email address hourly per requester IP address: 5-20",
  [quotas](https://docs.aws.amazon.com/cognito/latest/developerguide/quotas.html)).
  Requests from many IPs are not capped together.
- AWS WAF rate-based rules can't count by a field in a JSON request body, so
  they can't count by destination.
- The custom sender sees every message Cognito sends, with the destination,
  whatever the client or IP.

## How it works

For each event, the Lambda:

1. **Classifies** the trigger into a message class.
2. **Checks exemptions** (exempt classes, and for email exempt domains, are
   sent without counting).
3. **Detects retries** with a conditional write keyed on the SHA-256 of the
   encrypted code. Lambda retries carry the same ciphertext, so a retry is sent
   without being counted again.
4. **Increments counters** in DynamoDB with atomic `UpdateItem` `ADD` calls,
   run in parallel. Throttled attempts still count.
5. **Decides**. A throttled message is logged and dropped, and the function
   returns success. Throttled messages never reach the policy or, for SMS, the
   SMS history.

Cognito invokes custom sender triggers asynchronously
([Lambda triggers](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-working-with-lambda-triggers.html)),
so the function can't fail or change the Cognito API call. The caller always
sees "code sent", including when the message is throttled.

| Class             | Trigger sources (`CustomEmailSender_` / `CustomSMSSender_`) | Default email limits  | Default SMS limits   |
| ----------------- | ----------------------------------------------------------- | --------------------- | -------------------- |
| `authentication`  | `Authentication`                                            | 5 per 15m, 20 per 24h | 5 per 15m, 10 per 24h |
| `signup`          | `SignUp`, `ResendCode`                                      | 3 per 1h, 10 per 24h  | 3 per 1h, 5 per 24h  |
| `forgot_password` | `ForgotPassword`                                            | 5 per 1h              | 3 per 1h, 5 per 24h  |
| `attribute`       | `UpdateUserAttribute`, `VerifyUserAttribute`                | 5 per 1h              | 3 per 1h             |
| `notification`    | `AccountTakeOverNotification` (email only)                  | 3 per 1h              | n/a                  |
| `admin`           | `AdminCreateUser`                                           | exempt                | exempt               |

The defaults are destination limits. Unknown trigger sources are sent,
logged, and reported with class `unknown`.

## Limits

- **Destination limits** count per normalized destination. Email addresses
  are trimmed and lowercased, `+tag` suffixes are removed, and dots are
  removed from Gmail local parts (`googlemail.com` is treated as
  `gmail.com`). Phone numbers are counted in E.164 form, so `+1 (206)
  555-0100` and `+12065550100` share a counter. Counter keys use the SHA-256
  of the normalized destination; the destination itself is never stored.
- **User limits** (optional) count per user, keyed on the `sub` attribute or
  the Cognito `userName`, hashed the same way.
- **Global limits** (optional) count all messages in a class. In `count`
  mode (the default) they log and emit a metric but never block. In
  `enforce` mode they throttle. Global counters are split across shards that
  are summed on read, so a burst doesn't overload one DynamoDB item. For SMS,
  a global limit is the main defense against SMS pumping, which spreads
  across many numbers.
- **Priority degrade**: in `enforce` mode, once a class's global count passes
  `degradeFraction` of its max, low-trust recipients are throttled first. A
  recipient is low trust when `cognito:user_status` is `UNCONFIRMED` or the
  destination isn't verified (`email_verified` or `phone_number_verified`
  isn't `"true"`). Cognito doesn't document which attributes each trigger
  includes, so a missing attribute counts as unverified.

Windows are fixed and aligned to the Unix epoch (a `24h` window resets at
00:00 UTC), so up to twice a limit can be sent across a window boundary. A
message is throttled when its count, including itself, is greater than `max`.

## Configuration

| Channel | Enable                              | Table                             | Overrides (optional JSON)      |
| ------- | ----------------------------------- | --------------------------------- | ------------------------------ |
| Email   | `APP_EMAIL_RATE_LIMIT_ENABLED=true` | `APP_EMAIL_RATE_LIMIT_TABLE_NAME` | `APP_EMAIL_RATE_LIMIT_CONFIG`  |
| SMS     | `APP_SMS_RATE_LIMIT_ENABLED=true`   | `APP_SMS_RATE_LIMIT_TABLE_NAME`   | `APP_SMS_RATE_LIMIT_CONFIG`    |

Email and SMS can use the same table: counters are keyed by channel. The
override document applies over the channel's defaults. Fields you omit keep
their defaults, but an entry under `classes` replaces that class's defaults
entirely. The config is validated at startup, and an invalid config stops
the Lambda from starting. When a channel's rate limiting is disabled its
config isn't read.

| Field                         | Description                                                               | Default                      |
| ----------------------------- | ------------------------------------------------------------------------- | ---------------------------- |
| `failMode`                    | `open` sends when DynamoDB fails; `closed` drops the message.             | `open`                       |
| `timeout`                     | Deadline for all rate limit calls per message (Go duration, at most `10s`). | `1s`                       |
| `dedupeTtl`                   | How long retry markers are kept (Go duration, at least `1m`).             | `6h`                         |
| `metricNamespace`             | CloudWatch namespace for metrics.                                         | `CognitoCustomMessageSender` |
| `userKey`                     | User limit key: `sub` or `userName`.                                      | `sub`                        |
| `normalize.stripPlusTag`      | Email only: remove `+tag` from the local part.                            | `true`                       |
| `normalize.stripGmailDots`    | Email only: remove dots from Gmail local parts.                           | `true`                       |
| `exempt.domains`              | Email only: destination domains that are never counted (exact match).     | `[]`                         |
| `exempt.classes`              | Classes that are never counted.                                           | `["admin"]`                  |
| `global.mode`                 | Global limit mode: `count` or `enforce`.                                  | `count`                      |
| `global.shards`               | Shards per global counter (1-100).                                        | `4`                          |
| `global.degradeFraction`      | Fraction of a global max where low-trust recipients are throttled (0-1].  | `0.8`                        |
| `classes.<class>.destination` | List of `{"window", "max"}` limits per destination.                       | see table above              |
| `classes.<class>.user`        | List of `{"window", "max"}` limits per user.                              | `[]`                         |
| `classes.<class>.global`      | List of `{"window", "max"}` limits for the whole class.                   | `[]`                         |
| `classes.<class>.globalMode`  | Overrides `global.mode` for one class.                                    | unset                        |

A window is a positive integer followed by `s`, `m`, `h`, or `d` (for example
`15m`, `24h`, `7d`). `max` must be a positive integer, and windows can't repeat
within one list.

Email example:

```json
{
  "failMode": "open",
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

SMS example, with a global cap on sign-in codes:

```json
{
  "global": { "mode": "enforce" },
  "classes": {
    "authentication": {
      "destination": [{ "window": "15m", "max": 3 }, { "window": "24h", "max": 10 }],
      "global": [{ "window": "1h", "max": 2000 }]
    }
  }
}
```

Global limits have no defaults because they depend on normal traffic. Run in
`count` mode first, then set a max above the observed peak before switching to
`enforce`.

## Retries and failures

- **Retries:** the first attempt is counted; Lambda retries of the same event
  are sent without counting again. Events with no code (account takeover
  notifications) are counted on every attempt.
- **Store errors:** if DynamoDB errors, throttles, or exceeds `timeout`, the
  message is sent (`failMode: open`) or dropped (`failMode: closed`), and the
  error is logged. A limit that is known to be exceeded still throttles when
  another counter fails.
- **Throttles never return an error,** so Lambda doesn't retry them.
- **Delivery failures do return an error,** so Lambda retries the event. The
  retry check above keeps a retried message from being counted twice.

Cognito codes expire within minutes, so a late message is rarely useful.
Consider lowering the function's asynchronous retry settings
([`maximum_event_age_in_seconds`, `maximum_retry_attempts`](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html)).

## DynamoDB table

The table needs a string partition key named `pk` and TTL enabled on the `ttl`
attribute. On-demand capacity is recommended. Items are small counters and
retry markers that expire one hour after their window ends.

```json
{
  "Effect": "Allow",
  "Action": ["dynamodb:UpdateItem", "dynamodb:PutItem", "dynamodb:BatchGetItem"],
  "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/cognito-rate-limit"
}
```

## Metrics

Each message writes one [CloudWatch Embedded Metric Format](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html)
record to the function's log, so metrics need no extra API calls. Records are
written at any `APP_LOG_LEVEL`. Dimensions are `class` and `decision`; no
dimension identifies a destination.

| Metric                                                         | Description                                                                     |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `EmailRateLimitDecision`, `SMSRateLimitDecision`               | One per message, by class and decision.                                         |
| `EmailRateLimitGlobalExceeded`, `SMSRateLimitGlobalExceeded`   | Messages that global limits throttle (`enforce`) or would throttle (`count`).   |

| Decision                | Meaning                                                        |
| ----------------------- | -------------------------------------------------------------- |
| `sent`                  | Within limits. The policy can still deny the message.          |
| `throttled_destination` | Dropped: a destination limit was exceeded.                     |
| `throttled_user`        | Dropped: a user limit was exceeded.                            |
| `throttled_global`      | Dropped: a global limit or priority degrade applied.           |
| `deduped`               | A Lambda retry; sent without counting.                         |
| `exempt`                | Exempt class or domain, or unknown trigger; sent.              |
| `fail_open`             | The store failed; sent.                                        |
| `fail_closed`           | The store failed; dropped.                                     |

Throttle logs include the masked destination (`u***@example.com`,
`+*******0100`) and its hash.

## Trade-offs

- A throttled recipient gets no message, while the API call that triggered it
  still succeeds. Users who request many codes may need to wait for the
  window to reset.
- Fixed windows allow short bursts at window boundaries.
- Each window is counted independently. When many messages to one
  destination arrive at the same moment, an attempt can be within one
  window's limit but over another's, so a burst can send fewer messages than
  the smallest limit. It never sends more.
- Destination hashes are unsalted SHA-256, so someone with table access can
  test whether a known address or phone number appears. Phone numbers in
  particular are easy to enumerate.
- Each counted message adds one conditional write and one update per
  configured window (plus one batch read for global limits), run in parallel
  after the retry check.

## Rate limits, the SMS history, and policies

When rate limiting is enabled, the policy receives the limiter's result as
`input.rateLimit`, so a policy can add its own denial on top of the limits,
for example while global limits are still in `count` mode. See
[policies](policies.md#email-policy-input) for the fields and
[`rate-limit.rego`](../examples/policies/email/rate-limit.rego) for an email
example.

The [SMS history](sms.md#history-table) predates SMS rate limiting: it
records each SMS and passes `input.history.recentAttempts` to the policy,
which then decides whether to block. The rate limiter is the better tool for
new deployments: it runs before the policy, supports several windows, users,
and global limits, and emits metrics. The history table is optional, so a
deployment can use either or both.
