# Email rate limiting

Rate limiting caps how many emails one address, one user, or one message class
can receive in a time window. It is off by default.

## Why

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

## How it works

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

## Limits

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

## Configuration

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

## Retries and failures

- **Retries:** the first attempt is counted; Lambda retries of the same event
  are sent without counting again. Events with no code (account takeover
  notifications) are counted on every attempt.
- **Store errors:** if DynamoDB errors, throttles, or exceeds `timeout`, the
  email is sent (`failMode: open`) or dropped (`failMode: closed`), and the
  error is logged. A limit that is known to be exceeded still throttles when
  another counter fails.
- **Throttles never return an error,** so Lambda doesn't retry them.
- **Delivery failures do return an error,** so Lambda retries the event. The
  retry check above keeps a retried email from being counted twice.

Cognito codes expire within minutes, so a late email is rarely useful. Consider
lowering the function's asynchronous retry settings
([`maximum_event_age_in_seconds`, `maximum_retry_attempts`](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html)).

## DynamoDB table

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

## Metrics

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

## Trade-offs

- A throttled recipient gets no email, while the API call that triggered it
  still succeeds. Users who request many codes may need to wait for the window
  to reset.
- Fixed windows allow short bursts at window boundaries.
- Each window is counted independently. When many emails to one address
  arrive at the same moment, an attempt can be within one window's limit but
  over another's, so a burst can send fewer emails than the smallest limit. It
  never sends more.
- Address hashes are unsalted SHA-256, so someone with table access can test
  whether a known address appears.
- Each counted email adds one conditional write and one update per configured
  window (plus one batch read for global limits), run in parallel after the
  retry check.

## Policy input

When rate limiting is enabled, the email policy receives the limiter's result
as `input.rateLimit`, so a policy can add its own denial on top of the
limits, for example while global limits are still in `count` mode. See
[policies](policies.md#email-policy-input) for the fields and
[`rate-limit.rego`](../examples/policies/email/rate-limit.rego) for an
example.
