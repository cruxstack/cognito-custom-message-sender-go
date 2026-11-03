# SMS sender

The SMS sender handles `CustomSMSSender_*` events and sends through Amazon SNS.
It is a port of the Node.js SMS sender from
[terraform-aws-cognito-custom-message-sender](https://github.com/cruxstack/terraform-aws-cognito-custom-message-sender),
and keeps its policy input and output, history table, and code placeholder, so
existing policies and tables keep working.

## How it works

1. The `phone_number` attribute is parsed with libphonenumber metadata. A
   number that can't be parsed or doesn't map to a country is logged and
   dropped.
2. If [rate limiting](rate-limiting.md) is enabled
   (`APP_SMS_RATE_LIMIT_ENABLED`), the SMS is counted against the limits for
   its number, user, and class, and dropped when a limit is exceeded.
3. If the history table is configured (`APP_SMS_HISTORY_TABLE_NAME`), the
   attempt is saved, then the attempts to that phone number within
   `APP_SMS_THROTTLE_PERIOD` are counted, including this one.
4. The policy evaluates the event and returns `allow` with the message, or
   `deny` (or `block`) with a reason.
5. If allowed, the code is decrypted with KMS and replaces the first `{####}`
   in the message.
6. The message is published with `sns:Publish`.

History errors are logged and don't stop the send (the count is `0`).
Invalid phone numbers, throttles, and policy denials return success, so
Lambda doesn't retry them; policy, decryption, and SNS errors return an
error, so Lambda retries.

Use rate limiting to protect against SMS pumping and code flooding; see
[rate limiting](rate-limiting.md#rate-limits-the-sms-history-and-policies)
for how it compares with the history table.

## Policy

The policy is read from `APP_SMS_SENDER_POLICY_PATH` and must define
`data.cognito_custom_sender_sms_policy.result`. Rego v1 is recommended; Rego v0
policies, which the Node.js sender required, are still accepted with a
warning. The input and result are described in
[policies](policies.md#sms-policy), and
[`throttle.rego`](../examples/policies/sms/throttle.rego) is a complete
example.

## History table

The history table is optional. Without it, the policy input has no
`history`. The table uses the same layout as the Node.js sender:

| Key                                     | Attributes                                       |
| --------------------------------------- | ------------------------------------------------ |
| Table hash and range key                | `historyId` (S), `sentAtEpoch` (N, epoch millis) |
| `userPhoneNumber-index` (GSI, required) | `userPhoneNumber` (S), `sentAtEpoch` (N)         |
| `userSid-index` (GSI, optional)         | `userId` (S), `sentAtEpoch` (N)                  |

Each item also stores the trigger, phone number country, email address,
`sentAt` (ISO 8601), and `ttl` (epoch seconds). Enable TTL on `ttl`. Items
include the phone number and email address in plain text, because the count is
queried by phone number.

## IAM permissions

```jsonc
[
  { "Effect": "Allow", "Action": "sns:Publish", "Resource": "*" },
  { "Effect": "Allow", "Action": "kms:Decrypt", "Resource": "arn:aws:kms:us-east-1:123456789012:key/EXAMPLE" },
  // with rate limiting
  {
    "Effect": "Allow",
    "Action": ["dynamodb:UpdateItem", "dynamodb:PutItem", "dynamodb:BatchGetItem"],
    "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/example-rate-limit"
  },
  // with the history table
  {
    "Effect": "Allow",
    "Action": ["dynamodb:PutItem", "dynamodb:Query"],
    "Resource": [
      "arn:aws:dynamodb:us-east-1:123456789012:table/example-sms-history",
      "arn:aws:dynamodb:us-east-1:123456789012:table/example-sms-history/index/*"
    ]
  }
]
```

## Migrating from the Node.js sender

| Node.js variable                 | Go variable                  | Notes                                     |
| -------------------------------- | ---------------------------- | ----------------------------------------- |
| `SMS_SENDER_ENABLED`             | `APP_SMS_SENDER_ENABLED`     | Defaults to `false` here.                 |
| `SMS_SENDER_POLICY_PATH`         | `APP_SMS_SENDER_POLICY_PATH` | A `.rego` file instead of `policy.wasm`.  |
| `DDB_TABLE_HISTORY_NAME`         | `APP_SMS_HISTORY_TABLE_NAME` |                                           |
| `DDB_TABLE_HISTORY_TTL`          | `APP_SMS_HISTORY_TTL`        | Go duration instead of minutes.           |
| `SMS_THROTTLE_PERIOD_IN_MINUTES` | `APP_SMS_THROTTLE_PERIOD`    | Go duration instead of minutes.           |
| `KMS_KEY_ID`                     | `APP_KMS_KEY_ID`             |                                           |
| `LOG_LEVEL`                      | `APP_LOG_LEVEL`              |                                           |

For an SMS-only function, also set `APP_EMAIL_SENDER_ENABLED=false`. Other
differences:

- **History TTL:** `ttl` is written in epoch seconds. The Node.js sender wrote
  epoch milliseconds, which DynamoDB TTL treats as a date far in the future,
  so those items never expired.
- **Missing `sub`:** the `userId` attribute is omitted instead of written as an
  empty string, which DynamoDB rejects for index keys.
- **Phone validation:** `phoneNumberData.isValid` checks digits against full
  libphonenumber metadata. The Node.js sender's default metadata only checked
  length, so its `isValid` matched `isPossible`; policies that block on
  `isValid` can now block more numbers.
- **Policy result:** the action must be `allow`, `deny`, or `block` (an
  alias for `deny`); any other value, or a result without an `action`, is an
  error.
- **Logs:** phone numbers are masked (`+*******0100`).
- **Dry run:** `APP_SEND_ENABLED=false` also skips SNS.
