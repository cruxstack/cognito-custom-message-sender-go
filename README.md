# Cognito Custom Message Sender

An AWS Lambda function for the Amazon Cognito
[custom email](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-email-sender.html)
and [custom SMS](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-sms-sender.html)
sender triggers. A [Rego](https://www.openpolicyagent.org/docs/policy-language)
policy you write decides, for every message Cognito sends, whether to send it
and with which template, sender, and provider.

The easiest way to deploy it is the
[terraform-aws-cognito-custom-message-sender](https://github.com/cruxstack/terraform-aws-cognito-custom-message-sender)
module.

## Features

- **Policy-driven messages.** Pick templates, branding, and sender addresses
  by app client, trigger, user attribute, or client metadata, so one user
  pool can serve several apps. Deny messages you don't want to send.
- **Email through Amazon SES or SendGrid,** with ordered failover when a
  provider fails or SES sending is paused.
- **Email verification** before sending: an offline syntax check, or the
  SendGrid Email Address Validation API (disposable and role address
  detection).
- **SMS through Amazon SNS.** Policies and history tables from the earlier
  Node.js SMS sender keep working.
- **Rate limiting** for email and SMS per destination, per user, and per
  message class, backed by DynamoDB, to stop code floods and SMS pumping.
- **Safe by default:** configuration is validated at startup, codes are
  decrypted only for messages that will be sent, and logs mask personal data.

## How it works

1. Cognito invokes the function with the event and a code encrypted with
   your KMS key.
2. Optional rate limiting (and, for email, address verification) runs first.
3. Your policy evaluates the event and returns `allow` (with the template to
   use) or `deny`.
4. If allowed, the code is decrypted and sent with your template.

```rego
package cognito_custom_sender_email_policy

import rego.v1

result := {
	"action": "allow",
	"allow": {
		"srcAddress": "ACME <no-reply@example.com>",
		"providers": {"ses": {"templateId": "acme-code", "templateData": {"appName": "ACME"}}},
	},
}
```

The code is added to the template data as `code`. See
[policies](docs/policies.md) for the full input and result, and
[`examples/policies`](examples/policies) for tested examples.

## Deploying

### With Terraform

```hcl
module "cognito_message_sender" {
  source  = "cruxstack/cognito-custom-message-sender/aws"
  version = "~> 4.0" # module v4 runs v3 of this function of this function

  email_sender_enabled        = true
  email_sender_policy_content = file("${path.module}/policy.rego")

  sms_sender_enabled        = true
  sms_sender_policy_content = file("${path.module}/sms-policy.rego")
}
```

### By hand

1. Download `bootstrap_linux_arm64.zip` (or `amd64`) from the
   [latest release](https://github.com/cruxstack/cognito-custom-message-sender-go/releases/latest),
   or build it with `make build`.
2. Add your policy to the zip: `zip bootstrap_linux_arm64.zip policy.rego`.
   (`make package POLICY=policy.rego` builds and zips in one step.)
3. Create a Lambda function with the `provided.al2023` runtime, the matching
   architecture, and handler `bootstrap`. Give its role the
   [IAM permissions](docs/configuration.md#iam-permissions) for the features
   you use.
4. Set the [environment variables](docs/configuration.md); at minimum:

   ```sh
   APP_KMS_KEY_ID=arn:aws:kms:us-east-1:111122223333:key/...
   APP_EMAIL_SENDER_POLICY_PATH=policy.rego
   ```

5. Allow `cognito-idp.amazonaws.com` to invoke the function, and set it as
   the user pool's `CustomEmailSender` (and `CustomSMSSender`) trigger along
   with the pool's `KMSKeyID`.

## Local development

Evaluate a policy against sample events, with no AWS access:

```sh
go run ./cmd/devtool eval \
  -email-policy examples/policies/email/route.rego \
  -events examples/events/email.json
```

Run events through the whole sender in dry-run mode, with your `.env`:

```sh
cp .env.example .env
make run
```

`make help` lists the other targets; [CONTRIBUTING](CONTRIBUTING.md) covers
tests and conventions.

## Documentation

| Document                                       | Covers                                                    |
| ---------------------------------------------- | --------------------------------------------------------- |
| [Configuration](docs/configuration.md)         | Environment variables, failover, IAM, Lambda settings.    |
| [Policies](docs/policies.md)                   | Policy input and result, writing and testing policies.    |
| [Rate limiting](docs/rate-limiting.md)         | Email and SMS rate limits, the DynamoDB table, metrics.   |
| [SMS sender](docs/sms.md)                      | SMS history, phone numbers, migrating from Node.js.       |
| [Architecture](docs/architecture.md)           | Packages, the request flow, and failure handling.         |
| [Upgrading to v3](docs/upgrading-to-v3.md)     | Breaking changes from v2.                                 |

## License

[MIT](LICENSE)
