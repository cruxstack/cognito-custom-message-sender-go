# Cognito Custom Message Sender

A flexible AWS Lambda–based solution to send policy-driven emails in response
to AWS Cognito events. It supports both AWS SES and SendGrid for delivery,
optional SendGrid email verification, and a local debug mode for integration
testing without real credentials or addresses. As an example, share a single
userpool between multiple sites and-or apps, but send specific emails (templates)
that match the respective site or app by returning different template-id based
on the caller's client-id.

## Features

* **AWS Lambda Integration**: Handle Cognito Custom Email Sender events and
  deliver emails based on OPA policies.
* **Multiple Email Providers**: Support for both AWS SES and SendGrid as email
  delivery providers.
* **Policy-based Email Sending**: Evaluate Rego policies to allow or deny
  sending, and to customize template ID, data, source, and destination
  addresses.
* **SendGrid Email Verification (optional)**: Fetch and include SendGrid email
  verification data as policy input (disabled by default).
* **Local Debug Mode**: Run integration tests against example event data and
  policies, with mocked KMS decryption and dry-run sending.
* **Dry-run Support**: Log email requests instead of sending when
  `APP_SEND_ENABLED=false` or in debug mode.
* **Offline E2E Tests**: Comprehensive test suite with mocked external services.

## Environment Variables

Configure your Lambda or local environment via environment variables:

| Variable                                    | Description                                                               | Default                    |
| ------------------------------------------- | ------------------------------------------------------------------------- | -------------------------- |
| `APP_DEBUG_MODE`                            | `true` to enable debug mode (loads `.env`, mocks KMS and dry-run).        | `false`                    |
| `APP_DEBUG_DATA_PATH`                       | Path to JSON file containing array of Cognito event samples (for debug).  | `fixtures/debug-data.json` |
| `APP_EMAIL_SENDER_POLICY_PATH`              | Path to the Rego policy file used by OPA.                                 | **required**               |
| `APP_EMAIL_PROVIDER`                        | Email provider to use: `ses` or `sendgrid`.                               | `ses`                      |
| `APP_KMS_KEY_ID`                            | KMS key ID for decrypting the Cognito code.                               | **required**               |
| `APP_LOG_LEVEL`                             | Log level (`debug`, `info`, `warn`, `error`).                             | `info`                     |
| `APP_SEND_ENABLED`                          | `true` to send emails, `false` to dry-run.                                | `true`                     |
| `APP_EMAIL_VERIFICATION_ENABLED`            | `true` to include SendGrid verification in policy input, `false` to skip. | `false`                    |
| `APP_EMAIL_VERIFICATION_WHITELIST`          | Comma-separated list of email domains that skip API verification.         | `""`                       |
| `APP_SENDGRID_API_HOST`                     | Base URL for SendGrid API.                                                | `https://api.sendgrid.com` |
| `APP_SENDGRID_EMAIL_VERIFICATION_API_KEY`   | SendGrid API key for email verification.                                  | **required if verifying**  |
| `APP_SENDGRID_EMAIL_SEND_API_KEY`           | SendGrid API key for sending emails.                                      | **required if sendgrid**   |

> **Note:** `APP_SEND_ENABLED` is automatically set to `false` in debug mode unless explicitly overridden.

> **Deprecated:** `APP_SENDGRID_API_KEY` and `KMS_KEY_ID` are deprecated. Use
> `APP_SENDGRID_EMAIL_VERIFICATION_API_KEY` and `APP_KMS_KEY_ID` respectively.

## SendGrid Email Verification (Optional)

SendGrid's email address verification API improves the security and reliability
of your Cognito workflows by proactively detecting invalid or risky email
addresses before attempting to send. This helps reduce bounce rates, avoid AWS
SES suppression, and prevent abuse by filtering out disposable, mistyped, or
role-based emails.

To include SendGrid verification results as input to your OPA policy:

1. Set `APP_EMAIL_VERIFICATION_ENABLED=true`.
2. Provide `APP_SENDGRID_EMAIL_VERIFICATION_API_KEY` via environment. Optionally
   override host with `APP_SENDGRID_API_HOST`.
3. In your Rego policy, reference `input.emailVerification` fields (`valid`,
   `score`, `role`, `raw`).

Example policy snippet:

```rego
package cognito_custom_sender_email_policy
import rego.v1

result := deny_result {
  input.emailVerification != null
  not input.emailVerification.valid
}

result := allow_result {
  not deny_result
}

allow_result := {
  "action": "allow",
  "allow": {
    "srcAddress": "noreply@example.com",
    "dstAddress": input.userAttributes.email,
    "providers": {
      "ses": {
        "templateID": "verification-template",
        "templateData": {}
      }
    }
  }
}

deny_result := {
  "action": "deny",
  "reason": "email verification failed"
}
```

## OPA Policy Input

The Rego policy receives a single `input` object with the following shape:

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
  // only available if sendgrid is enabled
  "emailVerification": {
    "valid": true,
    "score": 0.97,
    "raw": "{...raw sendgrid response...}"
  }
}
```

> `emailVerification` is omitted if SendGrid verification is disabled.

The Rego policy must return a single object at `data.cognito_custom_sender_email_policy.result`
with the following shape:

* Deny example:

```json
{
  "action": "deny",
  "reason": "email verification failed"
}
```

* Allow example:

```jsonc
{
  "action": "allow",
  "allow": {
    "srcAddress": "noreply@example.org",
    "dstAddress": "user@example.org",
    "providers": {
      // email provider specific data
      "sendgrid": {
        "templateId": "d-xxxxxxxxxxxxxxxxxx",
        "templateData": {
          "code": "123456"
        }
      },
      "ses": {
        "templateId": "your-ses-template-id",
        "templateData": {
          "code": "123456"
        }
      }
    }
  }
}
```

## Debug Mode & Local Integration Tests

Use the `cmd/debug` utility to run against local fixtures without real emails or
KMS:

1. Copy or modify `.env.example` to `.env` and adjust values.
2. Run the debug utility:

   ```bash
   make debug
   ```

   Or with custom fixtures:

   ```bash
   go run ./cmd/debug -data path/to/events.json -policy path/to/policy.rego
   ```

This mode:

* Loads environment variables from `.env`.
* Mocks KMS decryption if `APP_KMS_KEY_ID=MOCKED_KEY_ID`.
* Dry-runs email requests (both SES and SendGrid).
    - Set `APP_SEND_ENABLED=true` to explicitly enable email sends

## Testing

Run the test suite using Make:

```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run e2e/integration tests only
make test-e2e
```

The e2e tests in `e2e/sender_test.go` are fully offline and use:

* **httptest mock server** for SendGrid email verification API
* **Mock provider** to capture and verify sent emails
* **Mocked KMS** via `APP_KMS_KEY_ID=MOCKED_KEY_ID`
* **Existing fixtures** (`fixtures/debug-policy.rego`) for policy evaluation

Test scenarios include:
* Policy allows/denies email based on verification results
* Different client IDs map to different templates
* Whitelisted domains skip API verification
* All Cognito trigger types (SignUp, ForgotPassword, etc.)
* Error handling for missing attributes

## Build & Deployment

1. Clone the repo:

   ```bash
   git clone https://github.com/cruxstack/cognito-custom-message-sender-go.git
   cd cognito-custom-message-sender-go
   ```
2. Build for Linux:

   ```bash
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bootstrap main.go
   ```
3. Package:

   ```bash
   zip deployment.zip bootstrap policy.rego
   ```
4. Deploy via AWS CLI, Terraform, or AWS Console as a `provided.al2023`
   runtime, setting the required environment variables and IAM role with
   appropriate permissions (SES/SendGrid, KMS).
