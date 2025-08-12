# Cognito Custom Message Sender

A flexible AWS Lambda–based solution to send policy-driven emails in response
to AWS Cognito events. It supports SES for delivery, optional SendGrid email
verification, and a local debug mode for integration testing without real
credentials or addresses. As an example, share a single userpool between
multiple sites and-or apps, but send specific emails (ses templates) that match
the respective site or app by returning different template-id based on the
caller's client-id.

## Features

* **AWS Lambda Integration**: Handle Cognito Custom Email Sender events and
  deliver emails based on OPA policies.
* **Policy-based Email Sending**: Evaluate Rego policies to allow or deny
  sending, and to customize template ID, data, source, and destination
  addresses.
* **SendGrid Verification (optional)**: Fetch and include SendGrid email
  verification data as policy input (disabled by default).
* **Local Debug Mode**: Run integration tests against example event data and
  policies, with mocked KMS decryption and dry-run sending.
* **Dry-run Support**: Log SES requests instead of sending when
  `APP_SEND_ENABLED=false` or in debug mode.

## Environment Variables

Configure your Lambda or local environment via environment variables:

| Variable                                    | Description                                                               | Default                           |
| ------------------------------------------- | ------------------------------------------------------------------------- | --------------------------------- |
| `APP_DEBUG_MODE`                            | `true` to enable debug mode (loads `.env`, mocks KMS and dry-run).        | `false`                           |
| `APP_DEBUG_DATA_PATH`                       | Path to JSON file containing array of Cognito event samples (for debug).  | `fixtures/debug-data.json`        |
| `APP_EMAIL_SENDER_POLICY_PATH`              | Path or S3 URI to the Rego policy file used by OPA.                       | **required**                      |
| `APP_KMS_KEY_ID`                            | KMS key ID for decrypting the Cognito code.                               | **required**                      |
| `APP_LOG_LEVEL`                             | Log level (`debug`, `info`, `warn`, `error`).                             | `info`                            |
| `APP_SEND_ENABLED`                          | `true` to send via SES, `false` to dry-run.                               | `true`                            |
| `APP_SENDGRID_API_KEY`                      | SendGrid API key for email verification.                                  | **required if enabling SendGrid** |
| `APP_SENDGRID_API_HOST`                     | Base URL for SendGrid API.                                                | `https://api.sendgrid.com`        |
| `APP_SENDGRID_EMAIL_VERIFICATION_ALLOWLIST` | List of email domains that automatically is validated as valid            | `""`                              |
| `APP_SENDGRID_EMAIL_VERIFICATION_ENABLED`   | `true` to include SendGrid verification in policy input, `false` to skip. | `false`                           |

> **Note:** `APP_SEND_ENABLED` is automatically set to `false` in debug mode unless explicitly overridden.

## SendGrid Email Verification (Optional)

SendGrid's email address verification API improves the security and reliability
of your Cognito workflows by proactively detecting invalid or risky email
addresses before attempting to send. This helps reduce bounce rates, avoid AWS
SES suppression, and prevent abuse by filtering out disposable, mistyped, or
role-based emails.

To include SendGrid verification results as input to your OPA policy:

1. Set `APP_SENDGRID_EMAIL_VERIFICATION_ENABLED=true`.
2. Provide `APP_SENDGRID_API_KEY` via environment. Optionally override host with
   `APP_SENDGRID_API_HOST`.
3. In your Rego policy, reference `input.emailVerification` fields (`valid`,
   `score`, `role`, `raw`).

Example policy snippet:

```rego
package cognito_custom_sender_email_policy

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
    "templateID": "verification-template",
    "templateData": {},
    "srcAddress": "noreply@example.com",
    "dstAddress": input.userAttributes.email
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
2. Build the debug binary:

   ```bash
   go run -C cmd/debug .
   ```

3. Override fixtures:

   ```bash
   go run -C cmd/debug -data path/to/events.json -policy path/to/policy.rego
   ```

This mode:

* Loads environment variables from `.env`.
* Mocks KMS decryption if `APP_KMS_KEY_ID=MOCKED_KEY_ID`.
* Dry-runs SES requests.
    - Set `APP_SEND_ENABLED=true` to explicitly enable SES sends

## Build & Deployment

1. Clone the repo:

   ```bash
   git clone https://github.com/cruxstack/cognito-custom-message-sender-go.git
   cd cognito-custom-message-sender-go
   ```
2. Build for Linux:

   ```bash
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bootstrap main.go
   ```
3. Package:

   ```bash
   zip deployment.zip bootstrap policy.rego
   ```
4. Deploy via AWS CLI, Terraform, or AWS Console as an `al2023provided.al2023`
   runtime, setting the required environment variables and IAM role with SES,
   KMS, and OPA policy access.

