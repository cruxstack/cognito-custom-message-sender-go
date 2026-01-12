# Cognito Custom Message Sender

## What

An AWS Lambda function that sends policy-driven emails in response to AWS
Cognito events. It supports AWS SES and SendGrid for delivery, with optional
SendGrid email verification and automatic failover between providers.

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

## How It Works

1. Cognito triggers the Lambda with a Custom Email Sender event
2. The Lambda decrypts the verification code using KMS
3. An OPA/Rego policy evaluates the event and returns:
   - **Allow**: with template ID, template data, and addresses
   - **Deny**: with a reason (email is not sent)
4. If allowed, the email is sent via SES or SendGrid

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

- **IAM permissions**: KMS decrypt, SES send (if using SES)
- **Environment variables**: see table below
- **Cognito**: set as Custom Email Sender trigger

### Environment Variables

| Variable                                  | Description                                        | Default                      |
| ----------------------------------------- | -------------------------------------------------- | ---------------------------- |
| `APP_EMAIL_SENDER_POLICY_PATH`            | Path to the Rego policy file.                      | **required**                 |
| `APP_KMS_KEY_ID`                          | KMS key ID for decrypting Cognito codes.           | **required**                 |
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
  }
}
```

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
│   ├── aws/            # AWS SDK wrappers (KMS, SES)
│   ├── config/         # Environment configuration
│   ├── encryption/     # KMS decryption
│   ├── opa/            # Policy evaluation
│   ├── providers/      # Email providers (SES, SendGrid)
│   ├── sender/         # Core send logic
│   ├── templates/      # Template handling
│   ├── types/          # Shared types
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
- Mocked KMS (`APP_KMS_KEY_ID=MOCKED_KEY_ID`)
- Mock email provider to capture sends

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

| Variable              | Description                            | Default                    |
| --------------------- | -------------------------------------- | -------------------------- |
| `APP_DEBUG_MODE`      | Enable debug mode.                     | `false`                    |
| `APP_DEBUG_DATA_PATH` | Path to JSON file with Cognito events. | `fixtures/debug-data.json` |

## Deprecated Variables

| Deprecated             | Use Instead                               |
| ---------------------- | ----------------------------------------- |
| `APP_SENDGRID_API_KEY` | `APP_SENDGRID_EMAIL_VERIFICATION_API_KEY` |
| `KMS_KEY_ID`           | `APP_KMS_KEY_ID`                          |
