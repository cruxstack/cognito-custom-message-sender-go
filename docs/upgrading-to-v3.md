# Upgrading to v3

v3 restructures the service and tightens its contracts. Most email policies
that use `allow.providers` keep working unchanged; configuration needs a few
renames. If you deploy with the
[Terraform module](https://github.com/cruxstack/terraform-aws-cognito-custom-message-sender),
upgrade the module to the major version that targets v3 instead of setting
these variables yourself.

Upgrade checklist:

1. Rename the environment variables below.
2. Check your email policy against the [policy changes](#policy-changes) and
   run it through `devtool eval` with a few sample events.
3. If you relied on failover swallowing errors, review the
   [behavior changes](#behavior-changes).
4. Pin the version you build. Building from a branch picks up breaking
   changes without warning.

## Configuration

v3 refuses to start when a removed variable is set to a non-empty value,
and names the replacement in the error.

| v2                                                  | v3                                                      |
| --------------------------------------------------- | ------------------------------------------------------- |
| `APP_EMAIL_PROVIDER=ses`                            | `APP_EMAIL_PROVIDERS=ses`                               |
| `APP_EMAIL_FAILOVER_ENABLED=true` and `APP_EMAIL_FAILOVER_PROVIDERS=sendgrid` | `APP_EMAIL_PROVIDERS=ses,sendgrid`  |
| `APP_EMAIL_FAILOVER_CACHE_TTL`                      | `APP_EMAIL_HEALTH_CHECK_TTL`                            |
| `APP_EMAIL_VERIFICATION_WHITELIST`                  | `APP_EMAIL_VERIFICATION_ALLOWLIST`                      |
| `APP_DEBUG_MODE`                                    | removed: use `APP_LOG_LEVEL=debug`, and `devtool` locally |
| `APP_DEBUG_DATA_PATH`                               | removed: use `devtool run -events`                      |
| `KMS_KEY_ID`                                        | `APP_KMS_KEY_ID`                                        |
| `APP_SENDGRID_API_KEY`                              | `APP_SENDGRID_EMAIL_VERIFICATION_API_KEY`               |

Other changes:

- **Invalid values are errors.** v2 logged a warning and used the default
  for an invalid boolean, log level, or duration (so `APP_SEND_ENABLED=flase`
  sent email). v3 refuses to start.
- **`APP_LOG_LEVEL`** accepts `debug`, `info`, `warn`, or `error`.
- **Table names are always required** when rate limiting or the SMS sender
  is enabled. v2 fell back to an in-memory store in debug mode.
- **`APP_EMAIL_VERIFICATION_PROVIDER`** must be `offline` or `sendgrid`. v2
  used `offline` for any unknown value.
- **`APP_EMAIL_VERIFICATION_ALLOWLIST`** applies to every verification
  provider, not only `sendgrid`.
- **`APP_SENDGRID_API_HOST`** applies to sending as well as verification, so
  EU accounts can send through `https://api.eu.sendgrid.com`.

## Policy changes

- **The top-level template was removed.** v1-style results with
  `allow.templateID` and `allow.templateData` are rejected. Move them under
  the provider:

  ```diff
   "allow": {
     "srcAddress": "no-reply@example.com",
     "dstAddress": input.userAttributes.email,
  -  "templateID": "acme-code",
  -  "templateData": {}
  +  "providers": {"ses": {"templateId": "acme-code", "templateData": {}}}
   }
  ```

- **Actions are validated.** The action must be `allow`, `deny`, or `block`.
  v2 treated any other value, including typos, as a denial.
- **Provider names are validated.** A key under `allow.providers` other than
  `ses` or `sendgrid` is an error.
- **`dstAddress` is optional** and defaults to the user's `email` attribute.
- **`emailVerification.score` is always 0 to 1.** v2 reported `100` for valid
  addresses with the `offline` provider and for allowlisted domains, but
  SendGrid's 0 to 1 score otherwise. Policies that compare the score to
  `100` need updating.
- **New input fields:** `userPoolId`, `region`, and `userName` in both
  policies; `emailVerification.provider`, `verdict`, `disposable`, and
  `role`. v2 declared `disposable` and `role` but never set them.
- **`clientMetadata` and `userAttributes` are `{}`, not `null`,** when the
  event has none.
- **Email verification no longer requires an `email` attribute.** v2
  returned an error (and Lambda retried) when verification was enabled and
  the attribute was missing; v3 skips verification and lets the policy
  decide.

## Behavior changes

- **Failed deliveries return an error.** With failover enabled, v2 returned
  success even when every provider failed, so the email was lost with no
  Lambda error, retry, or failure destination. v3 returns an error in
  every mode, so Lambda retries the event and the `Errors` metric reflects
  lost emails. Rate limiting doesn't count retries twice.
- **Failover no longer skips SES because a health check failed.** SES is
  skipped only when `GetAccount` reports that sending is paused, and even
  then it is tried last instead of not at all.
- **Temporary passwords are unescaped.** Cognito HTML-escapes characters
  such as `<` and `>` in temporary passwords. v2 sent them escaped
  (`&lt;`), so users couldn't sign in with the password they received.
- **SES sends with the SESv2 `SendEmail` API.** The role needs
  `ses:SendEmail`; `ses:SendTemplatedEmail` is no longer used.
- **Logs mask email addresses** (`u***@example.com`) and carry `request_id`,
  `trigger`, `user_pool_id`, and `client_id`.

## Building

- The Go module path is now `github.com/cruxstack/cognito-custom-message-sender-go/v3`.
- `cmd/debug` was replaced by `cmd/devtool` (`eval` and `run`); see the
  [README](../README.md#local-development).
- Releases include prebuilt `bootstrap` binaries for `linux/arm64` and
  `linux/amd64`, with checksums.
