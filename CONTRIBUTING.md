# Contributing

## Setup

You need Go (the version in `go.mod`) and `make`. Nothing else: linters and
the vulnerability checker run with `go run` at pinned versions, and every
test runs offline. A [dev container](.devcontainer/devcontainer.json) is
included if you prefer one.

```sh
make help     # list targets
make check    # lint, test, and vulnerability check, as CI runs them
```

## Layout

```text
main.go             Lambda entry point
cmd/devtool/        local CLI (eval policies, run events)
internal/           the service; see docs/architecture.md
e2e/                end-to-end tests through the real wiring
examples/policies/  example policies, tested by examples/examples_test.go
examples/events/    sample Cognito events
docs/               user documentation
```

## Tests

- `make test` runs everything with the race detector.
- `make test-e2e` runs the end-to-end tests. They build the service with
  `app.New` from environment-style configuration and replace only the AWS
  clients, KMS, the DynamoDB stores, and the SendGrid API. Prefer adding an
  end-to-end test for behavior a user would notice.
- `make test-policies` checks every example policy against the sample events
  and runs their Rego unit tests. A new example policy needs expectations in
  `examples/examples_test.go`.
- `make test-dynamodb` runs the DynamoDB store tests against
  [DynamoDB Local](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html)
  (`docker run -p 8000:8000 amazon/dynamodb-local`).

To try a change by hand, `make run` sends the sample events through the full
sender in dry-run mode with the settings in `.env` (copy `.env.example`).

## Conventions

- Configuration is read only in `internal/config`, and dependencies are
  built only in `internal/app`. Other packages take what they need as
  arguments or small interfaces.
- Every new environment variable is validated at startup and documented in
  `docs/configuration.md`. A change to the policy input or result is
  documented in `docs/policies.md`.
- Logs use `slog` with snake_case keys and the request context
  (`slog.InfoContext(ctx, ...)`), and never include unmasked addresses,
  phone numbers, or codes.

## Commits and releases

Pull request titles follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, ...); a check enforces it. Each merge to `main` is
tagged and released automatically: `fix:` and similar bump the patch
version, `feat:` the minor version, and a `!` (`feat!:`) or a
`BREAKING CHANGE:` footer the major version. Releases attach
`bootstrap_linux_arm64.zip`, `bootstrap_linux_amd64.zip`, and
`checksums.txt`.

Breaking changes to configuration or the policy contract affect the
[Terraform module](https://github.com/cruxstack/terraform-aws-cognito-custom-message-sender),
which builds this repository at a pinned tag. Release the module change
alongside, and add the change to the upgrade guide.
