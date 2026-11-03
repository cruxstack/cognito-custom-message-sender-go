// Command bootstrap is the AWS Lambda function for Cognito custom email and
// SMS sender triggers. Build it for the provided.al2023 runtime:
//
//	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags lambda.norpc -o bootstrap .
package main

import (
	"context"
	"log/slog"
	"os"
	"runtime/debug"

	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/app"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/logging"
)

// version is set at build time with -ldflags "-X main.version=v3.0.0".
var version = "dev"

func main() {
	var level slog.LevelVar
	slog.SetDefault(slog.New(logging.NewJSONHandler(os.Stdout, &level)))

	if err := run(context.Background(), &level); err != nil {
		slog.Error("startup failed", "version", version, "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, level *slog.LevelVar) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	level.Set(cfg.LogLevel)

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	h, err := app.New(ctx, cfg, awsCfg)
	if err != nil {
		return err
	}

	slog.Info("starting",
		"version", version,
		"revision", revision(),
		"email_enabled", cfg.Email.Enabled,
		"email_providers", cfg.Email.Providers,
		"sms_enabled", cfg.SMS.Enabled,
		"send_enabled", cfg.SendEnabled,
	)
	lambda.Start(h.Handle)
	return nil
}

// revision returns the VCS revision the binary was built from, if known.
func revision() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return "unknown"
}
