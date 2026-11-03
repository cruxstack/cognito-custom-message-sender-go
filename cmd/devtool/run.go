package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/app"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/decrypt"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/ratelimit"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/sms"
)

// localDefaults fill in settings a local run doesn't need for real, so the
// configuration validates without AWS resources.
var localDefaults = map[string]string{
	"APP_LOG_LEVEL":                   "debug",
	"APP_KMS_KEY_ID":                  "arn:aws:kms:us-east-1:111122223333:key/local",
	"APP_EMAIL_RATE_LIMIT_TABLE_NAME": "local",
	"APP_SMS_HISTORY_TABLE_NAME":      "local",
}

func runCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	eventsPath := fs.String("events", "", "JSON file with an event or an array of events (required)")
	envFile := fs.String("env", ".env", "dotenv file to load; variables already set take precedence")
	send := fs.Bool("send", false, "send messages for real (sets APP_SEND_ENABLED=true)")
	useAWS := fs.Bool("aws", false, "decrypt codes with KMS and use the DynamoDB tables instead of plaintext codes and in-memory stores")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *eventsPath == "" {
		fs.Usage()
		return errors.New("-events is required")
	}

	if err := loadDotEnv(*envFile); err != nil {
		return err
	}

	cfg, err := config.Load(func(key string) (string, bool) {
		if key == "APP_SEND_ENABLED" {
			return strconv.FormatBool(*send), true
		}
		if v, ok := os.LookupEnv(key); ok && v != "" {
			return v, true
		}
		v, ok := localDefaults[key]
		return v, ok
	})
	if err != nil {
		return err
	}
	slog.SetDefault(newLogger(os.Stderr, cfg.LogLevel))

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	var opts []app.Option
	if !*useAWS {
		opts = append(opts,
			app.WithDecrypter(decrypt.Plaintext{}),
			app.WithRateLimitStore(ratelimit.NewMemoryStore()),
			app.WithSMSHistory(sms.NewMemoryHistory()),
		)
	}

	h, err := app.New(ctx, cfg, awsCfg, opts...)
	if err != nil {
		return err
	}

	events, err := readEvents(*eventsPath)
	if err != nil {
		return err
	}

	failed := 0
	for i, e := range events {
		if err := h.Handle(ctx, e); err != nil {
			failed++
			slog.Error("event failed", "index", i, "error", err)
			continue
		}
		slog.Info("event handled", "index", i)
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d events failed", failed, len(events))
	}
	return nil
}
