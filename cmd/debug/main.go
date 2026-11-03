package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/encryption"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/handler"
	"github.com/joho/godotenv"
)

func main() {
	dataPath := flag.String("data", "", "path to JSON file with test event data")
	policyPath := flag.String("policy", "", "override path to Rego policy file")
	smsPolicyPath := flag.String("sms-policy", "", "path to sms Rego policy file; enables the sms sender")
	flag.Parse()

	if err := run(context.Background(), *dataPath, *policyPath, *smsPolicyPath); err != nil {
		slog.Error("debug run failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dataPath, policyPath, smsPolicyPath string) error {
	var level slog.LevelVar
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: &level})))

	if err := godotenv.Load(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to load .env: %w", err)
	}

	os.Setenv("APP_DEBUG_MODE", "true")
	if os.Getenv("APP_KMS_KEY_ID") == "" {
		os.Setenv("APP_KMS_KEY_ID", encryption.MockKeyID)
	}
	if os.Getenv("APP_EMAIL_SENDER_POLICY_PATH") == "" {
		os.Setenv("APP_EMAIL_SENDER_POLICY_PATH", "fixtures/debug-policy.rego")
	}
	if policyPath != "" {
		os.Setenv("APP_EMAIL_SENDER_POLICY_PATH", policyPath)
	}
	if smsPolicyPath != "" {
		os.Setenv("APP_SMS_SENDER_ENABLED", "true")
		os.Setenv("APP_SMS_SENDER_POLICY_PATH", smsPolicyPath)
	}

	cfg, err := config.New()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	level.Set(cfg.AppLogLevel)

	h, err := handler.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize sender: %w", err)
	}

	dataPath = cmp.Or(dataPath, cfg.DebugDataPath, "fixtures/debug-data.json")
	data, err := os.ReadFile(dataPath)
	if err != nil {
		return fmt.Errorf("failed to read data file: %w", err)
	}

	var events []json.RawMessage
	if err := json.Unmarshal(data, &events); err != nil {
		return fmt.Errorf("failed to parse data file %s: %w", dataPath, err)
	}

	for i, e := range events {
		if err := h.Handle(ctx, e); err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
		slog.Info("event processed", "index", i)
	}

	slog.Info("all events processed", "count", len(events))
	return nil
}
