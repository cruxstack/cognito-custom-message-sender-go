package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/aws"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/sender"
)

var (
	s *sender.Sender
)

func Handler(ctx context.Context, event aws.CognitoEventUserPoolsCustomEmailSender) error {
	if os.Getenv("APP_DEBUG_MODE") == "true" {
		evtJson, err := json.Marshal(event)
		if err != nil {
			slog.ErrorContext(ctx, "failed to marshal event", "error", err)
		}
		slog.DebugContext(ctx, "received event", "event", string(evtJson))
	}

	err := s.SendEmail(ctx, event)
	if err != nil {
		slog.ErrorContext(ctx, "failed to send email", "error", err)
		return err
	}

	return nil
}

func main() {
	cfg, err := config.New()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.AppLogLevel})
	slog.SetDefault(slog.New(handler))

	s, err = sender.NewSender(context.Background(), cfg)
	if err != nil {
		slog.Error("failed to initialize sender", "error", err)
		os.Exit(1)
	}

	lambda.Start(Handler)
}
