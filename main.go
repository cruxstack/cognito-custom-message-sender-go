package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/handler"
)

func main() {
	var level slog.LevelVar
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: &level})))

	cfg, err := config.New()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}
	level.Set(cfg.AppLogLevel)

	h, err := handler.New(context.Background(), cfg)
	if err != nil {
		slog.Error("failed to initialize sender", "error", err)
		os.Exit(1)
	}

	lambda.Start(func(ctx context.Context, event json.RawMessage) error {
		if cfg.DebugMode {
			slog.DebugContext(ctx, "received event", "event", event)
		}

		return h.Handle(ctx, event)
	})
}
