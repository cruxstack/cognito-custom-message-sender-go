package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/charmbracelet/log"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/aws"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/sender"
)

var (
	s *sender.Sender
)

func Handler(ctx context.Context, event aws.CognitoEventUserPoolsCustomEmailSender) error {
	if os.Getenv("DEBUG_MODE") == "true" {
		evtJson, err := json.Marshal(event)
		if err != nil {
			log.Error("issue marshalling event: %v", err)
		}
		log.Print(string(evtJson))
	}

	err := s.SendEmail(ctx, event)
	if err != nil {
		log.Error("failed to send email", "error", err)
		return err
	}

	return nil
}

func main() {
	cfg, err := config.New()
	if err != nil {
		fmt.Printf("configuration error: %s", err)
		os.Exit(1)
	}
	log.SetLevel(cfg.AppLogLevel)

	s, err = sender.NewSender(context.Background(), cfg)
	if err != nil {
		fmt.Printf("sender init error: %s", err)
		os.Exit(1)
	}

	lambda.Start(Handler)
}
