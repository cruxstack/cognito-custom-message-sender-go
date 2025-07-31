package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/charmbracelet/log"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/sender"
)

var (
	cfg    sender.SenderConfig
	dryRun bool
)

func Handler(ctx context.Context, event sender.CognitoEventUserPoolsCustomEmailSender) error {
	if os.Getenv("DEBUG_MODE") == "true" {
		evtJson, err := json.Marshal(event)
		if err != nil {
			log.Error("issue marshalling event: %v", err)
		}
		log.Print(string(evtJson))
	}

	err := sender.SendEmail(ctx, event, &cfg, dryRun)
	if err != nil {
		log.Error("failed to send email", "error", err)
		return err
	}

	return nil
}

func main() {
	logLevel, _ := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	log.SetLevel(logLevel)

	cfg = sender.SenderConfig{
		KMSKeyID:   os.Getenv("KMS_KEY_ID"),
		PolicyPath: os.Getenv("EMAIL_SENDER_POLICY_PATH"),
	}

	dryRun = os.Getenv("DRY_RUN") == "true"

	lambda.Start(Handler)
}
