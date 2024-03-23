package sender

import (
	"context"
	"errors"
	"fmt"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/aws"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/encryption"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/opa"
)

func SendEmail(ctx context.Context, event CognitoEventUserPoolsCustomEmailSender, cfg *SenderConfig, dryRun bool) error {
	aws, err := aws.NewAWSClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create AWS client: %w", err)
	}

	code, err := encryption.Decrypt(ctx, cfg.KMSKeyID, event.Request.Code)
	if err != nil {
		return fmt.Errorf("failed to decrypt verification code: %w", err)
	}

	data, err := getEmailData(ctx, event, cfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("failed to get email data: %w", err)
	}

	templateData := mergeTemplateData(data.TemplateData, map[string]interface{}{"code": code})

	err = aws.SES.SendEmail(ctx, data.TemplateID, templateData, data.SourceAddress, data.DestinationAddress, dryRun)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func mergeTemplateData(base, additional map[string]interface{}) map[string]interface{} {
	for k, v := range additional {
		base[k] = v
	}
	return base
}

// getEmailData retrieves the email data based on a policy evaluation.
func getEmailData(ctx context.Context, event CognitoEventUserPoolsCustomEmailSender, policyPath string) (EmailData, error) {
	policyInput := PolicyInput{
		Trigger:        event.TriggerSource,
		UserAttributes: event.Request.UserAttributes,
		ClientMetadata: event.Request.ClientMetadata,
	}

	result, err := opa.EvaluatePolicy(ctx, policyPath, policyInput)
	if err != nil {
		return EmailData{}, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	action, ok := result["action"].(string)
	if !ok || action != "allow" {
		return EmailData{}, errors.New("action not allowed or missing")
	}

	allow, ok := result["allow"].(map[string]interface{})
	if !ok {
		return EmailData{}, errors.New("invalid format for 'allow' in policy result")
	}

	emailData, err := parseEmailData(allow)
	if err != nil {
		return EmailData{}, fmt.Errorf("failed to parse email data: %w", err)
	}

	return emailData, nil
}

func parseEmailData(data map[string]interface{}) (EmailData, error) {
	dstAddress, ok := data["dstAddress"].(string)
	if !ok {
		return EmailData{}, errors.New("destination address missing or invalid")
	}
	srcAddress, ok := data["srcAddress"].(string)
	if !ok {
		return EmailData{}, errors.New("source address missing or invalid")
	}
	templateID, ok := data["templateID"].(string)
	if !ok {
		return EmailData{}, errors.New("template ID missing or invalid")
	}
	templateData, ok := data["templateData"].(map[string]interface{})
	if !ok {
		return EmailData{}, errors.New("template data missing or invalid")
	}

	return EmailData{
		DestinationAddress: dstAddress,
		SourceAddress:      srcAddress,
		TemplateID:         templateID,
		TemplateData:       templateData,
	}, nil
}
