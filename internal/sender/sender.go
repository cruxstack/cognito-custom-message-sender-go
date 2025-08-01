package sender

import (
	"context"
	"errors"
	"fmt"

	"github.com/charmbracelet/log"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/aws"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/encryption"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/opa"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/verifier"
)

type Sender struct {
	Config        *config.Config
	SES           *aws.SESClient
	KMS           *aws.KMSClient
	EmailVerifier verifier.EmailVerifier
}

func NewSender(ctx context.Context, cfg *config.Config) (*Sender, error) {
	aws, err := aws.NewAWSClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS client: %w", err)
	}

	verifier, err := verifier.NewSendGridVerifier(cfg)
	if err != nil {
		return nil, fmt.Errorf("sendgrid init error: %s\n", err)
	}

	return &Sender{
		Config:        cfg,
		KMS:           aws.KMS,
		SES:           aws.SES,
		EmailVerifier: verifier,
	}, nil
}

func (s *Sender) SendEmail(ctx context.Context, event aws.CognitoEventUserPoolsCustomEmailSender) error {
	code, err := encryption.Decrypt(ctx, s.Config.AppKmsKeyId, event.Request.Code)
	if err != nil {
		return fmt.Errorf("failed to decrypt verification code: %w", err)
	}

	data, err := s.GetEmailData(ctx, event)
	if err != nil {
		return fmt.Errorf("failed to get email data: %w", err)
	}

	if data == nil {
		return nil
	}

	templateData := s.MergeTemplateData(data.TemplateData, map[string]any{"code": code})

	err = s.SES.SendEmail(ctx, data.TemplateID, templateData, data.SourceAddress, data.DestinationAddress, !s.Config.AppSendEnabled)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (s *Sender) MergeTemplateData(base, additional map[string]any) map[string]any {
	for k, v := range additional {
		base[k] = v
	}
	return base
}

// GetEmailData retrieves the email data based on a policy evaluation.
func (s *Sender) GetEmailData(ctx context.Context, event aws.CognitoEventUserPoolsCustomEmailSender) (*EmailData, error) {
	var verificationData *verifier.EmailVerificationResult
	var err error

	if s.Config.SendGridEmailVerificationEnabled {
		email, ok := event.Request.UserAttributes["email"].(string)
		if !ok {
			return nil, errors.New("missing or invalid 'email' in user attributes")
		}

		verificationData, err = s.EmailVerifier.VerifyEmail(ctx, email)
		if err != nil {
			log.Warn("sendgrid verify email error", "error", err)
		}
	}

	policyInput := PolicyInput{
		Trigger:           event.TriggerSource,
		UserAttributes:    event.Request.UserAttributes,
		ClientMetadata:    event.Request.ClientMetadata,
		EmailVerification: verificationData,
	}

	result, err := opa.EvaluatePolicy(ctx, s.Config.AppEmailSenderPolicyPath, policyInput)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	action, ok := result["action"].(string)
	if !ok {
		return nil, errors.New("desired action missing")
	}

	if action != "allow" {
		email, _ := event.Request.UserAttributes["email"].(string)
		reason, _ := result["reason"].(string)

		log.Info("ignoring send request", "email", email, "reason", reason)
		return nil, nil
	}

	allow, ok := result["allow"].(map[string]any)
	if !ok {
		return nil, errors.New("invalid format for 'allow' in policy result")
	}

	emailData, err := s.ParseEmailData(allow)
	if err != nil {
		return nil, fmt.Errorf("failed to parse email data: %w", err)
	}

	return &emailData, nil
}

func (s *Sender) ParseEmailData(data map[string]any) (EmailData, error) {
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
	templateData, ok := data["templateData"].(map[string]any)
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
