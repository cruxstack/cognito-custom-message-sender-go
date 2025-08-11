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
		CallerContext:     event.CallerContext,
		UserAttributes:    event.Request.UserAttributes,
		ClientMetadata:    event.Request.ClientMetadata,
		EmailVerification: verificationData,
	}

	output, err := opa.EvaluatePolicy[PolicyOutput](ctx, s.Config.AppEmailSenderPolicyPath, policyInput)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	if output.Action == "" {
		return nil, errors.New("desired action missing")
	}

	if output.Action != "allow" {
		email, _ := event.Request.UserAttributes["email"].(string)
		log.Info("ignoring send request", "email", email, "reason", output.Reason)
		return nil, nil
	}

	emailData, err := s.ParseEmailData(&output.Allow)
	if err != nil {
		return nil, fmt.Errorf("failed to parse email data: %w", err)
	}

	return &emailData, nil
}

func (s *Sender) ParseEmailData(data *EmailData) (EmailData, error) {
	if data.DestinationAddress == "" {
		return EmailData{}, errors.New("destination address missing or invalid")
	}
	if data.SourceAddress == "" {
		return EmailData{}, errors.New("source address missing or invalid")
	}
	if data.TemplateID == "" {
		return EmailData{}, errors.New("template ID missing or invalid")
	}
	if data.TemplateData == nil {
		data.TemplateData = make(map[string]any)
	}

	return EmailData{
		DestinationAddress: data.DestinationAddress,
		SourceAddress:      data.SourceAddress,
		TemplateID:         data.TemplateID,
		TemplateData:       data.TemplateData,
	}, nil
}
