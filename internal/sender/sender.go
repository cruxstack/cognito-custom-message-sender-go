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
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/providers"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/verifier"
)

type Sender struct {
	Config        *config.Config
	KMS           *aws.KMSClient
	EmailVerifier verifier.EmailVerifier
	Provider      providers.Provider
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

	p, err := providers.NewProvider(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create email provider: %w", err)
	}

	return &Sender{
		Config:        cfg,
		KMS:           aws.KMS,
		Provider:      p,
		EmailVerifier: verifier,
	}, nil
}

func (s *Sender) SendEmail(ctx context.Context, event aws.CognitoEventUserPoolsCustomEmailSender) error {
	data, err := s.GetEmailData(ctx, event)
	if err != nil {
		return fmt.Errorf("failed to get email data: %w", err)
	}

	if data == nil {
		return nil // do nothing
	}

	code, err := encryption.Decrypt(ctx, s.Config.AppKmsKeyId, event.Request.Code)
	if err != nil {
		return fmt.Errorf("failed to decrypt verification code: %w", err)
	}
	data.VerificationCode = code

	err = s.Provider.Send(ctx, data)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// GetEmailData retrieves the email data based on a policy evaluation.
func (s *Sender) GetEmailData(ctx context.Context, event aws.CognitoEventUserPoolsCustomEmailSender) (*types.EmailData, error) {
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

	return emailData, nil
}

func (s *Sender) ParseEmailData(data *types.EmailData) (*types.EmailData, error) {
	if data.DestinationAddress == "" {
		return nil, errors.New("destination address missing or invalid")
	}
	if data.SourceAddress == "" {
		return nil, errors.New("source address missing or invalid")
	}

	// allow for backwards compatibility with v1
	if data.TemplateData == nil {
		data.TemplateData = make(map[string]any)
	}
	if data.Providers == nil {
		data.Providers = &types.EmailProviderMap{}
	}
	if s.Config.AppEmailProvider == "ses" && data.Providers.SES == nil {
		data.Providers.SES = &types.EmailProviderData{
			TemplateID:   data.TemplateID,
			TemplateData: data.TemplateData,
		}
	}

	if s.Config.AppEmailProvider == "sendgrid" && data.Providers.SendGrid == nil {
		return nil, fmt.Errorf("email provider is sendgrid but email data does not include data for sendgrid provider")
	}

	return data, nil
}
