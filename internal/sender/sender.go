package sender

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/encryption"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/opa"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/providers"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/verifier"
)

const PolicyQuery = "data.cognito_custom_sender_email_policy.result"

type Decrypter interface {
	Decrypt(ctx context.Context, ciphertext string) (string, error)
}

type Sender struct {
	Config         *config.Config
	Decrypter      Decrypter
	EmailVerifier  verifier.EmailVerifier
	PreparedPolicy *opa.PreparedPolicy
	Provider       providers.Provider
}

func NewSender(ctx context.Context, cfg *config.Config) (*Sender, error) {
	policy, err := opa.ReadPolicy(cfg.AppEmailSenderPolicyPath)
	if err != nil {
		return nil, err
	}

	preparedPolicy, err := opa.PreparePolicy(ctx, policy, PolicyQuery)
	if err != nil {
		return nil, err
	}

	decrypter, err := newDecrypter(cfg)
	if err != nil {
		return nil, err
	}

	provider, err := providers.NewProvider(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create email provider: %w", err)
	}

	return &Sender{
		Config:         cfg,
		Decrypter:      decrypter,
		EmailVerifier:  NewEmailVerifier(cfg),
		PreparedPolicy: preparedPolicy,
		Provider:       provider,
	}, nil
}

func (s *Sender) SendEmail(ctx context.Context, event types.CognitoEventUserPoolsCustomEmailSender) error {
	data, err := s.GetEmailData(ctx, event)
	if err != nil {
		return fmt.Errorf("failed to get email data: %w", err)
	}
	if data == nil {
		return nil
	}

	if event.Request.Code != "" {
		data.VerificationCode, err = s.Decrypter.Decrypt(ctx, event.Request.Code)
		if err != nil {
			return fmt.Errorf("failed to decrypt verification code: %w", err)
		}
	}

	if err := s.Provider.Send(ctx, data); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (s *Sender) GetEmailData(ctx context.Context, event types.CognitoEventUserPoolsCustomEmailSender) (*types.EmailData, error) {
	email, _ := event.Request.UserAttributes["email"].(string)

	var verification *verifier.EmailVerificationResult
	if s.Config.AppEmailVerificationEnabled {
		if email == "" {
			return nil, errors.New("missing or invalid 'email' in user attributes")
		}

		var err error
		verification, err = s.EmailVerifier.VerifyEmail(ctx, email)
		if err != nil {
			slog.WarnContext(ctx, "email verification failed", "email", email, "error", err)
		}
	}

	output, err := opa.Evaluate[PolicyOutput](ctx, s.PreparedPolicy, PolicyInput{
		Trigger:           event.TriggerSource,
		CallerContext:     event.CallerContext,
		UserAttributes:    event.Request.UserAttributes,
		ClientMetadata:    event.Request.ClientMetadata,
		EmailVerification: verification,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	switch output.Action {
	case "allow":
		return s.ParseEmailData(&output.Allow)
	case "":
		return nil, errors.New("desired action missing")
	default:
		slog.InfoContext(ctx, "send request denied by policy", "email", email, "reason", output.Reason)
		return nil, nil
	}
}

func (s *Sender) ParseEmailData(data *types.EmailData) (*types.EmailData, error) {
	if data.DestinationAddress == "" {
		return nil, errors.New("destination address missing or invalid")
	}
	if data.SourceAddress == "" {
		return nil, errors.New("source address missing or invalid")
	}

	if data.Providers == nil {
		data.Providers = &types.EmailProviderMap{}
	}
	if data.Providers.SES == nil && data.TemplateID != "" {
		data.Providers.SES = &types.EmailProviderData{
			TemplateID:   data.TemplateID,
			TemplateData: data.TemplateData,
		}
	}

	chain := s.Config.ProviderChain()
	if !slices.ContainsFunc(chain, func(p string) bool { return data.ProviderData(p) != nil }) {
		return nil, fmt.Errorf("email data has no template config for providers %v", chain)
	}

	return data, nil
}

func NewEmailVerifier(cfg *config.Config) verifier.EmailVerifier {
	switch cfg.AppEmailVerificationProvider {
	case "sendgrid":
		return verifier.NewSendGridVerifier(cfg)
	case "offline", "":
	default:
		slog.Warn("unknown email verification provider, defaulting to offline", "provider", cfg.AppEmailVerificationProvider)
	}
	return verifier.NewOfflineVerifier()
}

func newDecrypter(cfg *config.Config) (Decrypter, error) {
	if cfg.DebugMode && cfg.AppKmsKeyId == encryption.MockKeyID {
		return encryption.Passthrough{}, nil
	}

	d, err := encryption.NewKMSDecrypter(cfg.AppKmsKeyId)
	if err != nil {
		return nil, err
	}
	return d, nil
}
