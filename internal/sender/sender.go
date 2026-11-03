package sender

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/encryption"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/opa"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/providers"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/ratelimit"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/verifier"
)

const PolicyQuery = "data.cognito_custom_sender_email_policy.result"

type Decrypter interface {
	Decrypt(ctx context.Context, ciphertext string) (string, error)
}

// RateLimiter decides whether an email may be sent. Check must not fail;
// store errors resolve to a fail-open or fail-closed decision.
type RateLimiter interface {
	Check(ctx context.Context, req ratelimit.Request) *ratelimit.Result
}

type Sender struct {
	Config         *config.Config
	Decrypter      Decrypter
	EmailVerifier  verifier.EmailVerifier
	PreparedPolicy *opa.PreparedPolicy
	Provider       providers.Provider
	// RateLimiter is nil when rate limiting is disabled
	RateLimiter RateLimiter
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

	s := &Sender{
		Config:         cfg,
		Decrypter:      decrypter,
		EmailVerifier:  NewEmailVerifier(cfg),
		PreparedPolicy: preparedPolicy,
		Provider:       provider,
	}
	if cfg.AppEmailRateLimitEnabled {
		s.RateLimiter = newRateLimiter(cfg)
	}

	return s, nil
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

	// rate limits run first so throttled emails skip verification lookups.
	// cognito invokes this function asynchronously, so a throttle cannot
	// fail the user's request; the email is dropped without an error.
	var rateLimit *ratelimit.Result
	if s.RateLimiter != nil {
		rateLimit = s.RateLimiter.Check(ctx, ratelimit.Request{
			Trigger:        event.TriggerSource,
			Email:          email,
			UserName:       event.UserName,
			UserAttributes: event.Request.UserAttributes,
			Code:           event.Request.Code,
		})
		if !rateLimit.Allowed() {
			return nil, nil
		}
	}

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
		RateLimit:         rateLimit,
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

func newRateLimiter(cfg *config.Config) RateLimiter {
	if cfg.AppEmailRateLimitTableName == "" && cfg.DebugMode {
		slog.Warn("no rate limit table set in debug mode, using an in-memory store")
		return ratelimit.New(cfg.AppEmailRateLimit, ratelimit.NewMemoryStore())
	}

	// keep sdk retries short; the limiter has its own deadline and fails open
	client := dynamodb.NewFromConfig(*cfg.AWSConfig, func(o *dynamodb.Options) {
		o.RetryMaxAttempts = 2
	})
	return ratelimit.New(cfg.AppEmailRateLimit, ratelimit.NewDynamoDBStore(client, cfg.AppEmailRateLimitTableName))
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
