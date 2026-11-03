package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/sendgrid/sendgrid-go"
)

type SendGridValidationResult struct {
	Email   string  `json:"email"`
	Verdict string  `json:"verdict"`
	Score   float32 `json:"score"`
}

type SendGridValidationResponse struct {
	Result SendGridValidationResult `json:"result"`
}

type SendGridEmailVerifier struct {
	Whitelist []string
	APIHost   string
	APIKey    string
}

func NewSendGridVerifier(cfg *config.Config) *SendGridEmailVerifier {
	return &SendGridEmailVerifier{
		Whitelist: cfg.AppEmailVerificationWhitelist,
		APIHost:   cfg.SendGridApiHost,
		APIKey:    cfg.SendGridEmailVerificationApiKey,
	}
}

func (v *SendGridEmailVerifier) VerifyEmail(ctx context.Context, email string) (*EmailVerificationResult, error) {
	if v.isWhitelisted(email) {
		slog.DebugContext(ctx, "email domain whitelisted", "email", email)
		return &EmailVerificationResult{Score: 100, IsValid: true, Raw: `{}`}, nil
	}
	return v.VerifyEmailViaAPI(ctx, email)
}

func (v *SendGridEmailVerifier) isWhitelisted(email string) bool {
	domain, ok := emailDomain(email)
	if !ok {
		return false
	}
	return slices.ContainsFunc(v.Whitelist, func(d string) bool {
		return strings.EqualFold(d, domain)
	})
}

func (v *SendGridEmailVerifier) VerifyEmailViaAPI(ctx context.Context, email string) (*EmailVerificationResult, error) {
	body, err := json.Marshal(map[string]string{"email": email, "source": "cognito"})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	request := sendgrid.GetRequest(v.APIKey, "/v3/validations/email", v.APIHost)
	request.Method = http.MethodPost
	request.Body = body

	response, err := sendgrid.MakeRequestWithContext(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("sendgrid api error: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("sendgrid api returned status %d: %s", response.StatusCode, response.Body)
	}

	var payload SendGridValidationResponse
	if err := json.Unmarshal([]byte(response.Body), &payload); err != nil {
		return nil, fmt.Errorf("sendgrid unmarshal error: %w", err)
	}

	return &EmailVerificationResult{
		Score:   payload.Result.Score,
		IsValid: payload.Result.Verdict != "Invalid",
		Raw:     response.Body,
	}, nil
}
