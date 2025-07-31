package verifier

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/sendgrid/sendgrid-go"
)

type SendGridEmailEmailAddressValidationCheckResult struct {
}

type SendGridEmailEmailAddressValidationResult struct {
	Email   string  `json:"email"`
	Verdict string  `json:"verdict"`
	Score   float32 `json:"score"`
}

type SendGridEmailEmailAddressValidationResponse struct {
	Result SendGridEmailEmailAddressValidationResult `json:"result"`
}

type SendGridEmailVerifier struct {
	APIHost string
	APIKey  string
}

func (v *SendGridEmailVerifier) VerifyEmail(ctx context.Context, email string) (*EmailVerificationResult, error) {
	request := sendgrid.GetRequest(v.APIKey, "/v3/validations/email", v.APIHost)
	request.Body = fmt.Appendf(request.Body, `{"email":"%s","source":"cognito"}`, email)
	request.Method = "POST"

	response, err := sendgrid.API(request)
	if err != nil {
		return nil, fmt.Errorf("sendgrid api error: %w", err)
	}

	var payload SendGridEmailEmailAddressValidationResponse

	if err := json.Unmarshal([]byte(response.Body), &payload); err != nil {
		return nil, fmt.Errorf("sendgrid unmarshal error: %w", err)
	}

	result := payload.Result

	return &EmailVerificationResult{
		Score:   result.Score,
		IsValid: result.Verdict != "Invalid",
		Raw:     response.Body,
	}, nil
}

func NewSendGridVerifier(cfg *config.Config) (*SendGridEmailVerifier, error) {
	return &SendGridEmailVerifier{
		APIHost: cfg.SendGridApiHost,
		APIKey:  cfg.SendGridApiKey,
	}, nil
}
