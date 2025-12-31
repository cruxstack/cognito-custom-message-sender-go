package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"net/mail"
	"slices"
	"strings"

	"github.com/charmbracelet/log"
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
	Whitelist []string
	APIHost   string
	APIKey    string
}

func (v *SendGridEmailVerifier) VerifyEmail(ctx context.Context, email string) (*EmailVerificationResult, error) {
	result, _ := v.VerifyEmailViaWhitelist(ctx, email)
	if result != nil {
		log.Debug("email domain was on whitelist", "email", email)
		return result, nil
	}
	return v.VerifyEmailViaAPI(ctx, email)
}

func (v *SendGridEmailVerifier) VerifyEmailViaWhitelist(ctx context.Context, email string) (*EmailVerificationResult, error) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return nil, nil // invalid email format
	}

	at := strings.LastIndex(addr.Address, "@")
	if at == -1 || at == len(addr.Address)-1 {
		return nil, nil // no domain part
	}

	domain := addr.Address[at+1:]
	whitelisted := slices.Contains(v.Whitelist, domain)

	if !whitelisted {
		return nil, nil
	}

	return &EmailVerificationResult{
		Score:        100.0,
		IsValid:      true,
		IsDisposable: false,
		IsRoleBased:  false,
		Raw:          "{}",
	}, nil
}

func (v *SendGridEmailVerifier) VerifyEmailViaAPI(ctx context.Context, email string) (*EmailVerificationResult, error) {
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
		Whitelist: cfg.AppEmailVerificationWhitelist,
		APIHost:   cfg.SendGridApiHost,
		APIKey:    cfg.SendGridEmailVerificationApiKey,
	}, nil
}
