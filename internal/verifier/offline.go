package verifier

import (
	"context"
	"net/mail"
	"strings"
)

// OfflineEmailVerifier performs basic email address validation without
// external API calls. It validates the email format using RFC 5322 parsing.
type OfflineEmailVerifier struct{}

func (v *OfflineEmailVerifier) VerifyEmail(ctx context.Context, email string) (*EmailVerificationResult, error) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return &EmailVerificationResult{
			Score:        0,
			IsValid:      false,
			IsDisposable: false,
			IsRoleBased:  false,
			Raw:          `{"error":"invalid email format"}`,
		}, nil
	}

	// Ensure there's a domain part with at least one dot
	at := strings.LastIndex(addr.Address, "@")
	if at == -1 || at == len(addr.Address)-1 {
		return &EmailVerificationResult{
			Score:        0,
			IsValid:      false,
			IsDisposable: false,
			IsRoleBased:  false,
			Raw:          `{"error":"missing domain"}`,
		}, nil
	}

	domain := addr.Address[at+1:]
	if !strings.Contains(domain, ".") {
		return &EmailVerificationResult{
			Score:        0,
			IsValid:      false,
			IsDisposable: false,
			IsRoleBased:  false,
			Raw:          `{"error":"invalid domain"}`,
		}, nil
	}

	return &EmailVerificationResult{
		Score:        100.0,
		IsValid:      true,
		IsDisposable: false,
		IsRoleBased:  false,
		Raw:          `{}`,
	}, nil
}

func NewOfflineVerifier() *OfflineEmailVerifier {
	return &OfflineEmailVerifier{}
}
