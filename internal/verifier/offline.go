package verifier

import (
	"context"
	"strings"
)

type OfflineEmailVerifier struct{}

func NewOfflineVerifier() *OfflineEmailVerifier {
	return &OfflineEmailVerifier{}
}

func (v *OfflineEmailVerifier) VerifyEmail(_ context.Context, email string) (*EmailVerificationResult, error) {
	domain, ok := emailDomain(email)
	if !ok {
		return &EmailVerificationResult{Raw: `{"error":"invalid email format"}`}, nil
	}

	if !strings.Contains(domain, ".") {
		return &EmailVerificationResult{Raw: `{"error":"invalid domain"}`}, nil
	}

	return &EmailVerificationResult{Score: 100, IsValid: true, Raw: `{}`}, nil
}
