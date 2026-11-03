package verifier

import (
	"context"
	"net/mail"
	"strings"
)

type EmailVerificationResult struct {
	Score        float32 `json:"score"`
	IsValid      bool    `json:"valid"`
	IsDisposable bool    `json:"disposable"`
	IsRoleBased  bool    `json:"role"`
	Raw          string  `json:"raw"`
}

type EmailVerifier interface {
	VerifyEmail(ctx context.Context, email string) (*EmailVerificationResult, error)
}

func emailDomain(email string) (string, bool) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", false
	}

	at := strings.LastIndexByte(addr.Address, '@')
	if at < 0 || at == len(addr.Address)-1 {
		return "", false
	}

	return addr.Address[at+1:], true
}
