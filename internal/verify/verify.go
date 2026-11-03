// Package verify checks whether an email address is likely to be
// deliverable before a message is sent to it. The result is passed to the
// email policy as input.emailVerification.
package verify

import (
	"context"
	"net/mail"
	"slices"
	"strings"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/sendgrid"
)

// Provider names.
const (
	ProviderOffline   = "offline"
	ProviderSendGrid  = "sendgrid"
	ProviderAllowlist = "allowlist"
)

// Providers lists the verification providers that can be configured.
var Providers = []string{ProviderOffline, ProviderSendGrid}

// Verdicts. They match the SendGrid validation verdicts.
const (
	VerdictValid   = sendgrid.VerdictValid
	VerdictRisky   = sendgrid.VerdictRisky
	VerdictInvalid = sendgrid.VerdictInvalid
)

// Result is the outcome of verifying one address.
type Result struct {
	// Provider is the verifier that produced the result.
	Provider string `json:"provider"`
	// Valid is false only when the address is known to be undeliverable.
	// Risky addresses are valid.
	Valid   bool   `json:"valid"`
	Verdict string `json:"verdict"`
	// Score is the likelihood that the address is deliverable, from 0 to 1.
	Score float64 `json:"score"`
	// Disposable is true when the domain belongs to a disposable email
	// service. Only the sendgrid provider detects it.
	Disposable bool `json:"disposable"`
	// Role is true when the local part is a role or group address, such as
	// admin@. Only the sendgrid provider detects it.
	Role bool `json:"role"`
	// Raw is the provider's raw response as a JSON string ("{}" when there is
	// none).
	Raw string `json:"raw"`
}

// Verifier verifies one email address. An error means the address could not
// be checked, not that it is invalid.
type Verifier interface {
	Verify(ctx context.Context, email string) (*Result, error)
}

// Offline checks the address syntax (RFC 5322) and requires a dotted domain.
// It makes no network calls.
type Offline struct{}

func (Offline) Verify(_ context.Context, email string) (*Result, error) {
	r := &Result{Provider: ProviderOffline, Verdict: VerdictInvalid, Raw: "{}"}
	if domain, ok := Domain(email); ok && strings.Contains(domain, ".") && !strings.HasPrefix(domain, ".") {
		r.Valid, r.Verdict, r.Score = true, VerdictValid, 1
	}
	return r, nil
}

// SendGrid verifies addresses with the SendGrid Email Address Validation API,
// which needs an Email API Pro or Premier plan.
type SendGrid struct {
	Client *sendgrid.Client
}

func (v SendGrid) Verify(ctx context.Context, email string) (*Result, error) {
	res, raw, err := v.Client.ValidateEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return &Result{
		Provider:   ProviderSendGrid,
		Valid:      res.Verdict != sendgrid.VerdictInvalid,
		Verdict:    res.Verdict,
		Score:      res.Score,
		Disposable: res.Checks.Domain.IsSuspectedDisposableAddress,
		Role:       res.Checks.LocalPart.IsSuspectedRoleAddress,
		Raw:        string(raw),
	}, nil
}

// Allowlist treats addresses in the listed domains as valid without calling
// Next.
type Allowlist struct {
	// Domains are matched exactly and case-insensitively.
	Domains []string
	Next    Verifier
}

func (v Allowlist) Verify(ctx context.Context, email string) (*Result, error) {
	if domain, ok := Domain(email); ok && slices.ContainsFunc(v.Domains, func(d string) bool {
		return strings.EqualFold(d, domain)
	}) {
		return &Result{Provider: ProviderAllowlist, Valid: true, Verdict: VerdictValid, Score: 1, Raw: "{}"}, nil
	}
	return v.Next.Verify(ctx, email)
}

// Domain returns the domain of a syntactically valid address.
func Domain(email string) (string, bool) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", false
	}
	at := strings.LastIndexByte(addr.Address, '@')
	if at <= 0 || at == len(addr.Address)-1 {
		return "", false
	}
	return addr.Address[at+1:], true
}
