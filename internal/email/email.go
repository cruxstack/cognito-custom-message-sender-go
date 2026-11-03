// Package email handles custom email sender events: it rate limits, verifies
// the address, asks the policy whether and how to send, decrypts the code,
// and hands the message to the mailer.
package email

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/cognito"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/decrypt"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/logging"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/mailer"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/policy"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/ratelimit"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/verify"
)

// PolicyQuery is the rule the email policy must define.
const PolicyQuery = "data.cognito_custom_sender_email_policy.result"

// RateLimiter decides whether an email may be sent. Check never fails; store
// errors resolve to a fail-open or fail-closed decision.
type RateLimiter interface {
	Check(ctx context.Context, req ratelimit.Request) *ratelimit.Result
}

// Config holds the sender's dependencies.
type Config struct {
	Policy    *policy.Engine
	Decrypter decrypt.Decrypter
	Mailer    mailer.Mailer
	// Verifier is optional; nil disables email verification.
	Verifier verify.Verifier
	// RateLimiter is optional; nil disables rate limiting.
	RateLimiter RateLimiter
}

// Sender handles custom email sender events.
type Sender struct {
	cfg Config
}

// New returns a sender. Policy, Decrypter, and Mailer are required.
func New(cfg Config) (*Sender, error) {
	switch {
	case cfg.Policy == nil:
		return nil, errors.New("email sender: policy is required")
	case cfg.Decrypter == nil:
		return nil, errors.New("email sender: decrypter is required")
	case cfg.Mailer == nil:
		return nil, errors.New("email sender: mailer is required")
	}
	return &Sender{cfg: cfg}, nil
}

// Handle processes one event. Emails that are throttled or denied by the
// policy return nil. Errors (policy, decryption, or delivery failures) are
// returned so Lambda retries the event and, once retries are exhausted,
// sends it to the function's failure destination.
func (s *Sender) Handle(ctx context.Context, e *cognito.Event) error {
	to := e.Attribute("email")

	// rate limits run first, so throttled emails skip the verification call
	var rl *ratelimit.Result
	if s.cfg.RateLimiter != nil {
		rl = s.cfg.RateLimiter.Check(ctx, ratelimit.Request{
			Trigger:        e.TriggerSource,
			Destination:    to,
			UserName:       e.UserName,
			UserAttributes: e.Request.UserAttributes,
			Code:           e.Request.Code,
		})
		if !rl.Allowed() {
			return nil
		}
	}

	var verification *verify.Result
	if s.cfg.Verifier != nil && to != "" {
		var err error
		verification, err = s.cfg.Verifier.Verify(ctx, to)
		if err != nil {
			// leave input.emailVerification unset so the policy decides
			slog.WarnContext(ctx, "email verification unavailable", "to_masked", logging.MaskEmail(to), "error", err)
		}
	}

	d, err := policy.Eval[Decision](ctx, s.cfg.Policy, NewPolicyInput(e, verification, rl))
	if err != nil {
		return fmt.Errorf("email policy: %w", err)
	}

	msg, err := d.Message(to)
	if err != nil {
		return fmt.Errorf("email policy: %w", err)
	}
	if msg == nil {
		slog.InfoContext(ctx, "email denied by policy", "to_masked", logging.MaskEmail(to), "reason", cmp.Or(d.Reason, "not provided"))
		return nil
	}

	msg.Code, err = decrypt.Code(ctx, s.cfg.Decrypter, e.Request.Code)
	if err != nil {
		return fmt.Errorf("decrypt code: %w", err)
	}

	if err := s.cfg.Mailer.Send(ctx, msg); err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	return nil
}
