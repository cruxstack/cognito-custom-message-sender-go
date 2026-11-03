// Package sms handles custom SMS sender events: it rate limits, records the
// attempt, asks the policy whether and how to send, decrypts the code, and
// publishes the SMS through Amazon SNS.
//
// It started as a port of the earlier Node.js sender from the Terraform
// module: the policy input and output, the history table layout, and the
// {####} code placeholder are unchanged, so existing policies and tables keep
// working.
package sms

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/cognito"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/decrypt"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/logging"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/policy"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/ratelimit"
)

const (
	// PolicyQuery is the rule the SMS policy must define.
	PolicyQuery = "data.cognito_custom_sender_sms_policy.result"

	// CodePlaceholder in the policy's message is replaced with the code.
	CodePlaceholder = "{####}"
)

// PolicyInput is the policy's input document.
type PolicyInput struct {
	Trigger         string                `json:"trigger"`
	UserPoolID      string                `json:"userPoolId"`
	Region          string                `json:"region"`
	UserName        string                `json:"userName"`
	CallerContext   cognito.CallerContext `json:"callerContext"`
	UserAttributes  map[string]any        `json:"userAttributes"`
	ClientMetadata  map[string]string     `json:"clientMetadata"`
	PhoneNumberData *PhoneNumber          `json:"phoneNumberData"`
	// History is set when the SMS history table is configured.
	History *PolicyHistory `json:"history,omitempty"`
	// RateLimit is set when rate limiting is enabled. Throttled SMS never
	// reach the policy, but the policy can deny on these values.
	RateLimit *ratelimit.Result `json:"rateLimit,omitempty"`
}

// PolicyHistory summarizes recent SMS to the destination.
type PolicyHistory struct {
	// RecentAttempts counts SMS to the phone number within the throttle
	// period, including this one.
	RecentAttempts int `json:"recentAttempts"`
}

// NewPolicyInput builds the policy input for an event. history and rl are
// nil when the history table or rate limiting is disabled.
func NewPolicyInput(e *cognito.Event, phone *PhoneNumber, history *PolicyHistory, rl *ratelimit.Result) PolicyInput {
	in := PolicyInput{
		Trigger:         e.TriggerSource,
		UserPoolID:      e.UserPoolID,
		Region:          e.Region,
		UserName:        e.UserName,
		CallerContext:   e.CallerContext,
		UserAttributes:  e.Request.UserAttributes,
		ClientMetadata:  e.Request.ClientMetadata,
		PhoneNumberData: phone,
		History:         history,
		RateLimit:       rl,
	}
	if in.UserAttributes == nil {
		in.UserAttributes = map[string]any{}
	}
	if in.ClientMetadata == nil {
		in.ClientMetadata = map[string]string{}
	}
	return in
}

// Decision is the policy's result document.
type Decision struct {
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
	// Block carries the reason in the format of the Node.js sender.
	Block struct {
		Reason string `json:"reason"`
	} `json:"block"`
	Allow struct {
		Message     string `json:"message"`
		MessageType string `json:"messageType"`
		SenderID    string `json:"senderId"`
		ShortCode   string `json:"shortCode"`
	} `json:"allow"`
}

// RateLimiter decides whether an SMS may be sent. Check never fails; store
// errors resolve to a fail-open or fail-closed decision.
type RateLimiter interface {
	Check(ctx context.Context, req ratelimit.Request) *ratelimit.Result
}

// Config holds the sender's dependencies and settings.
type Config struct {
	Policy    *policy.Engine
	Decrypter decrypt.Decrypter
	Publisher Publisher
	// RateLimiter is optional; nil disables rate limiting.
	RateLimiter RateLimiter
	// History is optional; nil disables the history and input.history.
	History HistoryStore
	// HistoryTTL is how long history records are kept.
	HistoryTTL time.Duration
	// ThrottlePeriod is the window input.history.recentAttempts counts over.
	ThrottlePeriod time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
}

// Sender handles custom SMS sender events.
type Sender struct {
	cfg Config
}

// New returns a sender. Policy, Decrypter, and Publisher are required.
func New(cfg Config) (*Sender, error) {
	switch {
	case cfg.Policy == nil:
		return nil, errors.New("sms sender: policy is required")
	case cfg.Decrypter == nil:
		return nil, errors.New("sms sender: decrypter is required")
	case cfg.Publisher == nil:
		return nil, errors.New("sms sender: publisher is required")
	case cfg.History != nil && (cfg.HistoryTTL <= 0 || cfg.ThrottlePeriod <= 0):
		return nil, errors.New("sms sender: history ttl and throttle period must be positive")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Sender{cfg: cfg}, nil
}

// Handle processes one event. An invalid phone number, a throttle, or a
// policy denial is logged and returns nil; policy, decryption, and publish
// failures return an error so Lambda retries.
func (s *Sender) Handle(ctx context.Context, e *cognito.Event) error {
	rawPhone := e.Attribute("phone_number")
	phone, err := ParsePhoneNumber(rawPhone)
	if err != nil {
		// a retry can't fix the number, so drop the event without an error
		slog.WarnContext(ctx, "sms not sent: user phone number is not valid", "phone_masked", logging.MaskPhone(rawPhone))
		return nil //nolint:nilerr // see above
	}

	// rate limits run first, so throttled SMS aren't recorded in the history
	var rl *ratelimit.Result
	if s.cfg.RateLimiter != nil {
		rl = s.cfg.RateLimiter.Check(ctx, ratelimit.Request{
			Trigger:        e.TriggerSource,
			Destination:    phone.Number,
			UserName:       e.UserName,
			UserAttributes: e.Request.UserAttributes,
			Code:           e.Request.Code,
		})
		if !rl.Allowed() {
			return nil
		}
	}

	var history *PolicyHistory
	if s.cfg.History != nil {
		now := s.cfg.Now()
		s.recordAttempt(ctx, e, phone, now)
		history = &PolicyHistory{RecentAttempts: s.recentAttempts(ctx, phone, now)}
	}

	d, err := policy.Eval[Decision](ctx, s.cfg.Policy, NewPolicyInput(e, phone, history, rl))
	if err != nil {
		return fmt.Errorf("sms policy: %w", err)
	}

	action, err := policy.ParseAction(d.Action)
	if err != nil {
		return fmt.Errorf("sms policy: %w", err)
	}
	if action == policy.ActionDeny {
		slog.InfoContext(ctx, "sms denied by policy",
			"phone_masked", logging.MaskPhone(phone.Number),
			"reason", cmp.Or(d.Reason, d.Block.Reason, "not provided"),
		)
		return nil
	}
	if d.Allow.Message == "" {
		return errors.New(`sms policy: "allow.message" is required`)
	}

	code, err := decrypt.Code(ctx, s.cfg.Decrypter, e.Request.Code)
	if err != nil {
		return fmt.Errorf("decrypt code: %w", err)
	}

	body := d.Allow.Message
	if code != "" {
		body = strings.Replace(body, CodePlaceholder, code, 1)
	}

	if err := s.cfg.Publisher.Publish(ctx, Message{
		PhoneNumber: phone.Number,
		Body:        body,
		MessageType: d.Allow.MessageType,
		SenderID:    d.Allow.SenderID,
		ShortCode:   d.Allow.ShortCode,
	}); err != nil {
		return fmt.Errorf("send sms: %w", err)
	}
	return nil
}

// recordAttempt saves the attempt before counting, so the count includes it.
// History errors are logged and don't stop the send.
func (s *Sender) recordAttempt(ctx context.Context, e *cognito.Event, phone *PhoneNumber, now time.Time) {
	err := s.cfg.History.Save(ctx, Record{
		Trigger:                e.TriggerSource,
		UserID:                 e.Attribute("sub"),
		UserEmailAddress:       e.Attribute("email"),
		UserPhoneNumber:        phone.Number,
		UserPhoneNumberCountry: phone.Country,
		SentAt:                 now,
	}, now.Add(s.cfg.HistoryTTL))
	if err != nil {
		slog.ErrorContext(ctx, "failed to save sms history", "error", err)
	}
}

// recentAttempts returns 0 when the history can't be read.
func (s *Sender) recentAttempts(ctx context.Context, phone *PhoneNumber, now time.Time) int {
	n, err := s.cfg.History.CountByPhoneNumber(ctx, phone.Number, now.Add(-s.cfg.ThrottlePeriod))
	if err != nil {
		slog.ErrorContext(ctx, "failed to count sms history", "error", err)
		return 0
	}
	return n
}
