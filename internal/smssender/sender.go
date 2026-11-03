// Package smssender sends policy-driven SMS for cognito custom sms sender
// events. It is a port of the earlier node.js sender: the policy input and
// output, the history table, and the {####} code placeholder are unchanged.
package smssender

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/encryption"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/opa"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
)

const (
	PolicyQuery = "data.cognito_custom_sender_sms_policy.result"

	// CodePlaceholder in the policy's message is replaced with the code
	CodePlaceholder = "{####}"
)

type PolicyInput struct {
	Trigger         string                                    `json:"trigger"`
	CallerContext   events.CognitoEventUserPoolsCallerContext `json:"callerContext"`
	UserAttributes  map[string]any                            `json:"userAttributes"`
	ClientMetadata  map[string]string                         `json:"clientMetadata"`
	PhoneNumberData *PhoneNumber                              `json:"phoneNumberData"`
	History         PolicyHistory                             `json:"history"`
}

type PolicyHistory struct {
	// RecentAttempts counts SMS to the phone number within the throttle
	// period, including this one.
	RecentAttempts int `json:"recentAttempts"`
}

type PolicyOutput struct {
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
	Block  struct {
		Reason string `json:"reason"`
	} `json:"block"`
	Allow PolicyAllow `json:"allow"`
}

type PolicyAllow struct {
	Message     string `json:"message"`
	MessageType string `json:"messageType"`
	SenderID    string `json:"senderId"`
	ShortCode   string `json:"shortCode"`
}

type Decrypter interface {
	Decrypt(ctx context.Context, ciphertext string) (string, error)
}

type Sender struct {
	Config         *config.Config
	Decrypter      Decrypter
	PreparedPolicy *opa.PreparedPolicy
	History        HistoryStore
	Publisher      Publisher
	// Now defaults to time.Now
	Now func() time.Time
}

func NewSender(ctx context.Context, cfg *config.Config) (*Sender, error) {
	policy, err := opa.ReadPolicy(cfg.AppSMSSenderPolicyPath)
	if err != nil {
		return nil, err
	}

	preparedPolicy, err := PreparePolicy(ctx, policy)
	if err != nil {
		return nil, err
	}

	decrypter, err := encryption.NewDecrypter(cfg.AppKmsKeyId, cfg.DebugMode)
	if err != nil {
		return nil, err
	}

	return &Sender{
		Config:         cfg,
		Decrypter:      decrypter,
		PreparedPolicy: preparedPolicy,
		History:        newHistory(cfg),
		Publisher:      &SNSPublisher{Client: sns.NewFromConfig(*cfg.AWSConfig), DryRun: !cfg.AppSendEnabled},
	}, nil
}

// PreparePolicy compiles an sms policy written in rego v1, or in rego v0 for
// policies written for the earlier node.js sender.
func PreparePolicy(ctx context.Context, policy string) (*opa.PreparedPolicy, error) {
	pp, err := opa.PreparePolicy(ctx, policy, PolicyQuery)
	if err == nil {
		return pp, nil
	}

	pp, errV0 := opa.PreparePolicy(ctx, policy, PolicyQuery, opa.WithRegoV0())
	if errV0 != nil {
		return nil, err
	}
	slog.Warn("sms policy uses rego v0 syntax; rego v1 is recommended")
	return pp, nil
}

// SendSMS evaluates the policy and sends the SMS. Like the node.js sender,
// an invalid phone number or a policy block is logged and dropped without an
// error, while decryption and publish failures return an error so lambda
// retries.
func (s *Sender) SendSMS(ctx context.Context, event types.CognitoEventUserPoolsCustomSMSSender) error {
	rawPhone, _ := event.Request.UserAttributes["phone_number"].(string)
	phone, err := ParsePhoneNumber(rawPhone)
	if err != nil {
		slog.WarnContext(ctx, "sms not sent: user phone number is not valid",
			"trigger", event.TriggerSource, "phone_masked", MaskPhoneNumber(rawPhone))
		return nil
	}

	now := s.now()
	s.recordAttempt(ctx, event, phone, now)
	attempts := s.recentAttempts(ctx, phone, now)

	output, err := opa.Evaluate[PolicyOutput](ctx, s.PreparedPolicy, PolicyInput{
		Trigger:         event.TriggerSource,
		CallerContext:   event.CallerContext,
		UserAttributes:  event.Request.UserAttributes,
		ClientMetadata:  event.Request.ClientMetadata,
		PhoneNumberData: phone,
		History:         PolicyHistory{RecentAttempts: attempts},
	})
	if err != nil {
		return fmt.Errorf("failed to evaluate policy: %w", err)
	}

	switch output.Action {
	case "allow":
	case "":
		return errors.New("desired action missing")
	default:
		slog.InfoContext(ctx, "sms blocked by policy",
			"trigger", event.TriggerSource,
			"phone_masked", MaskPhoneNumber(phone.Number),
			"recent_attempts", attempts,
			"reason", cmp.Or(output.Block.Reason, output.Reason, "reason not provided"),
		)
		return nil
	}

	if output.Allow.Message == "" {
		return errors.New("sms message missing from policy result")
	}

	body := output.Allow.Message
	if event.Request.Code != "" {
		code, err := s.Decrypter.Decrypt(ctx, event.Request.Code)
		if err != nil {
			return fmt.Errorf("failed to decrypt verification code: %w", err)
		}
		body = strings.Replace(body, CodePlaceholder, code, 1)
	}

	if err := s.Publisher.Publish(ctx, Message{
		PhoneNumber: phone.Number,
		Body:        body,
		MessageType: output.Allow.MessageType,
		SenderID:    output.Allow.SenderID,
		ShortCode:   output.Allow.ShortCode,
	}); err != nil {
		return fmt.Errorf("failed to send sms: %w", err)
	}

	return nil
}

// recordAttempt saves the attempt before counting, so the count includes it.
// History errors are logged and don't stop the send.
func (s *Sender) recordAttempt(ctx context.Context, event types.CognitoEventUserPoolsCustomSMSSender, phone *PhoneNumber, now time.Time) {
	attrs := event.Request.UserAttributes
	userID, _ := attrs["sub"].(string)
	email, _ := attrs["email"].(string)

	err := s.History.Save(ctx, Record{
		Trigger:                event.TriggerSource,
		UserID:                 userID,
		UserEmailAddress:       email,
		UserPhoneNumber:        phone.Number,
		UserPhoneNumberCountry: phone.Country,
		SentAt:                 now,
	}, now.Add(s.Config.AppSMSHistoryTTL))
	if err != nil {
		slog.ErrorContext(ctx, "failed to save sms history", "error", err)
	}
}

// recentAttempts returns 0 when the history can't be read.
func (s *Sender) recentAttempts(ctx context.Context, phone *PhoneNumber, now time.Time) int {
	n, err := s.History.CountByPhoneNumber(ctx, phone.Number, now.Add(-s.Config.AppSMSThrottlePeriod))
	if err != nil {
		slog.ErrorContext(ctx, "failed to count sms history", "error", err)
		return 0
	}
	return n
}

func (s *Sender) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func newHistory(cfg *config.Config) HistoryStore {
	if cfg.AppSMSHistoryTableName == "" && cfg.DebugMode {
		slog.Warn("no sms history table set in debug mode, using an in-memory history")
		return NewMemoryHistory()
	}
	return NewDynamoDBHistory(dynamodb.NewFromConfig(*cfg.AWSConfig), cfg.AppSMSHistoryTableName)
}
