// Package handler routes cognito custom sender events to the email or sms
// sender by trigger source, so one function can serve both triggers.
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/sender"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/smssender"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
)

const (
	emailTriggerPrefix = "CustomEmailSender_"
	smsTriggerPrefix   = "CustomSMSSender_"
)

type EmailSender interface {
	SendEmail(ctx context.Context, event types.CognitoEventUserPoolsCustomEmailSender) error
}

type SMSSender interface {
	SendSMS(ctx context.Context, event types.CognitoEventUserPoolsCustomSMSSender) error
}

// Handler holds the enabled senders. A nil sender is disabled.
type Handler struct {
	Email EmailSender
	SMS   SMSSender
}

func New(ctx context.Context, cfg *config.Config) (*Handler, error) {
	h := &Handler{}

	if cfg.AppEmailSenderEnabled {
		s, err := sender.NewSender(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize email sender: %w", err)
		}
		h.Email = s
	}

	if cfg.AppSMSSenderEnabled {
		s, err := smssender.NewSender(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize sms sender: %w", err)
		}
		h.SMS = s
	}

	return h, nil
}

// Handle decodes the event and sends it with the matching sender. Events for
// a disabled sender or an unknown trigger are logged and ignored, so lambda
// doesn't retry them.
func (h *Handler) Handle(ctx context.Context, raw json.RawMessage) error {
	var header struct {
		TriggerSource string `json:"triggerSource"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return fmt.Errorf("failed to decode event: %w", err)
	}
	trigger := header.TriggerSource

	switch {
	case strings.HasPrefix(trigger, emailTriggerPrefix):
		if h.Email == nil {
			slog.WarnContext(ctx, "email sender is not enabled, event ignored", "trigger", trigger)
			return nil
		}
		var event types.CognitoEventUserPoolsCustomEmailSender
		if err := json.Unmarshal(raw, &event); err != nil {
			return fmt.Errorf("failed to decode email event: %w", err)
		}
		if err := h.Email.SendEmail(ctx, event); err != nil {
			slog.ErrorContext(ctx, "failed to send email", "trigger", trigger, "error", err)
			return err
		}

	case strings.HasPrefix(trigger, smsTriggerPrefix):
		if h.SMS == nil {
			slog.WarnContext(ctx, "sms sender is not enabled, event ignored", "trigger", trigger)
			return nil
		}
		var event types.CognitoEventUserPoolsCustomSMSSender
		if err := json.Unmarshal(raw, &event); err != nil {
			return fmt.Errorf("failed to decode sms event: %w", err)
		}
		if err := h.SMS.SendSMS(ctx, event); err != nil {
			slog.ErrorContext(ctx, "failed to send sms", "trigger", trigger, "error", err)
			return err
		}

	default:
		slog.WarnContext(ctx, "unsupported trigger source, event ignored", "trigger", trigger)
	}

	return nil
}
