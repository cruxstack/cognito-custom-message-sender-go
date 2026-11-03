// Package handler is the Lambda entry point: it decodes a Cognito custom
// sender event and routes it to the email or SMS sender by trigger source.
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/cognito"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/logging"
)

// Sender handles events for one trigger.
type Sender interface {
	Handle(ctx context.Context, e *cognito.Event) error
}

// Handler holds the enabled senders. A nil sender is disabled.
type Handler struct {
	Email Sender
	SMS   Sender
}

// Handle decodes and routes one event. Events for a disabled sender or an
// unknown trigger are logged and ignored, so Lambda doesn't retry them.
func (h *Handler) Handle(ctx context.Context, raw json.RawMessage) error {
	var e cognito.Event
	if err := json.Unmarshal(raw, &e); err != nil {
		return fmt.Errorf("decode event: %w", err)
	}

	// every log record for this event carries these attributes
	ctx = logging.WithAttrs(ctx,
		slog.String("trigger", e.TriggerSource),
		slog.String("user_pool_id", e.UserPoolID),
		slog.String("client_id", e.CallerContext.ClientID),
	)
	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		var compact bytes.Buffer
		if json.Compact(&compact, raw) == nil {
			slog.DebugContext(ctx, "received event", "event", json.RawMessage(compact.Bytes()))
		}
	}

	var s Sender
	switch e.Kind() {
	case cognito.KindEmail:
		s = h.Email
	case cognito.KindSMS:
		s = h.SMS
	default:
		slog.WarnContext(ctx, "unsupported trigger source, event ignored")
		return nil
	}
	if s == nil {
		slog.WarnContext(ctx, "sender for this trigger is not enabled, event ignored", "kind", e.Kind())
		return nil
	}

	if err := s.Handle(ctx, &e); err != nil {
		slog.ErrorContext(ctx, "failed to handle event", "kind", e.Kind(), "error", err)
		return err
	}
	return nil
}
