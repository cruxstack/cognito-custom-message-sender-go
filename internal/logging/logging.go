// Package logging configures structured logging and masks personal data in
// log attributes.
package logging

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"strings"

	"github.com/aws/aws-lambda-go/lambdacontext"
)

// NewJSONHandler returns a JSON handler wrapped with ContextHandler.
func NewJSONHandler(w io.Writer, level slog.Leveler) slog.Handler {
	return ContextHandler(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// ContextHandler wraps h so each record logged with a context carries the
// attributes added to it with WithAttrs, and the Lambda request ID
// (request_id) when the context is a Lambda invocation context.
func ContextHandler(h slog.Handler) slog.Handler {
	return contextHandler{h}
}

type ctxKey struct{}

// WithAttrs returns a context whose log records carry attrs, in addition to
// any attributes already on ctx.
func WithAttrs(ctx context.Context, attrs ...slog.Attr) context.Context {
	prev, _ := ctx.Value(ctxKey{}).([]slog.Attr)
	return context.WithValue(ctx, ctxKey{}, append(slices.Clip(prev), attrs...))
}

type contextHandler struct {
	slog.Handler
}

func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if lc, ok := lambdacontext.FromContext(ctx); ok && lc.AwsRequestID != "" {
		r.AddAttrs(slog.String("request_id", lc.AwsRequestID))
	}
	if attrs, ok := ctx.Value(ctxKey{}).([]slog.Attr); ok {
		r.AddAttrs(attrs...)
	}
	return h.Handler.Handle(ctx, r)
}

func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{h.Handler.WithGroup(name)}
}

// MaskEmail hides all but the first character of the local part, for example
// "u***@example.com".
func MaskEmail(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	switch {
	case addr == "":
		return ""
	case at <= 0:
		return "***"
	default:
		return addr[:1] + "***" + addr[at:]
	}
}

// MaskPhone hides all but the last four digits, for example "+*******0100".
func MaskPhone(s string) string {
	if s == "" {
		return ""
	}
	prefix := ""
	if rest, ok := strings.CutPrefix(s, "+"); ok {
		prefix, s = "+", rest
	}
	if len(s) <= 4 {
		return prefix + "***"
	}
	return prefix + strings.Repeat("*", len(s)-4) + s[len(s)-4:]
}
