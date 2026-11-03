// Package mailer delivers templated emails through Amazon SES or SendGrid,
// failing over between providers in a configured order.
package mailer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/logging"
)

// Provider names.
const (
	ProviderSES      = "ses"
	ProviderSendGrid = "sendgrid"
)

// Providers lists the providers that can be configured.
var Providers = []string{ProviderSES, ProviderSendGrid}

// CodeKey is the template data key that holds the decrypted code. It
// replaces any value the policy sets for the same key.
const CodeKey = "code"

// ErrNoTemplate is returned when a message has no template for any
// configured provider.
var ErrNoTemplate = errors.New("message has no template for any configured provider")

// Template selects a provider template and the data to render it with.
type Template struct {
	ID   string         `json:"templateId"`
	Data map[string]any `json:"templateData"`
}

// Message is one templated email.
type Message struct {
	// From is the sender address, optionally with a display name.
	From string
	To   string
	// Templates holds a template for each provider that can send the
	// message, keyed by provider name.
	Templates map[string]Template
	// Code is the decrypted secret, added to the template data as CodeKey.
	Code string
}

// Template returns the message's template for a provider.
func (m *Message) Template(provider string) (Template, bool) {
	t, ok := m.Templates[provider]
	return t, ok && t.ID != ""
}

// templateData returns the template data with the code added.
func (m *Message) templateData(t Template) map[string]any {
	out := make(map[string]any, len(t.Data)+1)
	maps.Copy(out, t.Data)
	out[CodeKey] = m.Code
	return out
}

// Provider sends a message with its own template.
type Provider interface {
	Name() string
	Send(ctx context.Context, m *Message) error
}

// HealthChecker is implemented by providers that can tell, before sending,
// that they can't deliver.
type HealthChecker interface {
	Healthy(ctx context.Context) bool
}

// Mailer sends a message with the first provider that succeeds.
type Mailer interface {
	Send(ctx context.Context, m *Message) error
}

// Chain sends with providers in order, skipping providers the message has no
// template for. Unhealthy providers are tried last rather than skipped, so a
// stale or wrong health check can't drop a message.
type Chain struct {
	providers []Provider
}

// NewChain returns a chain that tries providers in the given order.
func NewChain(providers ...Provider) *Chain {
	return &Chain{providers: providers}
}

// Names returns the provider names in order.
func (c *Chain) Names() []string {
	names := make([]string, len(c.providers))
	for i, p := range c.providers {
		names[i] = p.Name()
	}
	return names
}

// Send returns nil when one provider sent the message. Otherwise it returns
// ErrNoTemplate or the joined provider errors.
func (c *Chain) Send(ctx context.Context, m *Message) error {
	var healthy, unhealthy []Provider
	for _, p := range c.providers {
		if _, ok := m.Template(p.Name()); !ok {
			continue
		}
		if hc, ok := p.(HealthChecker); ok && len(c.providers) > 1 && !hc.Healthy(ctx) {
			slog.WarnContext(ctx, "email provider unhealthy, trying it last", "provider", p.Name())
			unhealthy = append(unhealthy, p)
			continue
		}
		healthy = append(healthy, p)
	}

	candidates := slices.Concat(healthy, unhealthy)
	if len(candidates) == 0 {
		return fmt.Errorf("%w %v", ErrNoTemplate, c.Names())
	}

	var errs []error
	for i, p := range candidates {
		err := p.Send(ctx, m)
		if err == nil {
			slog.InfoContext(ctx, "email sent", "provider", p.Name(), "to_masked", logging.MaskEmail(m.To))
			return nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
		if i < len(candidates)-1 {
			slog.WarnContext(ctx, "email provider failed, trying next", "provider", p.Name(), "error", err)
		}
	}
	return fmt.Errorf("all email providers failed: %w", errors.Join(errs...))
}

// DryRun logs the message the chain would send instead of sending it.
type DryRun struct {
	Providers []string
}

func (d DryRun) Send(ctx context.Context, m *Message) error {
	for _, name := range d.Providers {
		if t, ok := m.Template(name); ok {
			slog.InfoContext(ctx, "dry run: email not sent",
				"provider", name,
				"template_id", t.ID,
				"template_data_keys", slices.Sorted(maps.Keys(m.templateData(t))),
				"from", m.From,
				"to_masked", logging.MaskEmail(m.To),
			)
			return nil
		}
	}
	return fmt.Errorf("%w %v", ErrNoTemplate, d.Providers)
}
