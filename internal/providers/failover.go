package providers

import (
	"context"
	"log/slog"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
)

// FailoverProvider wraps multiple providers and attempts to send emails
// through them in order, failing over to the next provider if one is unhealthy
// or fails to send.
type FailoverProvider struct {
	providers []Provider
}

// NewFailoverProvider creates a new failover provider with the given providers.
// Providers are tried in order - the first healthy provider that successfully
// sends the email wins.
func NewFailoverProvider(providers []Provider) *FailoverProvider {
	return &FailoverProvider{
		providers: providers,
	}
}

// Name returns "failover" to identify this as a failover provider.
func (f *FailoverProvider) Name() string {
	return "failover"
}

// Send attempts to send an email through each provider in order.
// It first checks if each provider is healthy (if it implements HealthChecker),
// skipping unhealthy providers. If a provider fails to send, it tries the next one.
func (f *FailoverProvider) Send(ctx context.Context, d *types.EmailData) error {
	var lastErr error

	for _, p := range f.providers {
		providerName := p.Name()

		// Check if provider has required template config
		if !hasProviderConfig(d, providerName) {
			slog.WarnContext(ctx, "provider missing template config, skipping",
				"provider", providerName,
			)
			continue
		}

		// Check health if provider implements HealthChecker
		if hc, ok := p.(HealthChecker); ok {
			if !hc.IsHealthy(ctx) {
				slog.WarnContext(ctx, "provider unhealthy, skipping",
					"provider", providerName,
				)
				continue
			}
		}

		// Attempt to send
		err := p.Send(ctx, d)
		if err == nil {
			slog.InfoContext(ctx, "email sent successfully",
				"provider", providerName,
			)
			return nil
		}

		// Log failure and try next provider
		slog.WarnContext(ctx, "provider send failed, trying next",
			"provider", providerName,
			"error", err,
		)
		lastErr = err
	}

	// All providers failed or were skipped - log warning but don't return error
	// to avoid Lambda retries. The email is lost but this is preferable to
	// cascading failures when all providers are down.
	if lastErr != nil {
		slog.WarnContext(ctx, "all providers failed to send email",
			"last_error", lastErr,
			"destination", d.DestinationAddress,
		)
	} else {
		slog.WarnContext(ctx, "no providers available to send email",
			"destination", d.DestinationAddress,
		)
	}

	return nil
}

// hasProviderConfig checks if the email data has configuration for the given provider.
func hasProviderConfig(d *types.EmailData, providerName string) bool {
	if d.Providers == nil {
		return false
	}

	switch providerName {
	case "ses":
		return d.Providers.SES != nil && d.Providers.SES.TemplateID != ""
	case "sendgrid":
		return d.Providers.SendGrid != nil && d.Providers.SendGrid.TemplateID != ""
	default:
		return false
	}
}

// Providers returns the list of providers in this failover chain.
func (f *FailoverProvider) Providers() []Provider {
	return f.providers
}
