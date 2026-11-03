package providers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
)

type FailoverProvider struct {
	providers []Provider
}

func NewFailoverProvider(providers []Provider) *FailoverProvider {
	return &FailoverProvider{providers: providers}
}

func (f *FailoverProvider) Name() string {
	return "failover"
}

// Send tries each provider in order. It never returns an error so that an
// outage across all providers does not trigger cascading lambda retries.
func (f *FailoverProvider) Send(ctx context.Context, d *types.EmailData) error {
	var errs []error

	for _, p := range f.providers {
		name := p.Name()

		if d.ProviderData(name) == nil {
			slog.WarnContext(ctx, "provider missing template config, skipping", "provider", name)
			continue
		}

		if hc, ok := p.(HealthChecker); ok && !hc.IsHealthy(ctx) {
			slog.WarnContext(ctx, "provider unhealthy, skipping", "provider", name)
			continue
		}

		err := p.Send(ctx, d)
		if err == nil {
			slog.InfoContext(ctx, "email sent successfully", "provider", name)
			return nil
		}

		slog.WarnContext(ctx, "provider send failed, trying next", "provider", name, "error", err)
		errs = append(errs, fmt.Errorf("%s: %w", name, err))
	}

	if len(errs) > 0 {
		slog.ErrorContext(ctx, "all providers failed to send email", "destination", d.DestinationAddress, "error", errors.Join(errs...))
	} else {
		slog.ErrorContext(ctx, "no providers available to send email", "destination", d.DestinationAddress)
	}

	return nil
}
