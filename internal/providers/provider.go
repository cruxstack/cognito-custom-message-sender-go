package providers

import (
	"context"
	"fmt"
	"net/mail"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
)

type Provider interface {
	Name() string
	Send(ctx context.Context, d *types.EmailData) error
}

// NewProvider creates a provider based on configuration.
// If failover is enabled, it creates a FailoverProvider with the primary provider
// and all failover providers in order.
func NewProvider(cfg *config.Config) (Provider, error) {
	// If failover is enabled, create a failover provider chain
	if cfg.AppEmailFailoverEnabled && len(cfg.AppEmailFailoverProviders) > 0 {
		return newFailoverProvider(cfg)
	}

	// Single provider mode
	return createProvider(cfg.AppEmailProvider, cfg)
}

// newFailoverProvider creates a FailoverProvider with the primary provider first,
// followed by all configured failover providers.
func newFailoverProvider(cfg *config.Config) (Provider, error) {
	// Build list of all providers: primary first, then failover providers
	providerNames := append([]string{cfg.AppEmailProvider}, cfg.AppEmailFailoverProviders...)

	// Deduplicate while preserving order
	seen := make(map[string]bool)
	var uniqueNames []string
	for _, name := range providerNames {
		if !seen[name] {
			seen[name] = true
			uniqueNames = append(uniqueNames, name)
		}
	}

	// Create provider instances
	var providers []Provider
	for _, name := range uniqueNames {
		p, err := createProvider(name, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create provider %s: %w", name, err)
		}
		providers = append(providers, p)
	}

	return NewFailoverProvider(providers), nil
}

// createProvider creates a single provider by name.
func createProvider(name string, cfg *config.Config) (Provider, error) {
	switch name {
	case "sendgrid":
		return NewSendGridProvider(cfg), nil
	case "ses":
		return NewSESProvider(cfg), nil
	default:
		return nil, fmt.Errorf("unknown email provider: %s", name)
	}
}

func MergeTemplateData(base, additional map[string]any) map[string]any {
	if base == nil {
		base = make(map[string]any)
	}
	for k, v := range additional {
		base[k] = v
	}
	return base
}

func ParseNameAddr(s string) (string, string) {
	addr, err := mail.ParseAddress(s)
	if err != nil || addr == nil {
		return "", s
	}
	return addr.Name, addr.Address
}
