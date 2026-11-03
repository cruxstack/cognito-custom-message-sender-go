package providers

import (
	"context"
	"fmt"
	"maps"
	"net/mail"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
)

type Provider interface {
	Name() string
	Send(ctx context.Context, d *types.EmailData) error
}

func NewProvider(cfg *config.Config) (Provider, error) {
	chain := cfg.ProviderChain()
	if !cfg.AppEmailFailoverEnabled {
		return createProvider(chain[0], cfg)
	}

	providers := make([]Provider, 0, len(chain))
	for _, name := range chain {
		p, err := createProvider(name, cfg)
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}

	return NewFailoverProvider(providers), nil
}

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

func withCode(data map[string]any, code string) map[string]any {
	out := make(map[string]any, len(data)+1)
	maps.Copy(out, data)
	out["code"] = code
	return out
}

func parseNameAddr(s string) (name, address string) {
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return "", s
	}
	return addr.Name, addr.Address
}
