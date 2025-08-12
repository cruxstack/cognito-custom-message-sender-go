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

func NewProvider(cfg *config.Config) (Provider, error) {
	var p Provider

	switch cfg.AppEmailProvider {
	case "sendgrid":
		p = NewSendGridProvider(cfg)
	case "ses":
		p = NewSESProvider(cfg)
	default:
		return nil, fmt.Errorf("unknown email provider: %s", cfg.AppEmailProvider)
	}

	return p, nil
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
