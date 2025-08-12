package providers

import (
	"context"
	"fmt"

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
