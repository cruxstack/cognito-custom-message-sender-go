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
