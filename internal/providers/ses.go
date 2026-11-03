package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	awstypes "github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
)

type SESProvider struct {
	Client        *ses.Client
	DryRun        bool
	healthChecker *SESHealthChecker
}

func NewSESProvider(cfg *config.Config) *SESProvider {
	p := &SESProvider{
		Client: ses.NewFromConfig(*cfg.AWSConfig),
		DryRun: !cfg.AppSendEnabled,
	}

	if cfg.AppEmailFailoverEnabled {
		p.healthChecker = NewSESHealthChecker(sesv2.NewFromConfig(*cfg.AWSConfig), cfg.AppEmailFailoverCacheTTL)
	}

	return p
}

func (p *SESProvider) Name() string {
	return "ses"
}

func (p *SESProvider) Send(ctx context.Context, d *types.EmailData) error {
	pd := d.ProviderData(p.Name())
	if pd == nil {
		return errors.New("missing ses template config")
	}

	templateData, err := json.Marshal(withCode(pd.TemplateData, d.VerificationCode))
	if err != nil {
		return fmt.Errorf("error marshaling template data: %w", err)
	}

	if p.DryRun {
		slog.DebugContext(ctx, "dry-run ses send",
			"template_id", pd.TemplateID,
			"template_data", pd.TemplateData,
			"src_address", d.SourceAddress,
			"dst_address", d.DestinationAddress,
		)
		return nil
	}

	_, err = p.Client.SendTemplatedEmail(ctx, &ses.SendTemplatedEmailInput{
		Source:       awssdk.String(d.SourceAddress),
		Template:     awssdk.String(pd.TemplateID),
		TemplateData: awssdk.String(string(templateData)),
		Destination:  &awstypes.Destination{ToAddresses: []string{d.DestinationAddress}},
	})
	if err != nil {
		return fmt.Errorf("error sending templated email: %w", err)
	}

	return nil
}

func (p *SESProvider) IsHealthy(ctx context.Context) bool {
	if p.healthChecker == nil {
		return true
	}
	return p.healthChecker.IsHealthy(ctx)
}
