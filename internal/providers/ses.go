package providers

import (
	"context"
	"encoding/json"
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

	// Only create health checker if failover is enabled
	if cfg.AppEmailFailoverEnabled {
		sesv2Client := sesv2.NewFromConfig(*cfg.AWSConfig)
		p.healthChecker = NewSESHealthChecker(sesv2Client, cfg.AppEmailFailoverCacheTTL)
	}

	return p
}

func (p *SESProvider) Name() string {
	return "ses"
}

func (p *SESProvider) Send(ctx context.Context, d *types.EmailData) error {
	d.Providers.SES.TemplateData = MergeTemplateData(d.Providers.SES.TemplateData, map[string]any{"code": d.VerificationCode})

	if p.DryRun {
		return p.SendDryRun(ctx, d)
	}

	dataJSON, err := json.Marshal(d.Providers.SES.TemplateData)
	if err != nil {
		return fmt.Errorf("error marshaling template data: %w", err)
	}

	_, err = p.Client.SendTemplatedEmail(ctx, &ses.SendTemplatedEmailInput{
		Source:       awssdk.String(d.SourceAddress),
		Template:     awssdk.String(d.Providers.SES.TemplateID),
		TemplateData: awssdk.String(string(dataJSON)),
		Destination:  &awstypes.Destination{ToAddresses: []string{d.DestinationAddress}},
	})
	if err != nil {
		return fmt.Errorf("error sending templated email: %w", err)
	}

	return nil
}

func (p *SESProvider) SendDryRun(ctx context.Context, d *types.EmailData) error {
	dataJSON, err := json.Marshal(d.Providers.SES.TemplateData)
	if err != nil {
		return fmt.Errorf("error marshaling template data: %w", err)
	}

	slog.DebugContext(ctx, "dry-run ses send",
		"template_id", d.Providers.SES.TemplateID,
		"template_data", string(dataJSON),
		"src_address", d.SourceAddress,
		"dst_address", d.DestinationAddress,
	)

	return nil
}

// IsHealthy implements HealthChecker interface.
// Returns true if SES sending is enabled for the account.
// If no health checker is configured (failover disabled), always returns true.
func (p *SESProvider) IsHealthy(ctx context.Context) bool {
	if p.healthChecker == nil {
		return true
	}
	return p.healthChecker.IsHealthy(ctx)
}
