package providers

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	awstypes "github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/charmbracelet/log"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
)

type SESProvider struct {
	Client *ses.Client
	DryRun bool
}

func NewSESProvider(cfg *config.Config) *SESProvider {
	return &SESProvider{
		Client: ses.NewFromConfig(*cfg.AWSConfig),
		DryRun: !cfg.AppSendEnabled,
	}
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

	log.Debug(
		"[DRY-RUN] SES Send:",
		"templateId", d.Providers.SES.TemplateID,
		"templateData", string(dataJSON),
		"srcAddress", d.SourceAddress,
		"dstAddress", d.DestinationAddress,
	)

	return nil
}
