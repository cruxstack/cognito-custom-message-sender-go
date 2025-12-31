package providers

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type SendGridProvider struct {
	Client sendgrid.Client
	APIKey string
	DryRun bool
}

func NewSendGridProvider(cfg *config.Config) *SendGridProvider {
	return &SendGridProvider{
		Client: *sendgrid.NewSendClient(cfg.SendGridEmailSendApiKey),
		DryRun: !cfg.AppSendEnabled,
	}
}

func (p *SendGridProvider) Name() string {
	return "sendgrid"
}

func (p *SendGridProvider) Send(ctx context.Context, d *types.EmailData) error {
	d.Providers.SendGrid.TemplateData = MergeTemplateData(d.Providers.SendGrid.TemplateData, map[string]any{"code": d.VerificationCode})

	srcName, srcAddr := ParseNameAddr(d.SourceAddress)
	_, dstAddr := ParseNameAddr(d.DestinationAddress)

	if p.DryRun {
		return p.SendDryRun(ctx, d)
	}

	msg := mail.NewV3Mail()
	msg.SetFrom(mail.NewEmail(srcName, srcAddr))
	msg.SetTemplateID(d.Providers.SendGrid.TemplateID)

	data := mail.NewPersonalization()
	data.AddTos(mail.NewEmail("", dstAddr))
	for k, v := range d.Providers.SendGrid.TemplateData {
		data.SetDynamicTemplateData(k, v)
	}
	msg.AddPersonalizations(data)

	resp, err := p.Client.Send(msg)
	if err != nil {
		return fmt.Errorf("sendgrid api error: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sendgrid send failed: status=%d body=%s", resp.StatusCode, resp.Body)
	}

	return nil
}

func (p *SendGridProvider) SendDryRun(ctx context.Context, d *types.EmailData) error {
	slog.DebugContext(ctx, "dry-run sendgrid send",
		"template_id", d.Providers.SendGrid.TemplateID,
		"template_data", d.Providers.SendGrid.TemplateData,
		"src_address", d.SourceAddress,
		"dst_address", d.DestinationAddress,
	)
	return nil
}
