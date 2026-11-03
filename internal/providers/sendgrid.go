package providers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type SendGridProvider struct {
	Client *sendgrid.Client
	DryRun bool
}

func NewSendGridProvider(cfg *config.Config) *SendGridProvider {
	return &SendGridProvider{
		Client: sendgrid.NewSendClient(cfg.SendGridEmailSendApiKey),
		DryRun: !cfg.AppSendEnabled,
	}
}

func (p *SendGridProvider) Name() string {
	return "sendgrid"
}

func (p *SendGridProvider) Send(ctx context.Context, d *types.EmailData) error {
	pd := d.ProviderData(p.Name())
	if pd == nil {
		return errors.New("missing sendgrid template config")
	}

	if p.DryRun {
		slog.DebugContext(ctx, "dry-run sendgrid send",
			"template_id", pd.TemplateID,
			"template_data", pd.TemplateData,
			"src_address", d.SourceAddress,
			"dst_address", d.DestinationAddress,
		)
		return nil
	}

	srcName, srcAddr := parseNameAddr(d.SourceAddress)
	_, dstAddr := parseNameAddr(d.DestinationAddress)

	personalization := mail.NewPersonalization()
	personalization.AddTos(mail.NewEmail("", dstAddr))
	for k, v := range withCode(pd.TemplateData, d.VerificationCode) {
		personalization.SetDynamicTemplateData(k, v)
	}

	msg := mail.NewV3Mail()
	msg.SetFrom(mail.NewEmail(srcName, srcAddr))
	msg.SetTemplateID(pd.TemplateID)
	msg.AddPersonalizations(personalization)

	resp, err := p.Client.SendWithContext(ctx, msg)
	if err != nil {
		return fmt.Errorf("sendgrid api error: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sendgrid send failed: status=%d body=%s", resp.StatusCode, resp.Body)
	}

	return nil
}
