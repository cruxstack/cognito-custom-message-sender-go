package mailer

import (
	"context"
	"fmt"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/sendgrid"
)

// SendGrid sends with a SendGrid dynamic template.
type SendGrid struct {
	Client *sendgrid.Client
}

func (p SendGrid) Name() string { return ProviderSendGrid }

func (p SendGrid) Send(ctx context.Context, m *Message) error {
	t, ok := m.Template(ProviderSendGrid)
	if !ok {
		return fmt.Errorf("%w (sendgrid)", ErrNoTemplate)
	}
	return p.Client.SendTemplate(ctx, sendgrid.TemplateEmail{
		From:       m.From,
		To:         m.To,
		TemplateID: t.ID,
		Data:       m.templateData(t),
	})
}
