package mailer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sestypes "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// SESAPI is the subset of the SESv2 client used by SES.
type SESAPI interface {
	SendEmail(ctx context.Context, params *sesv2.SendEmailInput, optFns ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
	GetAccount(ctx context.Context, params *sesv2.GetAccountInput, optFns ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error)
}

// SES sends with an Amazon SES email template (sesv2 SendEmail). It needs
// the ses:SendEmail permission, plus ses:GetAccount for health checks.
type SES struct {
	client SESAPI

	// health check cache
	healthTTL   time.Duration
	mu          sync.Mutex
	healthy     bool
	healthUntil time.Time
	now         func() time.Time
}

// NewSES returns an SES provider. Health checks are cached for healthTTL.
func NewSES(client SESAPI, healthTTL time.Duration) *SES {
	return &SES{client: client, healthTTL: healthTTL, now: time.Now}
}

func (p *SES) Name() string { return ProviderSES }

func (p *SES) Send(ctx context.Context, m *Message) error {
	t, ok := m.Template(ProviderSES)
	if !ok {
		return fmt.Errorf("%w (ses)", ErrNoTemplate)
	}

	data, err := json.Marshal(m.templateData(t))
	if err != nil {
		return fmt.Errorf("encode ses template data: %w", err)
	}

	out, err := p.client.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(m.From),
		Destination:      &sestypes.Destination{ToAddresses: []string{m.To}},
		Content: &sestypes.EmailContent{
			Template: &sestypes.Template{
				TemplateName: aws.String(t.ID),
				TemplateData: aws.String(string(data)),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("ses send email: %w", err)
	}

	slog.DebugContext(ctx, "ses accepted email", "message_id", aws.ToString(out.MessageId))
	return nil
}

// Healthy reports false only when SES says sending is disabled for the
// account (for example after a suspension). When the account can't be read,
// SES is assumed healthy so the send is still attempted.
func (p *SES) Healthy(ctx context.Context) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	if now.Before(p.healthUntil) {
		return p.healthy
	}

	p.healthy = p.checkHealth(ctx)
	p.healthUntil = now.Add(p.healthTTL)
	return p.healthy
}

func (p *SES) checkHealth(ctx context.Context) bool {
	out, err := p.client.GetAccount(ctx, &sesv2.GetAccountInput{})
	if err != nil {
		slog.WarnContext(ctx, "ses health check failed, assuming healthy", "error", err)
		return true
	}
	if !out.SendingEnabled {
		slog.WarnContext(ctx, "ses sending is disabled for the account",
			"enforcement_status", aws.ToString(out.EnforcementStatus),
			"production_access", out.ProductionAccessEnabled,
		)
		return false
	}
	return true
}
