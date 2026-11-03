// Package app wires the service together from its configuration. It is the
// only package that knows about every other one; main and the devtool CLI
// call it, and tests use its options to replace AWS clients and stores.
package app

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sns"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/decrypt"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/email"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/handler"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/mailer"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/policy"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/ratelimit"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/sendgrid"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/sms"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/verify"
)

// Option replaces a dependency that New would otherwise build from the
// configuration and AWS config.
type Option func(*deps)

type deps struct {
	decrypter      decrypt.Decrypter
	ses            mailer.SESAPI
	sns            sms.SNSAPI
	rateLimitStore ratelimit.Store
	smsHistory     sms.HistoryStore
	httpClient     *http.Client
}

// WithDecrypter replaces the KMS decrypter.
func WithDecrypter(d decrypt.Decrypter) Option {
	return func(o *deps) { o.decrypter = d }
}

// WithSESClient replaces the SESv2 client.
func WithSESClient(c mailer.SESAPI) Option {
	return func(o *deps) { o.ses = c }
}

// WithSNSClient replaces the SNS client.
func WithSNSClient(c sms.SNSAPI) Option {
	return func(o *deps) { o.sns = c }
}

// WithRateLimitStore replaces the DynamoDB rate limit store for email and SMS.
func WithRateLimitStore(s ratelimit.Store) Option {
	return func(o *deps) { o.rateLimitStore = s }
}

// WithSMSHistory replaces the DynamoDB SMS history store. The history is
// still only used when APP_SMS_HISTORY_TABLE_NAME is set.
func WithSMSHistory(h sms.HistoryStore) Option {
	return func(o *deps) { o.smsHistory = h }
}

// WithHTTPClient sets the HTTP client used for SendGrid.
func WithHTTPClient(c *http.Client) Option {
	return func(o *deps) { o.httpClient = c }
}

// New builds the Lambda handler. It compiles the policies and creates every
// client up front, so configuration problems surface at startup.
func New(ctx context.Context, cfg *config.Config, awsCfg aws.Config, opts ...Option) (*handler.Handler, error) {
	var d deps
	for _, opt := range opts {
		opt(&d)
	}

	if d.decrypter == nil {
		kms, err := decrypt.NewKMS(cfg.KMSKeyID)
		if err != nil {
			return nil, fmt.Errorf("kms decrypter: %w", err)
		}
		d.decrypter = kms
	}

	var dynamo *dynamodb.Client
	dynamoClient := func() *dynamodb.Client {
		if dynamo == nil {
			// keep sdk retries short; callers have their own deadlines
			dynamo = dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.RetryMaxAttempts = 2 })
		}
		return dynamo
	}

	h := &handler.Handler{}

	if cfg.Email.Enabled {
		s, err := newEmailSender(ctx, cfg, awsCfg, &d, dynamoClient)
		if err != nil {
			return nil, fmt.Errorf("email sender: %w", err)
		}
		h.Email = s
	}

	if cfg.SMS.Enabled {
		s, err := newSMSSender(ctx, cfg, awsCfg, &d, dynamoClient)
		if err != nil {
			return nil, fmt.Errorf("sms sender: %w", err)
		}
		h.SMS = s
	}

	return h, nil
}

func newEmailSender(ctx context.Context, cfg *config.Config, awsCfg aws.Config, d *deps, dynamo func() *dynamodb.Client) (*email.Sender, error) {
	pol, err := policy.Load(ctx, cfg.Email.PolicyPath, email.PolicyQuery)
	if err != nil {
		return nil, err
	}

	var m mailer.Mailer = mailer.DryRun{Providers: cfg.Email.Providers}
	if cfg.SendEnabled {
		providers := make([]mailer.Provider, 0, len(cfg.Email.Providers))
		for _, name := range cfg.Email.Providers {
			switch name {
			case mailer.ProviderSES:
				if d.ses == nil {
					d.ses = sesv2.NewFromConfig(awsCfg)
				}
				providers = append(providers, mailer.NewSES(d.ses, cfg.Email.HealthCheckTTL))
			case mailer.ProviderSendGrid:
				providers = append(providers, mailer.SendGrid{
					Client: sendgrid.New(cfg.SendGrid.APIHost, cfg.SendGrid.SendAPIKey, d.httpClient),
				})
			default:
				return nil, fmt.Errorf("unknown email provider %q", name)
			}
		}
		m = mailer.NewChain(providers...)
	}

	var verifier verify.Verifier
	if cfg.Email.VerificationEnabled {
		verifier = verify.Offline{}
		if cfg.Email.VerificationProvider == verify.ProviderSendGrid {
			verifier = verify.SendGrid{
				Client: sendgrid.New(cfg.SendGrid.APIHost, cfg.SendGrid.VerificationAPIKey, d.httpClient),
			}
		}
		if len(cfg.Email.VerificationAllowlist) > 0 {
			verifier = verify.Allowlist{Domains: cfg.Email.VerificationAllowlist, Next: verifier}
		}
	}

	var limiter email.RateLimiter
	if cfg.Email.RateLimitEnabled {
		limiter = newLimiter(cfg.Email.RateLimit, cfg.Email.RateLimitTableName, d, dynamo)
	}

	return email.New(email.Config{
		Policy:      pol,
		Decrypter:   d.decrypter,
		Mailer:      m,
		Verifier:    verifier,
		RateLimiter: limiter,
	})
}

func newSMSSender(ctx context.Context, cfg *config.Config, awsCfg aws.Config, d *deps, dynamo func() *dynamodb.Client) (*sms.Sender, error) {
	pol, err := policy.Load(ctx, cfg.SMS.PolicyPath, sms.PolicyQuery, policy.AllowRegoV0())
	if err != nil {
		return nil, err
	}

	var pub sms.Publisher = sms.DryRunPublisher{}
	if cfg.SendEnabled {
		if d.sns == nil {
			d.sns = sns.NewFromConfig(awsCfg)
		}
		pub = &sms.SNSPublisher{Client: d.sns}
	}

	var history sms.HistoryStore
	if cfg.SMS.HistoryTableName != "" {
		history = d.smsHistory
		if history == nil {
			history = sms.NewDynamoDBHistory(dynamo(), cfg.SMS.HistoryTableName)
		}
	}

	var limiter sms.RateLimiter
	if cfg.SMS.RateLimitEnabled {
		limiter = newLimiter(cfg.SMS.RateLimit, cfg.SMS.RateLimitTableName, d, dynamo)
	}

	return sms.New(sms.Config{
		Policy:         pol,
		Decrypter:      d.decrypter,
		Publisher:      pub,
		RateLimiter:    limiter,
		History:        history,
		HistoryTTL:     cfg.SMS.HistoryTTL,
		ThrottlePeriod: cfg.SMS.ThrottlePeriod,
	})
}

// newLimiter returns a rate limiter backed by the table, or by the store
// passed with WithRateLimitStore. Email and SMS counters are keyed by
// channel, so they can share a table or a store.
func newLimiter(cfg *ratelimit.Config, table string, d *deps, dynamo func() *dynamodb.Client) *ratelimit.Limiter {
	store := d.rateLimitStore
	if store == nil {
		store = ratelimit.NewDynamoDBStore(dynamo(), table)
	}
	return ratelimit.New(cfg, store)
}
