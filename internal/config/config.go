// Package config reads the service configuration from environment
// variables. Invalid or contradictory settings are errors, so a misconfigured
// function fails at startup instead of misbehaving at send time.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/mailer"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/ratelimit"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/sendgrid"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/verify"
)

// Config is the service configuration.
type Config struct {
	LogLevel slog.Level
	// KMSKeyID is the ARN of the KMS key the user pool encrypts codes with.
	KMSKeyID string
	// SendEnabled is false for a dry run that logs messages instead of
	// sending them.
	SendEnabled bool

	Email    Email
	SMS      SMS
	SendGrid SendGrid
}

// Email configures the custom email sender.
type Email struct {
	Enabled    bool
	PolicyPath string
	// Providers are tried in order; more than one enables failover.
	Providers []string
	// HealthCheckTTL is how long an SES account health check is cached.
	HealthCheckTTL time.Duration

	VerificationEnabled   bool
	VerificationProvider  string
	VerificationAllowlist []string

	RateLimitEnabled   bool
	RateLimitTableName string
	// RateLimit is nil unless RateLimitEnabled is true.
	RateLimit *ratelimit.Config
}

// SMS configures the custom SMS sender.
type SMS struct {
	Enabled    bool
	PolicyPath string
	// HistoryTableName enables the SMS history (input.history) when set.
	HistoryTableName string
	HistoryTTL       time.Duration
	ThrottlePeriod   time.Duration

	RateLimitEnabled   bool
	RateLimitTableName string
	// RateLimit is nil unless RateLimitEnabled is true.
	RateLimit *ratelimit.Config
}

// SendGrid holds the SendGrid API settings.
type SendGrid struct {
	APIHost            string
	SendAPIKey         string
	VerificationAPIKey string
}

// removed lists variables from v2 that are no longer read, with what to use
// instead. Setting one is an error so an old configuration can't silently
// change behavior.
var removed = map[string]string{
	"APP_DEBUG_MODE":                   "APP_LOG_LEVEL=debug, and the devtool CLI for local runs",
	"APP_DEBUG_DATA_PATH":              "the devtool -events flag",
	"APP_EMAIL_PROVIDER":               "APP_EMAIL_PROVIDERS",
	"APP_EMAIL_FAILOVER_ENABLED":       "APP_EMAIL_PROVIDERS with more than one provider",
	"APP_EMAIL_FAILOVER_PROVIDERS":     "APP_EMAIL_PROVIDERS",
	"APP_EMAIL_FAILOVER_CACHE_TTL":     "APP_EMAIL_HEALTH_CHECK_TTL",
	"APP_EMAIL_VERIFICATION_WHITELIST": "APP_EMAIL_VERIFICATION_ALLOWLIST",
	"APP_SENDGRID_API_KEY":             "APP_SENDGRID_EMAIL_VERIFICATION_API_KEY",
	"KMS_KEY_ID":                       "APP_KMS_KEY_ID",
}

// FromEnv reads the configuration from the process environment.
func FromEnv() (*Config, error) {
	return Load(os.LookupEnv)
}

// Load reads the configuration with lookup, which has the signature of
// os.LookupEnv. All problems are reported together.
func Load(lookup func(string) (string, bool)) (*Config, error) {
	r := reader{lookup: lookup}

	for _, key := range slices.Sorted(maps.Keys(removed)) {
		if r.str(key) != "" {
			r.fail(fmt.Errorf("%s was removed in v3: use %s", key, removed[key]))
		}
	}

	cfg := &Config{
		LogLevel:    r.level("APP_LOG_LEVEL", slog.LevelInfo),
		KMSKeyID:    r.str("APP_KMS_KEY_ID"),
		SendEnabled: r.boolean("APP_SEND_ENABLED", true),
		Email: Email{
			Enabled:               r.boolean("APP_EMAIL_SENDER_ENABLED", true),
			PolicyPath:            r.str("APP_EMAIL_SENDER_POLICY_PATH"),
			Providers:             r.list("APP_EMAIL_PROVIDERS", []string{mailer.ProviderSES}),
			HealthCheckTTL:        r.duration("APP_EMAIL_HEALTH_CHECK_TTL", 30*time.Second),
			VerificationEnabled:   r.boolean("APP_EMAIL_VERIFICATION_ENABLED", true),
			VerificationProvider:  strings.ToLower(r.strOr("APP_EMAIL_VERIFICATION_PROVIDER", verify.ProviderOffline)),
			VerificationAllowlist: r.list("APP_EMAIL_VERIFICATION_ALLOWLIST", nil),
			RateLimitEnabled:      r.boolean("APP_EMAIL_RATE_LIMIT_ENABLED", false),
			RateLimitTableName:    r.str("APP_EMAIL_RATE_LIMIT_TABLE_NAME"),
		},
		SMS: SMS{
			Enabled:            r.boolean("APP_SMS_SENDER_ENABLED", false),
			PolicyPath:         r.str("APP_SMS_SENDER_POLICY_PATH"),
			HistoryTableName:   r.str("APP_SMS_HISTORY_TABLE_NAME"),
			HistoryTTL:         r.duration("APP_SMS_HISTORY_TTL", 30*24*time.Hour),
			ThrottlePeriod:     r.duration("APP_SMS_THROTTLE_PERIOD", 15*time.Minute),
			RateLimitEnabled:   r.boolean("APP_SMS_RATE_LIMIT_ENABLED", false),
			RateLimitTableName: r.str("APP_SMS_RATE_LIMIT_TABLE_NAME"),
		},
		SendGrid: SendGrid{
			APIHost:            r.strOr("APP_SENDGRID_API_HOST", sendgrid.DefaultBaseURL),
			SendAPIKey:         r.str("APP_SENDGRID_EMAIL_SEND_API_KEY"),
			VerificationAPIKey: r.str("APP_SENDGRID_EMAIL_VERIFICATION_API_KEY"),
		},
	}

	// rate limit configs are only read when the feature is enabled, so an
	// invalid value can't affect deployments that leave it off
	if cfg.Email.Enabled && cfg.Email.RateLimitEnabled {
		cfg.Email.RateLimit = r.rateLimit("APP_EMAIL_RATE_LIMIT_CONFIG", ratelimit.ChannelEmail)
	}
	if cfg.SMS.Enabled && cfg.SMS.RateLimitEnabled {
		cfg.SMS.RateLimit = r.rateLimit("APP_SMS_RATE_LIMIT_CONFIG", ratelimit.ChannelSMS)
	}

	r.errs = append(r.errs, cfg.validate()...)
	if len(r.errs) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  %w", joinIndented(r.errs))
	}
	return cfg, nil
}

func (c *Config) validate() []error {
	var errs []error
	req := func(ok bool, msg string) {
		if !ok {
			errs = append(errs, errors.New(msg))
		}
	}

	req(c.KMSKeyID != "", "APP_KMS_KEY_ID is required")
	req(c.Email.Enabled || c.SMS.Enabled, "at least one of APP_EMAIL_SENDER_ENABLED or APP_SMS_SENDER_ENABLED must be true")

	if e := c.Email; e.Enabled {
		req(e.PolicyPath != "", "APP_EMAIL_SENDER_POLICY_PATH is required when the email sender is enabled")
		req(len(e.Providers) > 0, "APP_EMAIL_PROVIDERS must list at least one provider")
		for i, p := range e.Providers {
			if !slices.Contains(mailer.Providers, p) {
				errs = append(errs, fmt.Errorf("APP_EMAIL_PROVIDERS: unknown provider %q: must be one of %v", p, mailer.Providers))
			}
			if slices.Index(e.Providers, p) != i {
				errs = append(errs, fmt.Errorf("APP_EMAIL_PROVIDERS: provider %q is listed more than once", p))
			}
		}
		if slices.Contains(e.Providers, mailer.ProviderSendGrid) {
			req(c.SendGrid.SendAPIKey != "", "APP_SENDGRID_EMAIL_SEND_API_KEY is required when sendgrid is in APP_EMAIL_PROVIDERS")
		}
		if e.VerificationEnabled {
			if !slices.Contains(verify.Providers, e.VerificationProvider) {
				errs = append(errs, fmt.Errorf("APP_EMAIL_VERIFICATION_PROVIDER: unknown provider %q: must be one of %v", e.VerificationProvider, verify.Providers))
			}
			if e.VerificationProvider == verify.ProviderSendGrid {
				req(c.SendGrid.VerificationAPIKey != "", "APP_SENDGRID_EMAIL_VERIFICATION_API_KEY is required when APP_EMAIL_VERIFICATION_PROVIDER is sendgrid")
			}
		}
		if e.RateLimitEnabled {
			req(e.RateLimitTableName != "", "APP_EMAIL_RATE_LIMIT_TABLE_NAME is required when APP_EMAIL_RATE_LIMIT_ENABLED is true")
		}
	}

	if s := c.SMS; s.Enabled {
		req(s.PolicyPath != "", "APP_SMS_SENDER_POLICY_PATH is required when the sms sender is enabled")
		if s.RateLimitEnabled {
			req(s.RateLimitTableName != "", "APP_SMS_RATE_LIMIT_TABLE_NAME is required when APP_SMS_RATE_LIMIT_ENABLED is true")
		}
	}

	return errs
}

// reader parses environment variables and collects errors.
type reader struct {
	lookup func(string) (string, bool)
	errs   []error
}

func (r *reader) fail(err error) {
	r.errs = append(r.errs, err)
}

// str returns the trimmed value of key, or "" when unset.
func (r *reader) str(key string) string {
	v, _ := r.lookup(key)
	return strings.TrimSpace(v)
}

// strOr returns the value of key, or def when unset or empty.
func (r *reader) strOr(key, def string) string {
	if v := r.str(key); v != "" {
		return v
	}
	return def
}

func (r *reader) boolean(key string, def bool) bool {
	s := r.str(key)
	if s == "" {
		return def
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		r.fail(fmt.Errorf("%s: %q is not a boolean (use true or false)", key, s))
		return def
	}
	return v
}

func (r *reader) duration(key string, def time.Duration) time.Duration {
	s := r.str(key)
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		r.fail(fmt.Errorf("%s: %q is not a positive Go duration (for example 30s or 15m)", key, s))
		return def
	}
	return d
}

func (r *reader) rateLimit(key string, ch ratelimit.Channel) *ratelimit.Config {
	rl, err := ratelimit.ParseConfig(ch, r.str(key))
	if err != nil {
		r.fail(fmt.Errorf("%s: %w", key, err))
	}
	return rl
}

func (r *reader) level(key string, def slog.Level) slog.Level {
	s := r.str(key)
	if s == "" {
		return def
	}
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	r.fail(fmt.Errorf("%s: %q must be one of debug, info, warn, or error", key, s))
	return def
}

// list splits a comma-separated value into lowercased items. It returns def
// when the variable is unset or empty.
func (r *reader) list(key string, def []string) []string {
	var out []string
	for item := range strings.SplitSeq(r.str(key), ",") {
		if item = strings.ToLower(strings.TrimSpace(item)); item != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

// joinIndented joins errors one per line for a readable startup error.
func joinIndented(errs []error) error {
	msgs := make([]string, len(errs))
	for i, err := range errs {
		msgs[i] = err.Error()
	}
	return errors.New(strings.Join(msgs, "\n  "))
}
