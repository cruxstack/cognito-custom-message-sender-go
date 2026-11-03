package config

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/ratelimit"
)

const (
	defaultFailoverCacheTTL = 30 * time.Second
	defaultSMSHistoryTTL    = 30 * 24 * time.Hour
	defaultSMSThrottle      = 15 * time.Minute
)

type Config struct {
	AWSConfig                       *aws.Config
	AppLogLevel                     slog.Level
	AppKmsKeyId                     string
	AppEmailProvider                string
	AppEmailSenderEnabled           bool
	AppEmailSenderPolicyPath        string
	AppEmailVerificationEnabled     bool
	AppEmailVerificationProvider    string
	AppEmailVerificationWhitelist   []string
	AppSendEnabled                  bool
	DebugMode                       bool
	DebugDataPath                   string
	SendGridApiHost                 string
	SendGridEmailVerificationApiKey string
	SendGridEmailSendApiKey         string
	AppEmailFailoverEnabled         bool
	AppEmailFailoverProviders       []string
	AppEmailFailoverCacheTTL        time.Duration
	AppEmailRateLimitEnabled        bool
	AppEmailRateLimitTableName      string
	AppEmailRateLimit               *ratelimit.Config
	AppSMSSenderEnabled             bool
	AppSMSSenderPolicyPath          string
	AppSMSHistoryTableName          string
	AppSMSHistoryTTL                time.Duration
	AppSMSThrottlePeriod            time.Duration
}

func New() (*Config, error) {
	cfg, err := fromEnv()
	if err != nil {
		return nil, err
	}

	awscfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %w", err)
	}
	cfg.AWSConfig = &awscfg

	return cfg, nil
}

func fromEnv() (*Config, error) {
	debug := envBool("APP_DEBUG_MODE", false)

	cfg := &Config{
		AppLogLevel:                     slog.LevelInfo,
		AppKmsKeyId:                     envWithFallback("APP_KMS_KEY_ID", "KMS_KEY_ID"),
		AppEmailProvider:                cmp.Or(envLower("APP_EMAIL_PROVIDER"), "ses"),
		AppEmailSenderEnabled:           envBool("APP_EMAIL_SENDER_ENABLED", true),
		AppEmailSenderPolicyPath:        os.Getenv("APP_EMAIL_SENDER_POLICY_PATH"),
		AppEmailVerificationEnabled:     envBool("APP_EMAIL_VERIFICATION_ENABLED", true),
		AppEmailVerificationProvider:    envLower("APP_EMAIL_VERIFICATION_PROVIDER"),
		AppEmailVerificationWhitelist:   envLowerList("APP_EMAIL_VERIFICATION_WHITELIST"),
		AppSendEnabled:                  envBool("APP_SEND_ENABLED", !debug),
		DebugMode:                       debug,
		DebugDataPath:                   os.Getenv("APP_DEBUG_DATA_PATH"),
		SendGridApiHost:                 cmp.Or(os.Getenv("APP_SENDGRID_API_HOST"), "https://api.sendgrid.com"),
		SendGridEmailSendApiKey:         os.Getenv("APP_SENDGRID_EMAIL_SEND_API_KEY"),
		SendGridEmailVerificationApiKey: envWithFallback("APP_SENDGRID_EMAIL_VERIFICATION_API_KEY", "APP_SENDGRID_API_KEY"),
		AppEmailFailoverEnabled:         envBool("APP_EMAIL_FAILOVER_ENABLED", false),
		AppEmailFailoverProviders:       envLowerList("APP_EMAIL_FAILOVER_PROVIDERS"),
		AppEmailFailoverCacheTTL:        defaultFailoverCacheTTL,
		AppEmailRateLimitEnabled:        envBool("APP_EMAIL_RATE_LIMIT_ENABLED", false),
		AppEmailRateLimitTableName:      strings.TrimSpace(os.Getenv("APP_EMAIL_RATE_LIMIT_TABLE_NAME")),
		AppSMSSenderEnabled:             envBool("APP_SMS_SENDER_ENABLED", false),
		AppSMSSenderPolicyPath:          os.Getenv("APP_SMS_SENDER_POLICY_PATH"),
		AppSMSHistoryTableName:          strings.TrimSpace(os.Getenv("APP_SMS_HISTORY_TABLE_NAME")),
		AppSMSHistoryTTL:                defaultSMSHistoryTTL,
		AppSMSThrottlePeriod:            defaultSMSThrottle,
	}

	if s := os.Getenv("APP_LOG_LEVEL"); s != "" {
		var level slog.Level
		if err := level.UnmarshalText([]byte(s)); err != nil {
			slog.Warn("invalid APP_LOG_LEVEL, using default", "value", s, "default", cfg.AppLogLevel)
		} else {
			cfg.AppLogLevel = level
		}
	}

	if s := os.Getenv("APP_EMAIL_FAILOVER_CACHE_TTL"); s != "" {
		ttl, err := time.ParseDuration(s)
		if err != nil || ttl < 0 {
			slog.Warn("invalid APP_EMAIL_FAILOVER_CACHE_TTL, using default", "value", s, "default", defaultFailoverCacheTTL)
		} else {
			cfg.AppEmailFailoverCacheTTL = ttl
		}
	}

	for key, dst := range map[string]*time.Duration{
		"APP_SMS_HISTORY_TTL":     &cfg.AppSMSHistoryTTL,
		"APP_SMS_THROTTLE_PERIOD": &cfg.AppSMSThrottlePeriod,
	} {
		if s := os.Getenv(key); s != "" {
			d, err := time.ParseDuration(s)
			if err != nil || d <= 0 {
				return nil, fmt.Errorf("invalid %s %q: must be a positive go duration", key, s)
			}
			*dst = d
		}
	}

	// the rate limit config is only read when the feature is enabled, so an
	// invalid value cannot affect deployments that leave it off
	if cfg.AppEmailRateLimitEnabled {
		rl, err := ratelimit.ParseConfig(os.Getenv("APP_EMAIL_RATE_LIMIT_CONFIG"))
		if err != nil {
			return nil, fmt.Errorf("invalid APP_EMAIL_RATE_LIMIT_CONFIG: %w", err)
		}
		cfg.AppEmailRateLimit = rl
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.AppKmsKeyId == "" {
		return errors.New("APP_KMS_KEY_ID is required")
	}

	if !c.AppEmailSenderEnabled && !c.AppSMSSenderEnabled {
		return errors.New("at least one of APP_EMAIL_SENDER_ENABLED or APP_SMS_SENDER_ENABLED must be true")
	}

	if c.AppEmailSenderEnabled && c.AppEmailSenderPolicyPath == "" {
		return errors.New("APP_EMAIL_SENDER_POLICY_PATH is required")
	}

	if c.AppSMSSenderEnabled {
		if c.AppSMSSenderPolicyPath == "" {
			return errors.New("APP_SMS_SENDER_POLICY_PATH is required when APP_SMS_SENDER_ENABLED is true")
		}
		// debug mode falls back to an in-memory history when no table is set
		if c.AppSMSHistoryTableName == "" && !c.DebugMode {
			return errors.New("APP_SMS_HISTORY_TABLE_NAME is required when APP_SMS_SENDER_ENABLED is true")
		}
	}

	if !isValidProvider(c.AppEmailProvider) {
		return fmt.Errorf("invalid APP_EMAIL_PROVIDER %q: must be 'ses' or 'sendgrid'", c.AppEmailProvider)
	}

	if c.AppEmailVerificationEnabled && c.AppEmailVerificationProvider == "sendgrid" && c.SendGridEmailVerificationApiKey == "" {
		return errors.New("APP_SENDGRID_EMAIL_VERIFICATION_API_KEY is required when using sendgrid email verification")
	}

	if c.AppEmailFailoverEnabled {
		if len(c.AppEmailFailoverProviders) == 0 {
			return errors.New("APP_EMAIL_FAILOVER_PROVIDERS is required when failover is enabled")
		}
		for _, p := range c.AppEmailFailoverProviders {
			if !isValidProvider(p) {
				return fmt.Errorf("invalid failover provider %q: must be 'ses' or 'sendgrid'", p)
			}
		}
	}

	if slices.Contains(c.ProviderChain(), "sendgrid") && c.SendGridEmailSendApiKey == "" {
		return errors.New("APP_SENDGRID_EMAIL_SEND_API_KEY is required when sendgrid is used for sending")
	}

	if c.AppEmailRateLimitEnabled {
		if c.AppEmailRateLimit == nil {
			return errors.New("rate limit config is required when APP_EMAIL_RATE_LIMIT_ENABLED is true")
		}
		// debug mode falls back to an in-memory store when no table is set
		if c.AppEmailRateLimitTableName == "" && !c.DebugMode {
			return errors.New("APP_EMAIL_RATE_LIMIT_TABLE_NAME is required when APP_EMAIL_RATE_LIMIT_ENABLED is true")
		}
	}

	return nil
}

func (c *Config) ProviderChain() []string {
	chain := []string{c.AppEmailProvider}
	if !c.AppEmailFailoverEnabled {
		return chain
	}
	for _, p := range c.AppEmailFailoverProviders {
		if !slices.Contains(chain, p) {
			chain = append(chain, p)
		}
	}
	return chain
}

func isValidProvider(p string) bool {
	return p == "ses" || p == "sendgrid"
}

func envBool(key string, def bool) bool {
	s := os.Getenv(key)
	if s == "" {
		return def
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		slog.Warn("invalid boolean env var, using default", "key", key, "value", s, "default", def)
		return def
	}
	return v
}

func envLower(key string) string {
	return strings.ToLower(strings.TrimSpace(os.Getenv(key)))
}

func envLowerList(key string) []string {
	var out []string
	for item := range strings.SplitSeq(envLower(key), ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func envWithFallback(key, deprecated string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	v := os.Getenv(deprecated)
	if v != "" {
		slog.Warn("deprecated env var used", "old", deprecated, "new", key)
	}
	return v
}
