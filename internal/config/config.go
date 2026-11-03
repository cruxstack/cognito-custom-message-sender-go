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
)

const defaultFailoverCacheTTL = 30 * time.Second

type Config struct {
	AWSConfig                       *aws.Config
	AppLogLevel                     slog.Level
	AppKmsKeyId                     string
	AppEmailProvider                string
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

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.AppKmsKeyId == "" {
		return errors.New("APP_KMS_KEY_ID is required")
	}

	if c.AppEmailSenderPolicyPath == "" {
		return errors.New("APP_EMAIL_SENDER_POLICY_PATH is required")
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
