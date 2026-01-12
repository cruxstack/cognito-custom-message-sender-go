package config

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

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

	// Failover configuration
	AppEmailFailoverEnabled   bool
	AppEmailFailoverProviders []string
	AppEmailFailoverCacheTTL  time.Duration
}

func New() (*Config, error) {
	awscfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}

	cfg := Config{
		DebugMode:                       os.Getenv("APP_DEBUG_MODE") == "true",
		DebugDataPath:                   os.Getenv("APP_DEBUG_DATA_PATH"),
		AWSConfig:                       &awscfg,
		AppKmsKeyId:                     os.Getenv("APP_KMS_KEY_ID"),
		AppLogLevel:                     slog.LevelInfo,
		AppEmailProvider:                os.Getenv("APP_EMAIL_PROVIDER"),
		AppEmailSenderPolicyPath:        os.Getenv("APP_EMAIL_SENDER_POLICY_PATH"),
		AppEmailVerificationEnabled:     os.Getenv("APP_EMAIL_VERIFICATION_ENABLED") != "false",
		AppEmailVerificationProvider:    os.Getenv("APP_EMAIL_VERIFICATION_PROVIDER"),
		AppEmailVerificationWhitelist:   []string{},
		AppSendEnabled:                  true,
		SendGridApiHost:                 os.Getenv("APP_SENDGRID_API_HOST"),
		SendGridEmailSendApiKey:         os.Getenv("APP_SENDGRID_EMAIL_SEND_API_KEY"),
		SendGridEmailVerificationApiKey: os.Getenv("APP_SENDGRID_EMAIL_VERIFICATION_API_KEY"),

		// Failover defaults
		AppEmailFailoverEnabled:   os.Getenv("APP_EMAIL_FAILOVER_ENABLED") == "true",
		AppEmailFailoverProviders: []string{},
		AppEmailFailoverCacheTTL:  30 * time.Second,
	}

	// disable send if debug mode by default
	if cfg.DebugMode && os.Getenv("APP_SEND_ENABLED") != "true" {
		cfg.AppSendEnabled = false
	}

	if levelStr := os.Getenv("APP_LOG_LEVEL"); levelStr != "" {
		var level slog.Level
		if err := level.UnmarshalText([]byte(levelStr)); err == nil {
			cfg.AppLogLevel = level
		}
	}

	if cfg.AppEmailProvider == "" || (cfg.AppEmailProvider != "ses" && cfg.AppEmailProvider != "sendgrid") {
		slog.Warn("unknown email provider, defaulting to ses", "provider", cfg.AppEmailProvider)
		cfg.AppEmailProvider = "ses"
	}

	whitelistStr := strings.TrimSpace(os.Getenv("APP_EMAIL_VERIFICATION_WHITELIST"))
	if whitelistStr != "" {
		whitelist := strings.Split(whitelistStr, ",")
		for i, x := range whitelist {
			whitelist[i] = strings.TrimSpace(x)
		}
		cfg.AppEmailVerificationWhitelist = whitelist
	}

	if cfg.SendGridApiHost == "" {
		cfg.SendGridApiHost = "https://api.sendgrid.com"
	}

	// Parse failover providers
	failoverProvidersStr := strings.TrimSpace(os.Getenv("APP_EMAIL_FAILOVER_PROVIDERS"))
	if failoverProvidersStr != "" {
		providers := strings.Split(failoverProvidersStr, ",")
		for i, p := range providers {
			providers[i] = strings.TrimSpace(p)
		}
		cfg.AppEmailFailoverProviders = providers
	}

	// Parse failover cache TTL
	if ttlStr := os.Getenv("APP_EMAIL_FAILOVER_CACHE_TTL"); ttlStr != "" {
		if ttl, err := time.ParseDuration(ttlStr); err == nil {
			cfg.AppEmailFailoverCacheTTL = ttl
		} else {
			slog.Warn("invalid APP_EMAIL_FAILOVER_CACHE_TTL, using default", "value", ttlStr, "default", "30s")
		}
	}

	// deprecated
	if cfg.AppKmsKeyId == "" && os.Getenv("KMS_KEY_ID") != "" {
		cfg.AppKmsKeyId = os.Getenv("KMS_KEY_ID")
		slog.Warn("deprecated env var used", "old", "KMS_KEY_ID", "new", "APP_KMS_KEY_ID")
	}

	if cfg.SendGridEmailVerificationApiKey == "" && os.Getenv("APP_SENDGRID_API_KEY") != "" {
		cfg.SendGridEmailVerificationApiKey = os.Getenv("APP_SENDGRID_API_KEY")
		slog.Warn("deprecated env var used", "old", "APP_SENDGRID_API_KEY", "new", "APP_SENDGRID_EMAIL_VERIFICATION_API_KEY")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Validate checks that required configuration fields are set and valid
func (c *Config) Validate() error {
	if c.AppKmsKeyId == "" {
		return errors.New("APP_KMS_KEY_ID is required")
	}

	if c.AppEmailSenderPolicyPath == "" {
		return errors.New("APP_EMAIL_SENDER_POLICY_PATH is required")
	}

	if c.AppEmailProvider == "sendgrid" && c.SendGridEmailSendApiKey == "" {
		return errors.New("APP_SENDGRID_EMAIL_SEND_API_KEY is required when using sendgrid provider")
	}

	if c.AppEmailVerificationEnabled && c.AppEmailVerificationProvider == "sendgrid" && c.SendGridEmailVerificationApiKey == "" {
		return errors.New("APP_SENDGRID_EMAIL_VERIFICATION_API_KEY is required when using sendgrid email verification")
	}

	// Validate failover configuration
	if c.AppEmailFailoverEnabled {
		if len(c.AppEmailFailoverProviders) == 0 {
			return errors.New("APP_EMAIL_FAILOVER_PROVIDERS is required when failover is enabled")
		}

		// Validate each failover provider
		validProviders := map[string]bool{"ses": true, "sendgrid": true}
		for _, p := range c.AppEmailFailoverProviders {
			if !validProviders[p] {
				return errors.New("invalid failover provider: " + p + " (must be 'ses' or 'sendgrid')")
			}
		}

		// Check that credentials exist for each failover provider
		allProviders := append([]string{c.AppEmailProvider}, c.AppEmailFailoverProviders...)
		for _, p := range allProviders {
			if p == "sendgrid" && c.SendGridEmailSendApiKey == "" {
				return errors.New("APP_SENDGRID_EMAIL_SEND_API_KEY is required when sendgrid is in failover chain")
			}
		}
	}

	return nil
}
