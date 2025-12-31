package config

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/charmbracelet/log"
)

type Config struct {
	AWSConfig                       *aws.Config
	AppLogLevel                     log.Level
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
		AppLogLevel:                     log.InfoLevel,
		AppEmailProvider:                os.Getenv("APP_EMAIL_PROVIDER"),
		AppEmailSenderPolicyPath:        os.Getenv("APP_EMAIL_SENDER_POLICY_PATH"),
		AppEmailVerificationEnabled:     os.Getenv("APP_EMAIL_VERIFICATION_ENABLED") != "false",
		AppEmailVerificationProvider:    os.Getenv("APP_EMAIL_VERIFICATION_PROVIDER"),
		AppEmailVerificationWhitelist:   []string{},
		AppSendEnabled:                  true,
		SendGridApiHost:                 os.Getenv("APP_SENDGRID_API_HOST"),
		SendGridEmailSendApiKey:         os.Getenv("APP_SENDGRID_EMAIL_SEND_API_KEY"),
		SendGridEmailVerificationApiKey: os.Getenv("APP_SENDGRID_EMAIL_VERIFICATION_API_KEY"),
	}

	// disable send if debug mode by default
	if cfg.DebugMode && os.Getenv("APP_SEND_ENABLED") != "true" {
		cfg.AppSendEnabled = false
	}

	logLevel, err := log.ParseLevel(os.Getenv("APP_LOG_LEVEL"))
	if err == nil {
		cfg.AppLogLevel = logLevel
	}

	if cfg.AppEmailProvider == "" || (cfg.AppEmailProvider != "ses" && cfg.AppEmailProvider != "sendgrid") {
		log.Warn("fallback to ses for email provider because of unknown provider", "provider", cfg.AppEmailProvider)
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

	// deprecated
	if cfg.AppKmsKeyId == "" && os.Getenv("KMS_KEY_ID") != "" {
		cfg.AppKmsKeyId = os.Getenv("KMS_KEY_ID")
		log.Warn("KMS_KEY_ID env is deprecated; use APP_KMS_KEY_ID")
	}

	if cfg.SendGridEmailVerificationApiKey == "" && os.Getenv("APP_SENDGRID_API_KEY") != "" {
		cfg.SendGridEmailVerificationApiKey = os.Getenv("APP_SENDGRID_API_KEY")
		log.Warn("APP_SENDGRID_API_KEY env is deprecated; use APP_SENDGRID_EMAIL_VERIFICATION_API_KEY")
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

	return nil
}
