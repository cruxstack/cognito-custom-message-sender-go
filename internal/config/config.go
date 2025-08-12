package config

import (
	"context"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/charmbracelet/log"
)

type Config struct {
	AWSConfig                          *aws.Config
	AppLogLevel                        log.Level
	AppKmsKeyId                        string
	AppEmailProvider                   string
	AppEmailSenderPolicyPath           string
	AppSendEnabled                     bool
	DebugMode                          bool
	DebugDataPath                      string
	SendGridApiHost                    string
	SendGridEmailVerificationEnabled   bool
	SendGridEmailVerificationAllowlist []string
	SendGridApiKey                     string
}

func New() (*Config, error) {
	awscfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}

	cfg := Config{
		DebugMode:                          os.Getenv("APP_DEBUG_MODE") == "true",
		DebugDataPath:                      os.Getenv("APP_DEBUG_DATA_PATH"),
		AWSConfig:                          &awscfg,
		AppKmsKeyId:                        os.Getenv("APP_KMS_KEY_ID"),
		AppLogLevel:                        log.InfoLevel,
		AppEmailProvider:                   "ses",
		AppEmailSenderPolicyPath:           os.Getenv("APP_EMAIL_SENDER_POLICY_PATH"),
		AppSendEnabled:                     true,
		SendGridApiKey:                     os.Getenv("APP_SENDGRID_API_KEY"),
		SendGridApiHost:                    os.Getenv("APP_SENDGRID_API_HOST"),
		SendGridEmailVerificationAllowlist: []string{},
		SendGridEmailVerificationEnabled:   os.Getenv("APP_SENDGRID_EMAIL_VERIFICATION_ENABLED") == "true",
	}

	// disable send if debug mode by default
	if cfg.DebugMode && os.Getenv("APP_SEND_ENABLED") != "true" {
		cfg.AppSendEnabled = false
	}

	logLevel, err := log.ParseLevel(os.Getenv("APP_LOG_LEVEL"))
	if err == nil {
		cfg.AppLogLevel = logLevel
	}

	allowlistStr := strings.TrimSpace(os.Getenv("APP_SENDGRID_EMAIL_VERIFICATION_ALLOWLIST"))
	if allowlistStr != "" {
		allowlist := strings.Split(allowlistStr, ",")
		for i, x := range allowlist {
			allowlist[i] = strings.TrimSpace(x)
		}
		cfg.SendGridEmailVerificationAllowlist = allowlist
	}

	if cfg.SendGridApiHost == "" {
		cfg.SendGridApiHost = "https://api.sendgrid.com"
	}

	// deprecated
	if cfg.AppKmsKeyId == "" && os.Getenv("KMS_KEY_ID") != "" {
		cfg.AppKmsKeyId = os.Getenv("KMS_KEY_ID")
		log.Warn("KMS_KEY_ID env is deprecated; use APP_KMS_KEY_ID")
	}

	return &cfg, nil
}
