package config

import (
	"os"

	"github.com/charmbracelet/log"
)

type Config struct {
	AppLogLevel                      log.Level
	AppKmsKeyId                      string
	AppEmailSenderPolicyPath         string
	DebugMode                        bool
	DebugDataPath                    string
	AppSendEnabled                   bool
	SendGridApiHost                  string
	SendGridEmailVerificationEnabled bool
	SendGridApiKey                   string
}

func New() (*Config, error) {
	cfg := Config{
		DebugMode:                        os.Getenv("APP_DEBUG_MODE") == "true",
		DebugDataPath:                    os.Getenv("APP_DEBUG_DATA_PATH"),
		AppKmsKeyId:                      os.Getenv("APP_KMS_KEY_ID"),
		AppLogLevel:                      log.InfoLevel,
		AppEmailSenderPolicyPath:         os.Getenv("APP_EMAIL_SENDER_POLICY_PATH"),
		AppSendEnabled:                   true,
		SendGridApiKey:                   os.Getenv("APP_SENDGRID_API_KEY"),
		SendGridApiHost:                  os.Getenv("APP_SENDGRID_API_HOST"),
		SendGridEmailVerificationEnabled: os.Getenv("APP_SENDGRID_EMAIL_VERIFICATION_ENABLED") == "true",
	}

	// disable send if debug mode by default
	if cfg.DebugMode && os.Getenv("APP_SEND_ENABLED") != "true" {
		cfg.AppSendEnabled = false
	}

	logLevel, err := log.ParseLevel(os.Getenv("APP_LOG_LEVEL"))
	if err == nil {
		cfg.AppLogLevel = logLevel
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
