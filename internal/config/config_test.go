package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func setBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("APP_KMS_KEY_ID", "arn:aws:kms:us-east-1:111122223333:key/test")
	t.Setenv("APP_EMAIL_SENDER_POLICY_PATH", "policy.rego")
	for _, key := range []string{
		"APP_DEBUG_MODE",
		"APP_SEND_ENABLED",
		"APP_EMAIL_PROVIDER",
		"APP_EMAIL_VERIFICATION_ENABLED",
		"APP_EMAIL_VERIFICATION_PROVIDER",
		"APP_EMAIL_VERIFICATION_WHITELIST",
		"APP_EMAIL_FAILOVER_ENABLED",
		"APP_EMAIL_FAILOVER_PROVIDERS",
		"APP_EMAIL_FAILOVER_CACHE_TTL",
		"APP_LOG_LEVEL",
		"APP_SENDGRID_API_KEY",
		"APP_SENDGRID_EMAIL_SEND_API_KEY",
		"APP_SENDGRID_EMAIL_VERIFICATION_API_KEY",
		"KMS_KEY_ID",
	} {
		t.Setenv(key, "")
	}
}

func TestFromEnv_SendEnabled(t *testing.T) {
	tests := []struct {
		name        string
		debug       string
		sendEnabled string
		want        bool
	}{
		{"default", "", "", true},
		{"disabled", "", "false", false},
		{"debug default", "true", "", false},
		{"debug enabled", "true", "true", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setBaseEnv(t)
			t.Setenv("APP_DEBUG_MODE", tc.debug)
			t.Setenv("APP_SEND_ENABLED", tc.sendEnabled)

			cfg, err := fromEnv()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.AppSendEnabled != tc.want {
				t.Errorf("AppSendEnabled = %v, want %v", cfg.AppSendEnabled, tc.want)
			}
		})
	}
}

func TestFromEnv_Defaults(t *testing.T) {
	setBaseEnv(t)

	cfg, err := fromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AppEmailProvider != "ses" {
		t.Errorf("AppEmailProvider = %q, want ses", cfg.AppEmailProvider)
	}
	if !cfg.AppEmailVerificationEnabled {
		t.Error("AppEmailVerificationEnabled = false, want true")
	}
	if cfg.AppEmailFailoverCacheTTL != defaultFailoverCacheTTL {
		t.Errorf("AppEmailFailoverCacheTTL = %v, want %v", cfg.AppEmailFailoverCacheTTL, defaultFailoverCacheTTL)
	}
	if cfg.SendGridApiHost != "https://api.sendgrid.com" {
		t.Errorf("SendGridApiHost = %q", cfg.SendGridApiHost)
	}
}

func TestFromEnv_Normalization(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("APP_EMAIL_PROVIDER", " SendGrid ")
	t.Setenv("APP_SENDGRID_EMAIL_SEND_API_KEY", "key")
	t.Setenv("APP_EMAIL_VERIFICATION_WHITELIST", " Example.com, ,trusted.org,")
	t.Setenv("APP_EMAIL_FAILOVER_ENABLED", "true")
	t.Setenv("APP_EMAIL_FAILOVER_PROVIDERS", "SES, sendgrid")
	t.Setenv("APP_EMAIL_FAILOVER_CACHE_TTL", "-1s")

	cfg, err := fromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AppEmailProvider != "sendgrid" {
		t.Errorf("AppEmailProvider = %q, want sendgrid", cfg.AppEmailProvider)
	}
	if want := []string{"example.com", "trusted.org"}; !slices.Equal(cfg.AppEmailVerificationWhitelist, want) {
		t.Errorf("AppEmailVerificationWhitelist = %v, want %v", cfg.AppEmailVerificationWhitelist, want)
	}
	if want := []string{"sendgrid", "ses"}; !slices.Equal(cfg.ProviderChain(), want) {
		t.Errorf("ProviderChain() = %v, want %v", cfg.ProviderChain(), want)
	}
	if cfg.AppEmailFailoverCacheTTL != defaultFailoverCacheTTL {
		t.Errorf("AppEmailFailoverCacheTTL = %v, want default", cfg.AppEmailFailoverCacheTTL)
	}
}

func TestFromEnv_DeprecatedVars(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("APP_KMS_KEY_ID", "")
	t.Setenv("KMS_KEY_ID", "legacy-key")
	t.Setenv("APP_SENDGRID_API_KEY", "legacy-verification-key")

	cfg, err := fromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AppKmsKeyId != "legacy-key" {
		t.Errorf("AppKmsKeyId = %q, want legacy-key", cfg.AppKmsKeyId)
	}
	if cfg.SendGridEmailVerificationApiKey != "legacy-verification-key" {
		t.Errorf("SendGridEmailVerificationApiKey = %q", cfg.SendGridEmailVerificationApiKey)
	}
}

func TestFromEnv_FailoverCacheTTL(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("APP_EMAIL_FAILOVER_CACHE_TTL", "1m")

	cfg, err := fromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AppEmailFailoverCacheTTL != time.Minute {
		t.Errorf("AppEmailFailoverCacheTTL = %v, want 1m", cfg.AppEmailFailoverCacheTTL)
	}
}

func TestFromEnv_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{"missing kms key", map[string]string{"APP_KMS_KEY_ID": ""}, "APP_KMS_KEY_ID"},
		{"missing policy path", map[string]string{"APP_EMAIL_SENDER_POLICY_PATH": ""}, "APP_EMAIL_SENDER_POLICY_PATH"},
		{"unknown provider", map[string]string{"APP_EMAIL_PROVIDER": "smtp"}, "APP_EMAIL_PROVIDER"},
		{"sendgrid without key", map[string]string{"APP_EMAIL_PROVIDER": "sendgrid"}, "APP_SENDGRID_EMAIL_SEND_API_KEY"},
		{
			"sendgrid verification without key",
			map[string]string{"APP_EMAIL_VERIFICATION_PROVIDER": "sendgrid"},
			"APP_SENDGRID_EMAIL_VERIFICATION_API_KEY",
		},
		{"failover without providers", map[string]string{"APP_EMAIL_FAILOVER_ENABLED": "true"}, "APP_EMAIL_FAILOVER_PROVIDERS"},
		{
			"invalid failover provider",
			map[string]string{"APP_EMAIL_FAILOVER_ENABLED": "true", "APP_EMAIL_FAILOVER_PROVIDERS": "smtp"},
			"invalid failover provider",
		},
		{
			"sendgrid failover without key",
			map[string]string{"APP_EMAIL_FAILOVER_ENABLED": "true", "APP_EMAIL_FAILOVER_PROVIDERS": "sendgrid"},
			"APP_SENDGRID_EMAIL_SEND_API_KEY",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setBaseEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			_, err := fromEnv()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
