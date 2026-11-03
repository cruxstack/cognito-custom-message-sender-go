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
		"APP_EMAIL_RATE_LIMIT_ENABLED",
		"APP_EMAIL_RATE_LIMIT_TABLE_NAME",
		"APP_EMAIL_RATE_LIMIT_CONFIG",
		"APP_EMAIL_SENDER_ENABLED",
		"APP_SMS_SENDER_ENABLED",
		"APP_SMS_SENDER_POLICY_PATH",
		"APP_SMS_HISTORY_TABLE_NAME",
		"APP_SMS_HISTORY_TTL",
		"APP_SMS_THROTTLE_PERIOD",
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
		{
			"rate limit without table",
			map[string]string{"APP_EMAIL_RATE_LIMIT_ENABLED": "true"},
			"APP_EMAIL_RATE_LIMIT_TABLE_NAME",
		},
		{
			"rate limit with invalid json",
			map[string]string{"APP_EMAIL_RATE_LIMIT_ENABLED": "true", "APP_EMAIL_RATE_LIMIT_TABLE_NAME": "t", "APP_EMAIL_RATE_LIMIT_CONFIG": "{"},
			"APP_EMAIL_RATE_LIMIT_CONFIG",
		},
		{
			"no sender enabled",
			map[string]string{"APP_EMAIL_SENDER_ENABLED": "false"},
			"at least one of",
		},
		{
			"sms without policy",
			map[string]string{"APP_SMS_SENDER_ENABLED": "true", "APP_SMS_HISTORY_TABLE_NAME": "t"},
			"APP_SMS_SENDER_POLICY_PATH",
		},
		{
			"sms without history table",
			map[string]string{"APP_SMS_SENDER_ENABLED": "true", "APP_SMS_SENDER_POLICY_PATH": "sms.rego"},
			"APP_SMS_HISTORY_TABLE_NAME",
		},
		{
			"sms invalid throttle period",
			map[string]string{"APP_SMS_THROTTLE_PERIOD": "15"},
			"APP_SMS_THROTTLE_PERIOD",
		},
		{
			"sms negative history ttl",
			map[string]string{"APP_SMS_HISTORY_TTL": "-1h"},
			"APP_SMS_HISTORY_TTL",
		},
		{
			"rate limit with invalid values",
			map[string]string{
				"APP_EMAIL_RATE_LIMIT_ENABLED":    "true",
				"APP_EMAIL_RATE_LIMIT_TABLE_NAME": "t",
				"APP_EMAIL_RATE_LIMIT_CONFIG":     `{"global": {"mode": "block"}}`,
			},
			"global.mode",
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

func TestFromEnv_RateLimitDisabled(t *testing.T) {
	setBaseEnv(t)
	// an invalid config is ignored while the feature is off
	t.Setenv("APP_EMAIL_RATE_LIMIT_CONFIG", "{not json")

	cfg, err := fromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AppEmailRateLimitEnabled || cfg.AppEmailRateLimit != nil {
		t.Errorf("rate limit enabled = %v, config = %+v; want disabled", cfg.AppEmailRateLimitEnabled, cfg.AppEmailRateLimit)
	}
}

func TestFromEnv_RateLimitEnabled(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("APP_EMAIL_RATE_LIMIT_ENABLED", "true")
	t.Setenv("APP_EMAIL_RATE_LIMIT_TABLE_NAME", " rate-limit-table ")
	t.Setenv("APP_EMAIL_RATE_LIMIT_CONFIG", `{"failMode": "closed"}`)

	cfg, err := fromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AppEmailRateLimitTableName != "rate-limit-table" {
		t.Errorf("AppEmailRateLimitTableName = %q", cfg.AppEmailRateLimitTableName)
	}
	if cfg.AppEmailRateLimit == nil || cfg.AppEmailRateLimit.FailMode != "closed" || cfg.AppEmailRateLimit.Global.Mode != "count" {
		t.Errorf("AppEmailRateLimit = %+v, want overrides applied over defaults", cfg.AppEmailRateLimit)
	}
}

func TestFromEnv_RateLimitDebugWithoutTable(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("APP_DEBUG_MODE", "true")
	t.Setenv("APP_EMAIL_RATE_LIMIT_ENABLED", "true")

	cfg, err := fromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AppEmailRateLimit == nil {
		t.Error("AppEmailRateLimit = nil, want defaults")
	}
}

func TestFromEnv_SenderDefaults(t *testing.T) {
	setBaseEnv(t)

	cfg, err := fromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.AppEmailSenderEnabled || cfg.AppSMSSenderEnabled {
		t.Errorf("email = %v, sms = %v; want email only by default", cfg.AppEmailSenderEnabled, cfg.AppSMSSenderEnabled)
	}
	if cfg.AppSMSHistoryTTL != defaultSMSHistoryTTL || cfg.AppSMSThrottlePeriod != defaultSMSThrottle {
		t.Errorf("sms durations = %v, %v", cfg.AppSMSHistoryTTL, cfg.AppSMSThrottlePeriod)
	}
}

func TestFromEnv_SMSOnly(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("APP_EMAIL_SENDER_POLICY_PATH", "")
	t.Setenv("APP_EMAIL_SENDER_ENABLED", "false")
	t.Setenv("APP_SMS_SENDER_ENABLED", "true")
	t.Setenv("APP_SMS_SENDER_POLICY_PATH", "sms.rego")
	t.Setenv("APP_SMS_HISTORY_TABLE_NAME", " sms-history ")
	t.Setenv("APP_SMS_HISTORY_TTL", "48h")
	t.Setenv("APP_SMS_THROTTLE_PERIOD", "5m")

	cfg, err := fromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AppSMSHistoryTableName != "sms-history" || cfg.AppSMSHistoryTTL != 48*time.Hour || cfg.AppSMSThrottlePeriod != 5*time.Minute {
		t.Errorf("sms config = %q, %v, %v", cfg.AppSMSHistoryTableName, cfg.AppSMSHistoryTTL, cfg.AppSMSThrottlePeriod)
	}
}

func TestFromEnv_SMSDebugWithoutTable(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("APP_DEBUG_MODE", "true")
	t.Setenv("APP_SMS_SENDER_ENABLED", "true")
	t.Setenv("APP_SMS_SENDER_POLICY_PATH", "sms.rego")

	if _, err := fromEnv(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
