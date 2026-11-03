package config

import (
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
)

func env(vars map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := vars[key]
		return v, ok
	}
}

// minimal is the smallest valid configuration.
func minimal() map[string]string {
	return map[string]string{
		"APP_KMS_KEY_ID":               "arn:aws:kms:us-east-1:111122223333:key/example",
		"APP_EMAIL_SENDER_POLICY_PATH": "policy.rego",
	}
}

func with(extra map[string]string) map[string]string {
	vars := minimal()
	for k, v := range extra {
		vars[k] = v
	}
	return vars
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load(env(minimal()))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.LogLevel != slog.LevelInfo || !cfg.SendEnabled {
		t.Errorf("log level %v, send enabled %v", cfg.LogLevel, cfg.SendEnabled)
	}
	e := cfg.Email
	if !e.Enabled || !slices.Equal(e.Providers, []string{"ses"}) || e.HealthCheckTTL != 30*time.Second ||
		!e.VerificationEnabled || e.VerificationProvider != "offline" || e.RateLimitEnabled || e.RateLimit != nil {
		t.Errorf("email = %+v", e)
	}
	if cfg.SMS.Enabled || cfg.SMS.HistoryTTL != 30*24*time.Hour || cfg.SMS.ThrottlePeriod != 15*time.Minute {
		t.Errorf("sms = %+v", cfg.SMS)
	}
	if cfg.SendGrid.APIHost != "https://api.sendgrid.com" {
		t.Errorf("sendgrid = %+v", cfg.SendGrid)
	}
}

func TestLoad_Full(t *testing.T) {
	cfg, err := Load(env(with(map[string]string{
		"APP_LOG_LEVEL":                           "WARN",
		"APP_SEND_ENABLED":                        "false",
		"APP_EMAIL_PROVIDERS":                     " SES , sendgrid ",
		"APP_EMAIL_HEALTH_CHECK_TTL":              "1m",
		"APP_EMAIL_VERIFICATION_PROVIDER":         "SendGrid",
		"APP_EMAIL_VERIFICATION_ALLOWLIST":        "Example.com, ,example.org",
		"APP_EMAIL_RATE_LIMIT_ENABLED":            "true",
		"APP_EMAIL_RATE_LIMIT_TABLE_NAME":         "rate-limits",
		"APP_EMAIL_RATE_LIMIT_CONFIG":             `{"failMode":"closed"}`,
		"APP_SMS_SENDER_ENABLED":                  "true",
		"APP_SMS_SENDER_POLICY_PATH":              "sms.rego",
		"APP_SMS_HISTORY_TABLE_NAME":              "history",
		"APP_SMS_HISTORY_TTL":                     "48h",
		"APP_SMS_THROTTLE_PERIOD":                 "5m",
		"APP_SENDGRID_API_HOST":                   "https://api.eu.sendgrid.com",
		"APP_SENDGRID_EMAIL_SEND_API_KEY":         "SG.send",
		"APP_SENDGRID_EMAIL_VERIFICATION_API_KEY": "SG.verify",
	})))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.LogLevel != slog.LevelWarn || cfg.SendEnabled {
		t.Errorf("log level %v, send enabled %v", cfg.LogLevel, cfg.SendEnabled)
	}
	e := cfg.Email
	if !slices.Equal(e.Providers, []string{"ses", "sendgrid"}) || e.HealthCheckTTL != time.Minute ||
		e.VerificationProvider != "sendgrid" || !slices.Equal(e.VerificationAllowlist, []string{"example.com", "example.org"}) {
		t.Errorf("email = %+v", e)
	}
	if !e.RateLimitEnabled || e.RateLimitTableName != "rate-limits" || e.RateLimit == nil || e.RateLimit.FailMode != "closed" {
		t.Errorf("rate limit = %v %q %+v", e.RateLimitEnabled, e.RateLimitTableName, e.RateLimit)
	}
	if s := cfg.SMS; !s.Enabled || s.PolicyPath != "sms.rego" || s.HistoryTableName != "history" || s.HistoryTTL != 48*time.Hour || s.ThrottlePeriod != 5*time.Minute {
		t.Errorf("sms = %+v", s)
	}
	if g := cfg.SendGrid; g.APIHost != "https://api.eu.sendgrid.com" || g.SendAPIKey != "SG.send" || g.VerificationAPIKey != "SG.verify" {
		t.Errorf("sendgrid = %+v", g)
	}
}

func TestLoad_SMSOnly(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"APP_KMS_KEY_ID":             "arn:aws:kms:us-east-1:111122223333:key/example",
		"APP_EMAIL_SENDER_ENABLED":   "false",
		"APP_SMS_SENDER_ENABLED":     "true",
		"APP_SMS_SENDER_POLICY_PATH": "sms.rego",
		"APP_SMS_HISTORY_TABLE_NAME": "history",
		// email settings are not validated when the email sender is off
		"APP_EMAIL_PROVIDERS":          "mailgun",
		"APP_EMAIL_RATE_LIMIT_ENABLED": "true",
		"APP_EMAIL_RATE_LIMIT_CONFIG":  "not json",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Email.Enabled || !cfg.SMS.Enabled {
		t.Errorf("email %v, sms %v", cfg.Email.Enabled, cfg.SMS.Enabled)
	}
}

func TestLoad_Errors(t *testing.T) {
	tests := []struct {
		name string
		vars map[string]string
		want string
	}{
		{"missing kms key", map[string]string{"APP_EMAIL_SENDER_POLICY_PATH": "p.rego"}, "APP_KMS_KEY_ID is required"},
		{"missing email policy", map[string]string{"APP_KMS_KEY_ID": "k"}, "APP_EMAIL_SENDER_POLICY_PATH is required"},
		{"no sender enabled", with(map[string]string{"APP_EMAIL_SENDER_ENABLED": "false"}), "at least one of"},
		{"invalid bool", with(map[string]string{"APP_SEND_ENABLED": "flase"}), `APP_SEND_ENABLED: "flase" is not a boolean`},
		{"invalid log level", with(map[string]string{"APP_LOG_LEVEL": "fatal"}), "APP_LOG_LEVEL"},
		{"invalid duration", with(map[string]string{"APP_EMAIL_HEALTH_CHECK_TTL": "30"}), "APP_EMAIL_HEALTH_CHECK_TTL"},
		{"negative duration", with(map[string]string{"APP_SMS_THROTTLE_PERIOD": "-1m"}), "APP_SMS_THROTTLE_PERIOD"},
		{"unknown provider", with(map[string]string{"APP_EMAIL_PROVIDERS": "ses,mailgun"}), `unknown provider "mailgun"`},
		{"duplicate provider", with(map[string]string{"APP_EMAIL_PROVIDERS": "ses,ses"}), "more than once"},
		{"sendgrid without key", with(map[string]string{"APP_EMAIL_PROVIDERS": "sendgrid"}), "APP_SENDGRID_EMAIL_SEND_API_KEY is required"},
		{"unknown verification provider", with(map[string]string{"APP_EMAIL_VERIFICATION_PROVIDER": "zerobounce"}), "APP_EMAIL_VERIFICATION_PROVIDER"},
		{"sendgrid verification without key", with(map[string]string{"APP_EMAIL_VERIFICATION_PROVIDER": "sendgrid"}), "APP_SENDGRID_EMAIL_VERIFICATION_API_KEY is required"},
		{"rate limit without table", with(map[string]string{"APP_EMAIL_RATE_LIMIT_ENABLED": "true"}), "APP_EMAIL_RATE_LIMIT_TABLE_NAME is required"},
		{"invalid rate limit config", with(map[string]string{"APP_EMAIL_RATE_LIMIT_ENABLED": "true", "APP_EMAIL_RATE_LIMIT_TABLE_NAME": "t", "APP_EMAIL_RATE_LIMIT_CONFIG": `{"failMode":"maybe"}`}), "APP_EMAIL_RATE_LIMIT_CONFIG"},
		{"sms without policy", with(map[string]string{"APP_SMS_SENDER_ENABLED": "true", "APP_SMS_HISTORY_TABLE_NAME": "h"}), "APP_SMS_SENDER_POLICY_PATH is required"},
		{"sms without table", with(map[string]string{"APP_SMS_SENDER_ENABLED": "true", "APP_SMS_SENDER_POLICY_PATH": "p"}), "APP_SMS_HISTORY_TABLE_NAME is required"},
		{"removed variable", with(map[string]string{"APP_EMAIL_PROVIDER": "sendgrid"}), "APP_EMAIL_PROVIDER was removed in v3: use APP_EMAIL_PROVIDERS"},
		{"removed debug mode", with(map[string]string{"APP_DEBUG_MODE": "false"}), "APP_DEBUG_MODE was removed"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(env(tc.vars))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Load() error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestLoad_ReportsAllErrors(t *testing.T) {
	_, err := Load(env(map[string]string{"APP_SEND_ENABLED": "nope", "KMS_KEY_ID": "old"}))
	if err == nil {
		t.Fatal("Load() should fail")
	}
	for _, want := range []string{"APP_SEND_ENABLED", "KMS_KEY_ID was removed", "APP_KMS_KEY_ID is required", "APP_EMAIL_SENDER_POLICY_PATH is required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v\nwant it to contain %q", err, want)
		}
	}
}

func TestLoad_EmptyRemovedVariableIsIgnored(t *testing.T) {
	// older terraform module versions set some variables to empty strings
	if _, err := Load(env(with(map[string]string{"APP_EMAIL_FAILOVER_PROVIDERS": "", "APP_EMAIL_VERIFICATION_WHITELIST": " "}))); err != nil {
		t.Errorf("Load() = %v", err)
	}
}
