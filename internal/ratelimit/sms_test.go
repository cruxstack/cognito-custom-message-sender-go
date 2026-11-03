package ratelimit

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestClassify_SMS(t *testing.T) {
	tests := map[string]string{
		"CustomSMSSender_Authentication":      ClassAuthentication,
		"CustomSMSSender_SignUp":              ClassSignUp,
		"CustomSMSSender_ResendCode":          ClassSignUp,
		"CustomSMSSender_ForgotPassword":      ClassForgotPassword,
		"CustomSMSSender_UpdateUserAttribute": ClassAttribute,
		"CustomSMSSender_VerifyUserAttribute": ClassAttribute,
		"CustomSMSSender_AdminCreateUser":     ClassAdmin,
	}
	for trigger, want := range tests {
		if got, known := Classify(trigger); got != want || !known {
			t.Errorf("Classify(%q) = %q, %v; want %q", trigger, got, known, want)
		}
	}
}

func TestDefaultConfig_SMS(t *testing.T) {
	cfg := DefaultConfig(ChannelSMS)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Channel() != ChannelSMS || cfg.Normalize.StripPlusTag || cfg.Normalize.StripGmailDots {
		t.Errorf("config = %+v", cfg)
	}
	if _, ok := cfg.Classes[ClassNotification]; ok {
		t.Error("sms has no notification class")
	}
	if got := cfg.Classes[ClassAuthentication].Destination; len(got) != 2 || got[0].Max != 5 {
		t.Errorf("authentication limits = %+v", got)
	}
}

func TestParseConfig_SMS(t *testing.T) {
	cfg, err := ParseConfig(ChannelSMS, `{"classes": {"authentication": {"destination": [{"window": "1h", "max": 2}]}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Channel() != ChannelSMS || cfg.Classes[ClassAuthentication].Destination[0].Max != 2 {
		t.Errorf("config = %+v", cfg)
	}

	errs := map[string]string{
		"notification class": `{"classes": {"notification": {}}}`,
		"exempt domains":     `{"exempt": {"domains": ["example.com"]}}`,
		"normalize":          `{"normalize": {"stripPlusTag": true}}`,
	}
	for name, raw := range errs {
		if _, err := ParseConfig(ChannelSMS, raw); err == nil {
			t.Errorf("%s: ParseConfig() should fail for sms", name)
		}
	}
}

func TestLowTrust_SMS(t *testing.T) {
	tests := []struct {
		attrs      map[string]any
		wantLow    bool
		wantReason string
	}{
		{map[string]any{"phone_number_verified": "true"}, false, ""},
		{map[string]any{"phone_number_verified": "false"}, true, "phone_number_unverified"},
		{map[string]any{"email_verified": "true"}, true, "phone_number_verified_missing"},
		{map[string]any{"phone_number_verified": "true", "cognito:user_status": "UNCONFIRMED"}, true, "user_unconfirmed"},
	}
	for _, tc := range tests {
		if low, reason := LowTrust(ChannelSMS, tc.attrs); low != tc.wantLow || reason != tc.wantReason {
			t.Errorf("LowTrust(%v) = %v, %q; want %v, %q", tc.attrs, low, reason, tc.wantLow, tc.wantReason)
		}
	}
}

func TestLimiter_SMS(t *testing.T) {
	cfg, err := ParseConfig(ChannelSMS, `{"classes": {"authentication": {"destination": [{"window": "15m", "max": 2}]}}}`)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, cfg, nil, slog.LevelInfo)
	attrs := map[string]any{"phone_number_verified": "true", "sub": "sub-1"}

	var last *Result
	for range 3 {
		last = h.check("CustomSMSSender_Authentication", "+12065550100", attrs)
	}
	if last.Decision != DecisionThrottledDestination || last.Class != ClassAuthentication {
		t.Errorf("third sms = %+v, want throttled", last)
	}
	if r := h.check("CustomSMSSender_Authentication", "+12065550199", attrs); !r.Allowed() {
		t.Errorf("another number = %+v, want allowed", r)
	}

	for _, k := range h.store.Keys() {
		if !strings.HasPrefix(k, "sms#") {
			t.Errorf("key %q should be prefixed with the channel", k)
		}
		if strings.Contains(k, "2065550100") {
			t.Errorf("key %q contains the phone number", k)
		}
	}

	logs := h.logs.String()
	if !strings.Contains(logs, `"msg":"sms throttled by rate limit"`) || !strings.Contains(logs, `"dst_masked":"+*******0100"`) {
		t.Errorf("throttle log missing or unmasked:\n%s", logs)
	}
	if !strings.Contains(logs, `"SMSRateLimitDecision":1`) {
		t.Errorf("sms metric missing:\n%s", logs)
	}
}

func TestLimiter_ChannelsShareAStore(t *testing.T) {
	store := NewMemoryStore()
	limit := `{"classes": {"signup": {"destination": [{"window": "1h", "max": 1}]}}}`
	emailCfg, _ := ParseConfig(ChannelEmail, limit)
	smsCfg, _ := ParseConfig(ChannelSMS, limit)
	now := func() time.Time { return testStart }
	email := New(emailCfg, store, WithClock(now), WithLogger(slog.New(slog.DiscardHandler)))
	sms := New(smsCfg, store, WithClock(now), WithLogger(slog.New(slog.DiscardHandler)))

	ctx := context.Background()
	attrs := map[string]any{"sub": "sub-1"}
	// the same ciphertext and user on both channels must not collide
	r1 := email.Check(ctx, Request{Trigger: "CustomEmailSender_SignUp", Destination: "user@example.com", UserAttributes: attrs, Code: "c"})
	r2 := sms.Check(ctx, Request{Trigger: "CustomSMSSender_SignUp", Destination: "+12065550100", UserAttributes: attrs, Code: "c"})
	if r1.Decision != DecisionSent || r2.Decision != DecisionSent {
		t.Errorf("decisions = %s, %s; want sent for both", r1.Decision, r2.Decision)
	}
}
