package ratelimit

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		trigger   string
		wantClass string
		wantKnown bool
	}{
		{"CustomEmailSender_Authentication", ClassAuthentication, true},
		{"CustomEmailSender_SignUp", ClassSignUp, true},
		{"CustomEmailSender_ResendCode", ClassSignUp, true},
		{"CustomEmailSender_ForgotPassword", ClassForgotPassword, true},
		{"CustomEmailSender_UpdateUserAttribute", ClassAttribute, true},
		{"CustomEmailSender_VerifyUserAttribute", ClassAttribute, true},
		{"CustomEmailSender_AdminCreateUser", ClassAdmin, true},
		{"CustomEmailSender_AccountTakeOverNotification", ClassNotification, true},
		{"CustomEmailSender_SomethingNew", ClassUnknown, false},
		{"customemailsender_signup", ClassUnknown, false},
		{"", ClassUnknown, false},
	}

	for _, tc := range tests {
		t.Run(tc.trigger, func(t *testing.T) {
			class, known := Classify(tc.trigger)
			if class != tc.wantClass || known != tc.wantKnown {
				t.Errorf("Classify(%q) = %q, %v; want %q, %v", tc.trigger, class, known, tc.wantClass, tc.wantKnown)
			}
		})
	}
}

func TestNormalizeAddress(t *testing.T) {
	all := NormalizeConfig{StripPlusTag: true, StripGmailDots: true}
	none := NormalizeConfig{}

	tests := []struct {
		name string
		in   string
		opts NormalizeConfig
		want string
	}{
		{"lowercase and trim", "  User@Example.COM ", all, "user@example.com"},
		{"plus tag stripped", "user+promo@example.com", all, "user@example.com"},
		{"only first plus matters", "user+a+b@example.com", all, "user@example.com"},
		{"plus tag kept when disabled", "user+promo@example.com", none, "user+promo@example.com"},
		{"leading plus kept", "+user@example.com", all, "+user@example.com"},
		{"dots kept for other domains", "first.last@example.com", all, "first.last@example.com"},
		{"gmail dots stripped", "First.Last@gmail.com", all, "firstlast@gmail.com"},
		{"googlemail maps to gmail", "first.last+x@googlemail.com", all, "firstlast@gmail.com"},
		{"gmail dots kept when disabled", "first.last@gmail.com", none, "first.last@gmail.com"},
		{"gmail all dots kept", "...@gmail.com", all, "...@gmail.com"},
		{"gmail dots kept with only plus stripping", "first.last+x@gmail.com", NormalizeConfig{StripPlusTag: true}, "first.last@gmail.com"},
		{"last at sign splits", `"a@b"@example.com`, all, `"a@b"@example.com`},
		{"no at sign", "not-an-address", all, "not-an-address"},
		{"trailing at sign", "user@", all, "user@"},
		{"empty", "", all, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeAddress(tc.in, tc.opts); got != tc.want {
				t.Errorf("NormalizeAddress(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestHash(t *testing.T) {
	h := Hash("user@example.com")
	if len(h) != 64 || strings.Contains(h, "user") {
		t.Errorf("Hash() = %q, want 64 hex chars without the input", h)
	}
	if Hash("user@example.com") != h {
		t.Error("Hash() is not deterministic")
	}
}

func TestLowTrust(t *testing.T) {
	tests := []struct {
		name       string
		attrs      map[string]any
		wantLow    bool
		wantReason string
	}{
		{"verified and confirmed", map[string]any{"email_verified": "true", "cognito:user_status": "CONFIRMED"}, false, ""},
		{"verified without status", map[string]any{"email_verified": "true"}, false, ""},
		{"verified as bool", map[string]any{"email_verified": true}, false, ""},
		{"verified mixed case", map[string]any{"email_verified": "True"}, false, ""},
		{"unverified", map[string]any{"email_verified": "false"}, true, "email_unverified"},
		{"unverified as bool", map[string]any{"email_verified": false}, true, "email_unverified"},
		{"verified but unconfirmed", map[string]any{"email_verified": "true", "cognito:user_status": "UNCONFIRMED"}, true, "user_unconfirmed"},
		{"missing email_verified", map[string]any{"cognito:user_status": "CONFIRMED"}, true, "email_verified_missing"},
		{"null email_verified", map[string]any{"email_verified": nil}, true, "email_verified_missing"},
		{"nil attributes", nil, true, "email_verified_missing"},
		{"unexpected type", map[string]any{"email_verified": 1}, true, "email_unverified"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			low, reason := LowTrust(ChannelEmail, tc.attrs)
			if low != tc.wantLow || reason != tc.wantReason {
				t.Errorf("LowTrust() = %v, %q; want %v, %q", low, reason, tc.wantLow, tc.wantReason)
			}
		})
	}
}

func TestAddressDomain(t *testing.T) {
	tests := map[string]string{
		"user@Example.com": "example.com",
		"user@":            "",
		"no-at-sign":       "",
		"":                 "",
	}
	for in, want := range tests {
		if got := AddressDomain(in); got != want {
			t.Errorf("AddressDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
