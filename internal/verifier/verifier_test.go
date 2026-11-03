package verifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOfflineVerifier_ValidEmails(t *testing.T) {
	v := NewOfflineVerifier()
	ctx := context.Background()

	validEmails := []string{
		"user@example.com",
		"user.name@example.com",
		"user+tag@example.com",
		"user@sub.example.com",
		"user@example.co.uk",
		"a@b.co",
	}

	for _, email := range validEmails {
		t.Run(email, func(t *testing.T) {
			result, err := v.VerifyEmail(ctx, email)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.IsValid {
				t.Errorf("expected email %q to be valid, got invalid: %s", email, result.Raw)
			}
			if result.Score != 100.0 {
				t.Errorf("expected score 100, got %f", result.Score)
			}
		})
	}
}

func TestOfflineVerifier_InvalidEmails(t *testing.T) {
	v := NewOfflineVerifier()
	ctx := context.Background()

	testCases := []struct {
		email       string
		description string
	}{
		{"", "empty string"},
		{"notanemail", "no @ symbol"},
		{"@example.com", "no local part"},
		{"user@", "no domain"},
		{"user@localhost", "domain without dot"},
		{"user@.com", "domain starts with dot"},
		{"user@@example.com", "double @"},
		{"user @example.com", "space in local part"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := v.VerifyEmail(ctx, tc.email)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.IsValid {
				t.Errorf("expected email %q to be invalid (%s), got valid", tc.email, tc.description)
			}
			if result.Score != 0 {
				t.Errorf("expected score 0 for invalid email, got %f", result.Score)
			}
		})
	}
}

func TestSendGridVerifier_VerifyEmailViaAPI(t *testing.T) {
	testCases := []struct {
		name           string
		email          string
		serverResponse SendGridValidationResponse
		expectedValid  bool
		expectedScore  float32
	}{
		{
			name:  "valid email",
			email: "valid@example.com",
			serverResponse: SendGridValidationResponse{
				Result: SendGridValidationResult{
					Email:   "valid@example.com",
					Verdict: "Valid",
					Score:   0.95,
				},
			},
			expectedValid: true,
			expectedScore: 0.95,
		},
		{
			name:  "invalid email",
			email: "invalid@example.com",
			serverResponse: SendGridValidationResponse{
				Result: SendGridValidationResult{
					Email:   "invalid@example.com",
					Verdict: "Invalid",
					Score:   0.1,
				},
			},
			expectedValid: false,
			expectedScore: 0.1,
		},
		{
			name:  "risky email",
			email: "risky@example.com",
			serverResponse: SendGridValidationResponse{
				Result: SendGridValidationResult{
					Email:   "risky@example.com",
					Verdict: "Risky",
					Score:   0.5,
				},
			},
			expectedValid: true, // Risky is not Invalid
			expectedScore: 0.5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v3/validations/email" {
					t.Errorf("unexpected path: %s", r.URL.Path)
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				if r.Method != "POST" {
					t.Errorf("unexpected method: %s", r.Method)
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tc.serverResponse)
			}))
			defer server.Close()

			v := &SendGridEmailVerifier{
				APIHost: server.URL,
				APIKey:  "test-api-key",
			}

			ctx := context.Background()
			result, err := v.VerifyEmailViaAPI(ctx, tc.email)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.IsValid != tc.expectedValid {
				t.Errorf("expected IsValid=%v, got %v", tc.expectedValid, result.IsValid)
			}
			if result.Score != tc.expectedScore {
				t.Errorf("expected Score=%f, got %f", tc.expectedScore, result.Score)
			}
		})
	}
}

func TestSendGridVerifier_IsWhitelisted(t *testing.T) {
	v := &SendGridEmailVerifier{
		Whitelist: []string{"trusted.com", "allowed.org"},
	}

	testCases := []struct {
		name        string
		email       string
		expectMatch bool
	}{
		{"whitelisted domain", "user@trusted.com", true},
		{"another whitelisted domain", "admin@allowed.org", true},
		{"domain case insensitive", "user@Trusted.COM", true},
		{"non-whitelisted domain", "user@untrusted.com", false},
		{"subdomain not whitelisted", "user@sub.trusted.com", false},
		{"invalid email format", "not-an-email", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := v.isWhitelisted(tc.email); got != tc.expectMatch {
				t.Errorf("isWhitelisted(%q) = %v, want %v", tc.email, got, tc.expectMatch)
			}
		})
	}
}

func TestSendGridVerifier_VerifyEmail_WhitelistSkipsAPI(t *testing.T) {
	apiCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalled = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(SendGridValidationResponse{
			Result: SendGridValidationResult{
				Verdict: "Valid",
				Score:   0.9,
			},
		})
	}))
	defer server.Close()

	v := &SendGridEmailVerifier{
		Whitelist: []string{"trusted.com"},
		APIHost:   server.URL,
		APIKey:    "test-api-key",
	}

	ctx := context.Background()

	// Test whitelisted email - should NOT call API
	result, err := v.VerifyEmail(ctx, "user@trusted.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if apiCalled {
		t.Error("API should not be called for whitelisted domain")
	}
	if !result.IsValid {
		t.Error("whitelisted email should be valid")
	}

	// Test non-whitelisted email - should call API
	apiCalled = false
	result, err = v.VerifyEmail(ctx, "user@other.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !apiCalled {
		t.Error("API should be called for non-whitelisted domain")
	}
	if !result.IsValid {
		t.Error("expected valid result from API")
	}
}
