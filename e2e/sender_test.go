package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/encryption"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/opa"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/ratelimit"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/sender"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/verifier"
)

// MockProvider captures sent emails for verification in tests
type MockProvider struct {
	mu         sync.Mutex
	SentEmails []*types.EmailData
	SendError  error
}

func (p *MockProvider) Name() string {
	return "mock"
}

func (p *MockProvider) Send(ctx context.Context, d *types.EmailData) error {
	if p.SendError != nil {
		return p.SendError
	}

	// Simulate what the real providers do: merge verification code into template data
	if d.Providers != nil && d.Providers.SES != nil {
		if d.Providers.SES.TemplateData == nil {
			d.Providers.SES.TemplateData = make(map[string]any)
		}
		d.Providers.SES.TemplateData["code"] = d.VerificationCode
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// Make a deep copy to avoid mutation issues
	emailCopy := *d
	if d.Providers != nil {
		providersCopy := *d.Providers
		if d.Providers.SES != nil {
			sesCopy := *d.Providers.SES
			sesCopy.TemplateData = make(map[string]any)
			for k, v := range d.Providers.SES.TemplateData {
				sesCopy.TemplateData[k] = v
			}
			providersCopy.SES = &sesCopy
		}
		emailCopy.Providers = &providersCopy
	}
	p.SentEmails = append(p.SentEmails, &emailCopy)
	return nil
}

func (p *MockProvider) GetSentEmails() []*types.EmailData {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.SentEmails
}

func (p *MockProvider) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.SentEmails = nil
}

// SendGridMockServer creates an httptest server that mocks the SendGrid validation API
type SendGridMockServer struct {
	Server          *httptest.Server
	mu              sync.Mutex
	Responses       map[string]verifier.SendGridValidationResponse
	DefaultResponse verifier.SendGridValidationResponse
	RequestCount    int
	LastRequest     string
}

func NewSendGridMockServer() *SendGridMockServer {
	mock := &SendGridMockServer{
		Responses: make(map[string]verifier.SendGridValidationResponse),
		DefaultResponse: verifier.SendGridValidationResponse{
			Result: verifier.SendGridValidationResult{
				Email:   "test@example.com",
				Verdict: "Valid",
				Score:   0.9,
			},
		},
	}

	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		mock.RequestCount++

		if r.URL.Path != "/v3/validations/email" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		var reqBody struct {
			Email  string `json:"email"`
			Source string `json:"source"`
		}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mock.LastRequest = reqBody.Email

		response := mock.DefaultResponse
		if resp, ok := mock.Responses[reqBody.Email]; ok {
			response = resp
		}
		response.Result.Email = reqBody.Email

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))

	return mock
}

func (m *SendGridMockServer) SetResponse(email string, resp verifier.SendGridValidationResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Responses[email] = resp
}

func (m *SendGridMockServer) SetInvalidResponse(email string) {
	m.SetResponse(email, verifier.SendGridValidationResponse{
		Result: verifier.SendGridValidationResult{
			Email:   email,
			Verdict: "Invalid",
			Score:   0.1,
		},
	})
}

func (m *SendGridMockServer) Close() {
	m.Server.Close()
}

func (m *SendGridMockServer) URL() string {
	return m.Server.URL
}

// testConfig creates a config suitable for offline testing
func testConfig(t *testing.T, sendGridURL string, emailVerificationEnabled bool) *config.Config {
	t.Helper()

	awscfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(aws.CredentialsProviderFunc(
			func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     "test",
					SecretAccessKey: "test",
				}, nil
			},
		)),
	)
	if err != nil {
		t.Fatalf("failed to load AWS config: %v", err)
	}

	return &config.Config{
		AWSConfig:                       &awscfg,
		AppKmsKeyId:                     encryption.MockKeyID,
		AppEmailProvider:                "ses",
		AppEmailSenderPolicyPath:        "../fixtures/debug-policy.rego",
		AppEmailVerificationEnabled:     emailVerificationEnabled,
		AppEmailVerificationWhitelist:   []string{},
		AppSendEnabled:                  false, // DryRun mode
		SendGridApiHost:                 sendGridURL,
		SendGridEmailVerificationApiKey: "test-api-key",
	}
}

// createTestSender creates a Sender with mocked dependencies
func createTestSender(t *testing.T, cfg *config.Config, provider *MockProvider) *sender.Sender {
	t.Helper()

	policy, err := opa.ReadPolicy(cfg.AppEmailSenderPolicyPath)
	if err != nil {
		t.Fatalf("failed to read policy: %v", err)
	}

	preparedPolicy, err := opa.PreparePolicy(context.Background(), policy, sender.PolicyQuery)
	if err != nil {
		t.Fatalf("failed to prepare policy: %v", err)
	}

	emailVerifier := &verifier.SendGridEmailVerifier{
		Whitelist: cfg.AppEmailVerificationWhitelist,
		APIHost:   cfg.SendGridApiHost,
		APIKey:    cfg.SendGridEmailVerificationApiKey,
	}

	return &sender.Sender{
		Config:         cfg,
		Decrypter:      encryption.Passthrough{},
		EmailVerifier:  emailVerifier,
		PreparedPolicy: preparedPolicy,
		Provider:       provider,
	}
}

// newCognitoEvent creates a test Cognito event
func newCognitoEvent(trigger, clientID, email, code string) types.CognitoEventUserPoolsCustomEmailSender {
	return types.CognitoEventUserPoolsCustomEmailSender{
		CognitoEventUserPoolsHeader: events.CognitoEventUserPoolsHeader{
			Version:       "1",
			TriggerSource: trigger,
			Region:        "us-east-1",
			UserPoolID:    "us-east-1_test12345",
			CallerContext: events.CognitoEventUserPoolsCallerContext{
				AWSSDKVersion: "aws-sdk-unknown-unknown",
				ClientID:      clientID,
			},
			UserName: email,
		},
		Request: types.CognitoEventUserPoolsCustomEmailSenderRequest{
			UserAttributes: map[string]any{
				"email":          email,
				"email_verified": "false",
				"sub":            "00000000-0000-0000-0000-000000000000",
			},
			Code:           code,
			ClientMetadata: nil,
			Type:           "customEmailSenderRequestV1",
		},
	}
}

func TestSendEmail_PolicyAllows_EmailSent(t *testing.T) {
	// Setup
	mockSendGrid := NewSendGridMockServer()
	defer mockSendGrid.Close()

	cfg := testConfig(t, mockSendGrid.URL(), false)
	provider := &MockProvider{}
	s := createTestSender(t, cfg, provider)

	ctx := context.Background()
	event := newCognitoEvent(
		"CustomEmailSender_SignUp",
		"xxxx1111", // Maps to template-01 in debug-policy.rego
		"test@example.com",
		"123456",
	)

	// Execute
	err := s.SendEmail(ctx, event)

	// Verify
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	emails := provider.GetSentEmails()
	if len(emails) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(emails))
	}

	sent := emails[0]
	if sent.DestinationAddress != "test@example.com" {
		t.Errorf("expected destination 'test@example.com', got '%s'", sent.DestinationAddress)
	}
	if sent.SourceAddress != "ACME <noreply@example.org>" {
		t.Errorf("expected source 'ACME <noreply@example.org>', got '%s'", sent.SourceAddress)
	}
	if sent.VerificationCode != "123456" {
		t.Errorf("expected code '123456', got '%s'", sent.VerificationCode)
	}
	if sent.Providers.SES.TemplateID != "template-01" {
		t.Errorf("expected templateID 'template-01', got '%s'", sent.Providers.SES.TemplateID)
	}
}

func TestSendEmail_DifferentClientID_DifferentTemplate(t *testing.T) {
	mockSendGrid := NewSendGridMockServer()
	defer mockSendGrid.Close()

	cfg := testConfig(t, mockSendGrid.URL(), false)
	provider := &MockProvider{}
	s := createTestSender(t, cfg, provider)

	ctx := context.Background()

	testCases := []struct {
		name       string
		clientID   string
		expectedID string
	}{
		{
			name:       "client xxxx1111 gets template-01",
			clientID:   "xxxx1111",
			expectedID: "template-01",
		},
		{
			name:       "client xxxx2222 gets template-02",
			clientID:   "xxxx2222",
			expectedID: "template-02",
		},
		{
			name:       "unknown client gets default-template",
			clientID:   "unknown-client",
			expectedID: "default-template",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider.Reset()

			event := newCognitoEvent(
				"CustomEmailSender_SignUp",
				tc.clientID,
				"user@example.com",
				"654321",
			)

			err := s.SendEmail(ctx, event)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			emails := provider.GetSentEmails()
			if len(emails) != 1 {
				t.Fatalf("expected 1 email sent, got %d", len(emails))
			}

			if emails[0].Providers.SES.TemplateID != tc.expectedID {
				t.Errorf("expected templateID '%s', got '%s'", tc.expectedID, emails[0].Providers.SES.TemplateID)
			}
		})
	}
}

func TestSendEmail_WithEmailVerification_Valid(t *testing.T) {
	mockSendGrid := NewSendGridMockServer()
	defer mockSendGrid.Close()

	cfg := testConfig(t, mockSendGrid.URL(), true) // Enable verification
	provider := &MockProvider{}
	s := createTestSender(t, cfg, provider)

	ctx := context.Background()
	event := newCognitoEvent(
		"CustomEmailSender_SignUp",
		"xxxx1111",
		"valid@example.com",
		"123456",
	)

	err := s.SendEmail(ctx, event)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify SendGrid API was called
	if mockSendGrid.RequestCount != 1 {
		t.Errorf("expected 1 SendGrid API call, got %d", mockSendGrid.RequestCount)
	}

	emails := provider.GetSentEmails()
	if len(emails) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(emails))
	}
}

func TestSendEmail_WithEmailVerification_Invalid_Denied(t *testing.T) {
	mockSendGrid := NewSendGridMockServer()
	defer mockSendGrid.Close()

	// Configure SendGrid to return invalid for this email
	mockSendGrid.SetInvalidResponse("invalid@example.com")

	cfg := testConfig(t, mockSendGrid.URL(), true) // Enable verification
	provider := &MockProvider{}
	s := createTestSender(t, cfg, provider)

	ctx := context.Background()
	event := newCognitoEvent(
		"CustomEmailSender_SignUp",
		"xxxx1111",
		"invalid@example.com",
		"123456",
	)

	err := s.SendEmail(ctx, event)

	// The policy should deny based on invalid email verification
	if err != nil {
		t.Fatalf("expected no error (policy denial is not an error), got: %v", err)
	}

	// Verify SendGrid API was called
	if mockSendGrid.RequestCount != 1 {
		t.Errorf("expected 1 SendGrid API call, got %d", mockSendGrid.RequestCount)
	}

	// No email should be sent due to policy denial
	emails := provider.GetSentEmails()
	if len(emails) != 0 {
		t.Fatalf("expected 0 emails sent (policy denied), got %d", len(emails))
	}
}

func TestSendEmail_WhitelistedDomain_SkipsAPIVerification(t *testing.T) {
	mockSendGrid := NewSendGridMockServer()
	defer mockSendGrid.Close()

	cfg := testConfig(t, mockSendGrid.URL(), true)
	cfg.AppEmailVerificationWhitelist = []string{"trusted.com"}

	provider := &MockProvider{}
	s := createTestSender(t, cfg, provider)

	ctx := context.Background()
	event := newCognitoEvent(
		"CustomEmailSender_SignUp",
		"xxxx1111",
		"user@trusted.com",
		"123456",
	)

	err := s.SendEmail(ctx, event)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// SendGrid API should NOT be called for whitelisted domains
	if mockSendGrid.RequestCount != 0 {
		t.Errorf("expected 0 SendGrid API calls for whitelisted domain, got %d", mockSendGrid.RequestCount)
	}

	// Email should still be sent
	emails := provider.GetSentEmails()
	if len(emails) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(emails))
	}
}

func TestSendEmail_DifferentTriggerSources(t *testing.T) {
	mockSendGrid := NewSendGridMockServer()
	defer mockSendGrid.Close()

	cfg := testConfig(t, mockSendGrid.URL(), false)
	provider := &MockProvider{}
	s := createTestSender(t, cfg, provider)

	ctx := context.Background()

	triggers := []string{
		"CustomEmailSender_SignUp",
		"CustomEmailSender_ResendCode",
		"CustomEmailSender_ForgotPassword",
		"CustomEmailSender_UpdateUserAttribute",
		"CustomEmailSender_VerifyUserAttribute",
		"CustomEmailSender_AdminCreateUser",
	}

	for _, trigger := range triggers {
		t.Run(trigger, func(t *testing.T) {
			provider.Reset()

			event := newCognitoEvent(
				trigger,
				"xxxx1111",
				"user@example.com",
				"111111",
			)

			err := s.SendEmail(ctx, event)
			if err != nil {
				t.Fatalf("expected no error for trigger %s, got: %v", trigger, err)
			}

			emails := provider.GetSentEmails()
			if len(emails) != 1 {
				t.Fatalf("expected 1 email sent for trigger %s, got %d", trigger, len(emails))
			}
		})
	}
}

func TestSendEmail_MissingEmailAttribute_Error(t *testing.T) {
	mockSendGrid := NewSendGridMockServer()
	defer mockSendGrid.Close()

	cfg := testConfig(t, mockSendGrid.URL(), true) // Enable verification to trigger email lookup
	provider := &MockProvider{}
	s := createTestSender(t, cfg, provider)

	ctx := context.Background()
	event := newCognitoEvent(
		"CustomEmailSender_SignUp",
		"xxxx1111",
		"user@example.com",
		"123456",
	)
	// Remove email attribute
	delete(event.Request.UserAttributes, "email")

	err := s.SendEmail(ctx, event)

	if err == nil {
		t.Fatal("expected error for missing email attribute, got nil")
	}

	emails := provider.GetSentEmails()
	if len(emails) != 0 {
		t.Fatalf("expected 0 emails sent, got %d", len(emails))
	}
}

func TestSendEmail_TemplateDataContainsClientID(t *testing.T) {
	mockSendGrid := NewSendGridMockServer()
	defer mockSendGrid.Close()

	cfg := testConfig(t, mockSendGrid.URL(), false)
	provider := &MockProvider{}
	s := createTestSender(t, cfg, provider)

	ctx := context.Background()
	event := newCognitoEvent(
		"CustomEmailSender_SignUp",
		"xxxx1111",
		"test@example.com",
		"123456",
	)

	err := s.SendEmail(ctx, event)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	emails := provider.GetSentEmails()
	if len(emails) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(emails))
	}

	// Check that template data includes clientId from policy
	clientID, ok := emails[0].Providers.SES.TemplateData["clientId"]
	if !ok {
		t.Error("expected templateData to contain 'clientId'")
	}
	if clientID != "xxxx1111" {
		t.Errorf("expected clientId 'xxxx1111', got '%v'", clientID)
	}

	// Check that verification code is added to template data
	code, ok := emails[0].Providers.SES.TemplateData["code"]
	if !ok {
		t.Error("expected templateData to contain 'code'")
	}
	if code != "123456" {
		t.Errorf("expected code '123456', got '%v'", code)
	}
}

type failingDecrypter struct{}

func (failingDecrypter) Decrypt(context.Context, string) (string, error) {
	return "", errors.New("decrypt should not be called")
}

func TestSendEmail_EmptyCode_SkipsDecrypt(t *testing.T) {
	mockSendGrid := NewSendGridMockServer()
	defer mockSendGrid.Close()

	cfg := testConfig(t, mockSendGrid.URL(), false)
	provider := &MockProvider{}
	s := createTestSender(t, cfg, provider)
	s.Decrypter = failingDecrypter{}

	event := newCognitoEvent(
		"CustomEmailSender_AccountTakeOverNotification",
		"xxxx1111",
		"user@example.com",
		"",
	)

	if err := s.SendEmail(context.Background(), event); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	emails := provider.GetSentEmails()
	if len(emails) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(emails))
	}
	if emails[0].VerificationCode != "" {
		t.Errorf("expected empty code, got %q", emails[0].VerificationCode)
	}
}

// withRateLimit enables the real limiter backed by an in-memory store.
func withRateLimit(t *testing.T, s *sender.Sender, raw string) *ratelimit.MemoryStore {
	t.Helper()

	rl, err := ratelimit.ParseConfig(raw)
	if err != nil {
		t.Fatalf("invalid rate limit config: %v", err)
	}
	s.Config.AppEmailRateLimitEnabled = true
	s.Config.AppEmailRateLimit = rl

	store := ratelimit.NewMemoryStore()
	s.RateLimiter = ratelimit.New(rl, store, ratelimit.WithLogger(slog.New(slog.DiscardHandler)))
	return store
}

func TestSendEmail_RateLimit_ThrottlesRepeatedSignups(t *testing.T) {
	mockSendGrid := NewSendGridMockServer()
	defer mockSendGrid.Close()

	cfg := testConfig(t, mockSendGrid.URL(), true)
	provider := &MockProvider{}
	s := createTestSender(t, cfg, provider)
	withRateLimit(t, s, `{"classes": {"signup": {"destination": [{"window": "1h", "max": 2}]}}}`)

	ctx := context.Background()

	// aliases of one mailbox share a counter
	for i, addr := range []string{"user@example.com", "User+a@example.com", "user+b@Example.com", "user@example.com"} {
		event := newCognitoEvent("CustomEmailSender_SignUp", "xxxx1111", addr, fmt.Sprintf("code-%d", i))
		if err := s.SendEmail(ctx, event); err != nil {
			t.Fatalf("attempt %d: throttling must not return an error, got: %v", i+1, err)
		}
	}

	if got := len(provider.GetSentEmails()); got != 2 {
		t.Fatalf("expected 2 emails sent before throttling, got %d", got)
	}

	// throttled emails skip the verification api
	if mockSendGrid.RequestCount != 2 {
		t.Errorf("expected 2 SendGrid API calls, got %d", mockSendGrid.RequestCount)
	}

	// other mailboxes keep their own budget
	if err := s.SendEmail(ctx, newCognitoEvent("CustomEmailSender_SignUp", "xxxx1111", "other@example.com", "code-x")); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got := len(provider.GetSentEmails()); got != 3 {
		t.Errorf("expected 3 emails sent, got %d", got)
	}
}

func TestSendEmail_RateLimit_RetryCountedOnce(t *testing.T) {
	mockSendGrid := NewSendGridMockServer()
	defer mockSendGrid.Close()

	cfg := testConfig(t, mockSendGrid.URL(), false)
	provider := &MockProvider{}
	s := createTestSender(t, cfg, provider)
	withRateLimit(t, s, `{"classes": {"authentication": {"destination": [{"window": "15m", "max": 2}]}}}`)

	ctx := context.Background()
	first := newCognitoEvent("CustomEmailSender_Authentication", "xxxx1111", "user@example.com", "ciphertext-1")

	// the provider fails, so lambda would retry the same event
	provider.SendError = errors.New("provider unavailable")
	if err := s.SendEmail(ctx, first); err == nil {
		t.Fatal("expected the provider error to be returned for a retry")
	}

	provider.SendError = nil
	if err := s.SendEmail(ctx, first); err != nil {
		t.Fatalf("retry: expected no error, got: %v", err)
	}

	// the retry did not use budget, so one more new code fits under the limit
	second := newCognitoEvent("CustomEmailSender_Authentication", "xxxx1111", "user@example.com", "ciphertext-2")
	third := newCognitoEvent("CustomEmailSender_Authentication", "xxxx1111", "user@example.com", "ciphertext-3")
	for _, e := range []types.CognitoEventUserPoolsCustomEmailSender{second, third} {
		if err := s.SendEmail(ctx, e); err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
	}

	emails := provider.GetSentEmails()
	if len(emails) != 2 {
		t.Fatalf("expected 2 emails sent (retry and second code), got %d", len(emails))
	}
	if emails[0].VerificationCode != "ciphertext-1" || emails[1].VerificationCode != "ciphertext-2" {
		t.Errorf("unexpected codes sent: %q, %q", emails[0].VerificationCode, emails[1].VerificationCode)
	}
}

func TestSendEmail_RateLimit_AdminCreateUserExempt(t *testing.T) {
	mockSendGrid := NewSendGridMockServer()
	defer mockSendGrid.Close()

	cfg := testConfig(t, mockSendGrid.URL(), false)
	provider := &MockProvider{}
	s := createTestSender(t, cfg, provider)
	store := withRateLimit(t, s, "")

	for i := range 10 {
		event := newCognitoEvent("CustomEmailSender_AdminCreateUser", "xxxx1111", "user@example.com", fmt.Sprintf("code-%d", i))
		if err := s.SendEmail(context.Background(), event); err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
	}

	if got := len(provider.GetSentEmails()); got != 10 {
		t.Errorf("expected all 10 admin emails sent, got %d", got)
	}
	if store.Len() != 0 {
		t.Errorf("expected exempt emails to skip the store, found %d items", store.Len())
	}
}
