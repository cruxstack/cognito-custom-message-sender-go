package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/encryption"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/handler"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/opa"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/smssender"
)

// MockSMSPublisher captures sent SMS for verification in tests
type MockSMSPublisher struct {
	mu   sync.Mutex
	Sent []smssender.Message
}

func (p *MockSMSPublisher) Publish(_ context.Context, m smssender.Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Sent = append(p.Sent, m)
	return nil
}

func (p *MockSMSPublisher) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.Sent)
}

func createTestSMSSender(t *testing.T, policyPath string, publisher smssender.Publisher) (*smssender.Sender, *smssender.MemoryHistory) {
	t.Helper()

	policy, err := opa.ReadPolicy(policyPath)
	if err != nil {
		t.Fatalf("failed to read policy: %v", err)
	}
	pp, err := smssender.PreparePolicy(context.Background(), policy)
	if err != nil {
		t.Fatalf("failed to prepare policy: %v", err)
	}

	cfg := testConfig(t, "", false)
	cfg.AppSMSSenderEnabled = true
	cfg.AppSMSThrottlePeriod = 15 * time.Minute
	cfg.AppSMSHistoryTTL = 24 * time.Hour

	history := smssender.NewMemoryHistory()
	return &smssender.Sender{
		Config:         cfg,
		Decrypter:      encryption.Passthrough{},
		PreparedPolicy: pp,
		History:        history,
		Publisher:      publisher,
	}, history
}

func rawEvent(t *testing.T, v any) json.RawMessage {
	t.Helper()
	bs, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return bs
}

func smsEvent(trigger, phone, code string) map[string]any {
	return map[string]any{
		"version":       "1",
		"triggerSource": trigger,
		"region":        "us-east-1",
		"userPoolId":    "us-east-1_EXAMPLE",
		"userName":      "user-1",
		"callerContext": map[string]string{"awsSdkVersion": "aws-sdk-unknown-unknown", "clientId": "xxxx1111"},
		"request": map[string]any{
			"type": "customSMSSenderRequestV1",
			"code": code,
			"userAttributes": map[string]any{
				"sub":                   "00000000-0000-0000-0000-000000000000",
				"phone_number":          phone,
				"phone_number_verified": "true",
			},
		},
	}
}

func TestHandler_ServesEmailAndSMS(t *testing.T) {
	mockSendGrid := NewSendGridMockServer()
	defer mockSendGrid.Close()

	emailProvider := &MockProvider{}
	emailSender := createTestSender(t, testConfig(t, mockSendGrid.URL(), false), emailProvider)

	smsPublisher := &MockSMSPublisher{}
	smsSender, history := createTestSMSSender(t, "../fixtures/sms-policy.rego", smsPublisher)

	h := &handler.Handler{Email: emailSender, SMS: smsSender}
	ctx := context.Background()

	email := newCognitoEvent("CustomEmailSender_SignUp", "xxxx1111", "user@example.com", "123456")
	if err := h.Handle(ctx, rawEvent(t, email)); err != nil {
		t.Fatalf("email: expected no error, got: %v", err)
	}

	// the fixture policy blocks after 5 attempts in the throttle period
	for i := range 7 {
		e := smsEvent("CustomSMSSender_Authentication", "+12065550100", fmt.Sprintf("65432%d", i))
		if err := h.Handle(ctx, rawEvent(t, e)); err != nil {
			t.Fatalf("sms attempt %d: blocks must not return an error, got: %v", i+1, err)
		}
	}

	if got := len(emailProvider.GetSentEmails()); got != 1 {
		t.Errorf("expected 1 email sent, got %d", got)
	}
	if got := smsPublisher.Count(); got != 5 {
		t.Fatalf("expected 5 sms sent before blocking, got %d", got)
	}
	if got := len(history.Records()); got != 7 {
		t.Errorf("expected 7 sms attempts recorded, got %d", got)
	}

	first := smsPublisher.Sent[0]
	if first.PhoneNumber != "+12065550100" || first.Body != "Your code is: 654320" || first.MessageType != "Transactional" {
		t.Errorf("unexpected first sms: %+v", first)
	}
}

func TestHandler_SMSInvalidPhoneDropped(t *testing.T) {
	smsPublisher := &MockSMSPublisher{}
	smsSender, history := createTestSMSSender(t, "../fixtures/sms-policy.rego", smsPublisher)
	h := &handler.Handler{SMS: smsSender}

	e := smsEvent("CustomSMSSender_SignUp", "not-a-phone-number", "123456")
	if err := h.Handle(context.Background(), rawEvent(t, e)); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if smsPublisher.Count() != 0 || len(history.Records()) != 0 {
		t.Error("expected an invalid phone number to be dropped without sending or recording")
	}
}

func TestHandler_DebugSMSFixture(t *testing.T) {
	data, err := os.ReadFile("../fixtures/debug-sms-data.json")
	if err != nil {
		t.Fatal(err)
	}
	var events []json.RawMessage
	if err := json.Unmarshal(data, &events); err != nil {
		t.Fatal(err)
	}

	smsPublisher := &MockSMSPublisher{}
	smsSender, _ := createTestSMSSender(t, "../fixtures/sms-policy.rego", smsPublisher)
	h := &handler.Handler{SMS: smsSender}

	for i, e := range events {
		if err := h.Handle(context.Background(), e); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
	}
	// 7 attempts to one number (5 sent, 2 blocked) and 1 invalid number
	if got := smsPublisher.Count(); got != 5 {
		t.Errorf("expected 5 sms sent from the debug fixture, got %d", got)
	}
}
