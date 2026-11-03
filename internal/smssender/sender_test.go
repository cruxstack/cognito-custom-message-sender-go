package smssender

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/encryption"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/opa"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
)

type fakePublisher struct {
	sent []Message
	err  error
}

func (p *fakePublisher) Publish(_ context.Context, m Message) error {
	if p.err != nil {
		return p.err
	}
	p.sent = append(p.sent, m)
	return nil
}

type fakeDecrypter struct {
	code string
	err  error
}

func (d fakeDecrypter) Decrypt(context.Context, string) (string, error) {
	return d.code, d.err
}

type failingHistory struct{}

func (failingHistory) Save(context.Context, Record, time.Time) error {
	return errors.New("history unavailable")
}

func (failingHistory) CountByPhoneNumber(context.Context, string, time.Time) (int, error) {
	return 0, errors.New("history unavailable")
}

// recordingPolicy echoes parts of the policy input into the message.
const recordingPolicy = `
package cognito_custom_sender_sms_policy

import rego.v1

result := {
	"action": "allow",
	"allow": {
		"message": sprintf("%s|%s|%s|%d|%s|{####}", [
			input.trigger,
			input.phoneNumberData.country,
			input.phoneNumberData.number,
			input.history.recentAttempts,
			input.callerContext.clientId,
		]),
		"messageType": "Transactional",
		"senderId": "EXAMPLE",
		"shortCode": "",
	},
}
`

type harness struct {
	sender    *Sender
	history   *MemoryHistory
	publisher *fakePublisher
	now       time.Time
}

func newHarness(t *testing.T, policy string) *harness {
	t.Helper()
	pp, err := PreparePolicy(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{history: NewMemoryHistory(), publisher: &fakePublisher{}, now: testNow}
	h.sender = &Sender{
		Config:         &config.Config{AppSMSThrottlePeriod: 15 * time.Minute, AppSMSHistoryTTL: 30 * 24 * time.Hour},
		Decrypter:      fakeDecrypter{code: "123456"},
		PreparedPolicy: pp,
		History:        h.history,
		Publisher:      h.publisher,
		Now:            func() time.Time { return h.now },
	}
	return h
}

func smsEvent(trigger, phone, code string) types.CognitoEventUserPoolsCustomSMSSender {
	return types.CognitoEventUserPoolsCustomSMSSender{
		CognitoEventUserPoolsHeader: events.CognitoEventUserPoolsHeader{
			TriggerSource: trigger,
			CallerContext: events.CognitoEventUserPoolsCallerContext{ClientID: "1example23456789"},
		},
		Request: types.CognitoEventUserPoolsCustomSMSSenderRequest{
			UserAttributes: map[string]any{
				"sub":                   "00000000-0000-0000-0000-000000000000",
				"email":                 "user@example.com",
				"email_verified":        "true",
				"phone_number":          phone,
				"phone_number_verified": "true",
			},
			Code: code,
			Type: "customSMSSenderRequestV1",
		},
	}
}

func TestSendSMS_SendsWithPolicyInput(t *testing.T) {
	h := newHarness(t, recordingPolicy)

	if err := h.sender.SendSMS(context.Background(), smsEvent("CustomSMSSender_SignUp", "+12065550100", "ciphertext")); err != nil {
		t.Fatal(err)
	}

	if len(h.publisher.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(h.publisher.sent))
	}
	m := h.publisher.sent[0]
	want := "CustomSMSSender_SignUp|US|+12065550100|1|1example23456789|123456"
	if m.Body != want || m.PhoneNumber != "+12065550100" || m.SenderID != "EXAMPLE" || m.MessageType != "Transactional" {
		t.Errorf("message = %+v, want body %q", m, want)
	}
}

func TestSendSMS_SavesHistory(t *testing.T) {
	h := newHarness(t, recordingPolicy)
	if err := h.sender.SendSMS(context.Background(), smsEvent("CustomSMSSender_SignUp", "+1 206 555 0100", "c")); err != nil {
		t.Fatal(err)
	}

	recs := h.history.Records()
	want := Record{
		Trigger:                "CustomSMSSender_SignUp",
		UserID:                 "00000000-0000-0000-0000-000000000000",
		UserEmailAddress:       "user@example.com",
		UserPhoneNumber:        "+12065550100",
		UserPhoneNumberCountry: "US",
		SentAt:                 testNow,
	}
	if len(recs) != 1 || recs[0] != want {
		t.Errorf("records = %+v, want %+v", recs, want)
	}
}

func TestSendSMS_InvalidPhoneNumber(t *testing.T) {
	for _, phone := range []string{"invalid-phone-number", "", "2065550100"} {
		t.Run(phone, func(t *testing.T) {
			h := newHarness(t, recordingPolicy)
			// an invalid number is dropped without an error, so lambda doesn't retry
			if err := h.sender.SendSMS(context.Background(), smsEvent("CustomSMSSender_SignUp", phone, "c")); err != nil {
				t.Fatalf("SendSMS() error = %v", err)
			}
			if len(h.publisher.sent) != 0 || len(h.history.Records()) != 0 {
				t.Error("invalid numbers should not be sent or recorded")
			}
		})
	}
}

func TestSendSMS_ExamplePolicyThrottles(t *testing.T) {
	policy, err := os.ReadFile("../../fixtures/sms-policy.rego")
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, string(policy))
	ctx := context.Background()

	for i := range 7 {
		if err := h.sender.SendSMS(ctx, smsEvent("CustomSMSSender_Authentication", "+12065550100", "c")); err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
		h.now = h.now.Add(time.Minute)
	}

	// attempts are recorded before counting, so the 6th sees 6 recent attempts
	if got := len(h.publisher.sent); got != 5 {
		t.Errorf("sent %d messages, want 5 before the policy blocks", got)
	}
	if got := len(h.history.Records()); got != 7 {
		t.Errorf("recorded %d attempts, want 7 (blocked attempts are recorded)", got)
	}
	if h.publisher.sent[0].Body != "Your code is: 123456" {
		t.Errorf("body = %q", h.publisher.sent[0].Body)
	}

	// attempts older than the throttle period no longer count
	h.now = h.now.Add(15 * time.Minute)
	if err := h.sender.SendSMS(ctx, smsEvent("CustomSMSSender_Authentication", "+12065550100", "c")); err != nil {
		t.Fatal(err)
	}
	if got := len(h.publisher.sent); got != 6 {
		t.Errorf("sent %d messages after the throttle period, want 6", got)
	}
}

func TestSendSMS_Blocked(t *testing.T) {
	policies := map[string]string{
		"block": `package cognito_custom_sender_sms_policy
import rego.v1
result := {"action": "block", "block": {"reason": "blocked country"}}`,
		"deny": `package cognito_custom_sender_sms_policy
import rego.v1
result := {"action": "deny", "reason": "denied"}`,
	}

	for name, policy := range policies {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, policy)
			h.sender.Decrypter = fakeDecrypter{err: errors.New("decrypt should not be called")}
			if err := h.sender.SendSMS(context.Background(), smsEvent("CustomSMSSender_SignUp", "+12065550100", "c")); err != nil {
				t.Fatalf("SendSMS() error = %v, want a block without an error", err)
			}
			if len(h.publisher.sent) != 0 {
				t.Error("blocked messages should not be sent")
			}
		})
	}
}

func TestSendSMS_PolicyErrors(t *testing.T) {
	policies := map[string]string{
		"missing action": `package cognito_custom_sender_sms_policy
import rego.v1
result := {"allow": {"message": "hi"}}`,
		"missing message": `package cognito_custom_sender_sms_policy
import rego.v1
result := {"action": "allow", "allow": {}}`,
		"undefined result": `package cognito_custom_sender_sms_policy
import rego.v1
result := 1 if false`,
	}

	for name, policy := range policies {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, policy)
			if err := h.sender.SendSMS(context.Background(), smsEvent("CustomSMSSender_SignUp", "+12065550100", "c")); err == nil {
				t.Error("SendSMS() should return an error")
			}
			if len(h.publisher.sent) != 0 {
				t.Error("nothing should be sent")
			}
		})
	}
}

func TestSendSMS_DecryptAndPublishErrors(t *testing.T) {
	t.Run("decrypt", func(t *testing.T) {
		h := newHarness(t, recordingPolicy)
		h.sender.Decrypter = fakeDecrypter{err: errors.New("kms unavailable")}
		err := h.sender.SendSMS(context.Background(), smsEvent("CustomSMSSender_SignUp", "+12065550100", "c"))
		if err == nil || !strings.Contains(err.Error(), "decrypt") {
			t.Errorf("SendSMS() error = %v, want a decrypt error", err)
		}
	})

	t.Run("publish", func(t *testing.T) {
		h := newHarness(t, recordingPolicy)
		h.publisher.err = errors.New("sns unavailable")
		err := h.sender.SendSMS(context.Background(), smsEvent("CustomSMSSender_SignUp", "+12065550100", "c"))
		if err == nil || !strings.Contains(err.Error(), "send sms") {
			t.Errorf("SendSMS() error = %v, want a send error", err)
		}
	})
}

func TestSendSMS_NoCodeKeepsPlaceholder(t *testing.T) {
	h := newHarness(t, recordingPolicy)
	h.sender.Decrypter = fakeDecrypter{err: errors.New("decrypt should not be called")}
	if err := h.sender.SendSMS(context.Background(), smsEvent("CustomSMSSender_AccountTakeOverNotification", "+12065550100", "")); err != nil {
		t.Fatal(err)
	}
	if body := h.publisher.sent[0].Body; !strings.HasSuffix(body, "|{####}") {
		t.Errorf("body = %q, want the placeholder left as is", body)
	}
}

func TestSendSMS_ReplacesFirstPlaceholderOnly(t *testing.T) {
	h := newHarness(t, `package cognito_custom_sender_sms_policy
import rego.v1
result := {"action": "allow", "allow": {"message": "{####} and {####}"}}`)
	if err := h.sender.SendSMS(context.Background(), smsEvent("CustomSMSSender_SignUp", "+12065550100", "c")); err != nil {
		t.Fatal(err)
	}
	if body := h.publisher.sent[0].Body; body != "123456 and {####}" {
		t.Errorf("body = %q, want only the first placeholder replaced, as before", body)
	}
}

func TestSendSMS_HistoryFailureFailsOpen(t *testing.T) {
	h := newHarness(t, recordingPolicy)
	h.sender.History = failingHistory{}
	if err := h.sender.SendSMS(context.Background(), smsEvent("CustomSMSSender_SignUp", "+12065550100", "c")); err != nil {
		t.Fatal(err)
	}
	if len(h.publisher.sent) != 1 || !strings.Contains(h.publisher.sent[0].Body, "|0|") {
		t.Errorf("sent = %+v, want a send with recentAttempts 0", h.publisher.sent)
	}
}

func TestPreparePolicy_RegoV0(t *testing.T) {
	// node.js sender policies were compiled by opa 0.54, which only accepts
	// rego v0 syntax
	v0 := `package cognito_custom_sender_sms_policy

default result = {"action": "allow", "allow": {"message": "Your code is: {####}"}}

result = {"action": "block", "block": {"reason": "rate limit exceeded"}} {
  input.history.recentAttempts > 1
}
`
	h := newHarness(t, v0)
	ctx := context.Background()
	for range 2 {
		if err := h.sender.SendSMS(ctx, smsEvent("CustomSMSSender_SignUp", "+12065550100", "c")); err != nil {
			t.Fatal(err)
		}
	}
	if len(h.publisher.sent) != 1 {
		t.Errorf("sent %d messages, want the v0 policy to block the second", len(h.publisher.sent))
	}
}

func TestPreparePolicy_InvalidReportsV1Error(t *testing.T) {
	_, err := PreparePolicy(context.Background(), "package cognito_custom_sender_sms_policy\nresult := {")
	if err == nil {
		t.Fatal("PreparePolicy() should fail")
	}
}

func TestPreparePolicy_V1ParsesAsV1(t *testing.T) {
	// "if" is a keyword in v1; this only compiles when parsed as v1
	pp, err := PreparePolicy(context.Background(), `package cognito_custom_sender_sms_policy
result := {"action": "allow", "allow": {"message": "x"}} if true`)
	if err != nil {
		t.Fatal(err)
	}
	out, err := opa.Evaluate[PolicyOutput](context.Background(), pp, PolicyInput{})
	if err != nil || out.Action != "allow" {
		t.Errorf("Evaluate() = %+v, %v", out, err)
	}
}

func TestNewSender_DebugUsesMemoryHistory(t *testing.T) {
	cfg := &config.Config{
		AppKmsKeyId:            encryption.MockKeyID,
		AppSMSSenderPolicyPath: "../../fixtures/sms-policy.rego",
		DebugMode:              true,
		AWSConfig:              testAWSConfig(),
	}
	s, err := NewSender(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.History.(*MemoryHistory); !ok {
		t.Errorf("History = %T, want *MemoryHistory", s.History)
	}
	if p, ok := s.Publisher.(*SNSPublisher); !ok || !p.DryRun {
		t.Errorf("Publisher = %+v, want dry-run sns publisher", s.Publisher)
	}
}

// testAWSConfig has static credentials so building clients makes no calls.
func testAWSConfig() *aws.Config {
	return &aws.Config{
		Region: "us-east-1",
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	}
}
