// Package e2e tests the service end to end: configuration is read from
// environment variables and wired by app.New exactly as in Lambda. Only the
// AWS clients, the KMS decrypter, the DynamoDB stores, and the SendGrid API
// are replaced with in-process fakes.
package e2e

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sns"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/app"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/decrypt"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/handler"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/ratelimit"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/sms"
)

const policies = "../examples/policies/"

// env is one configured instance of the service and its fakes.
type env struct {
	t        *testing.T
	handler  *handler.Handler
	ses      *fakeSES
	sns      *fakeSNS
	sendgrid *fakeSendGrid
	history  *sms.MemoryHistory
}

// newEnv builds the service from vars on top of a minimal email
// configuration that sends through SES.
func newEnv(t *testing.T, vars map[string]string) *env {
	t.Helper()

	e := &env{t: t, ses: &fakeSES{sendingEnabled: true}, sns: &fakeSNS{}, sendgrid: newFakeSendGrid(t), history: sms.NewMemoryHistory()}

	all := map[string]string{
		"APP_KMS_KEY_ID":                          "arn:aws:kms:us-east-1:111122223333:key/example",
		"APP_EMAIL_SENDER_POLICY_PATH":            policies + "email/route.rego",
		"APP_EMAIL_VERIFICATION_ENABLED":          "false",
		"APP_SENDGRID_API_HOST":                   e.sendgrid.URL,
		"APP_SENDGRID_EMAIL_SEND_API_KEY":         "SG.send",
		"APP_SENDGRID_EMAIL_VERIFICATION_API_KEY": "SG.verify",
	}
	maps.Copy(all, vars)

	cfg, err := config.Load(func(k string) (string, bool) { v, ok := all[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}

	e.handler, err = app.New(context.Background(), cfg, aws.Config{Region: "us-east-1"},
		app.WithDecrypter(decrypt.Plaintext{}),
		app.WithSESClient(e.ses),
		app.WithSNSClient(e.sns),
		app.WithRateLimitStore(ratelimit.NewMemoryStore()),
		app.WithSMSHistory(e.history),
	)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) handle(raw json.RawMessage) error {
	e.t.Helper()
	return e.handler.Handle(context.Background(), raw)
}

func (e *env) mustHandle(raw json.RawMessage) {
	e.t.Helper()
	if err := e.handle(raw); err != nil {
		e.t.Fatalf("Handle() = %v", err)
	}
}

// emailEvent returns a custom email sender event. code is plaintext, since
// the environment decrypts with decrypt.Plaintext.
func emailEvent(trigger, clientID, email, code string) json.RawMessage {
	return event(trigger, clientID, code, map[string]any{
		"sub":                 "00000000-0000-4000-8000-000000000001",
		"cognito:user_status": "UNCONFIRMED",
		"email":               email,
		"email_verified":      "false",
	})
}

func smsEvent(trigger, phone, code string) json.RawMessage {
	return event(trigger, "1example23456789", code, map[string]any{
		"sub":                   "00000000-0000-4000-8000-000000000001",
		"phone_number":          phone,
		"phone_number_verified": "true",
	})
}

func event(trigger, clientID, code string, attrs map[string]any) json.RawMessage {
	b, err := json.Marshal(map[string]any{
		"version":       "1",
		"triggerSource": trigger,
		"region":        "us-east-1",
		"userPoolId":    "us-east-1_EXAMPLE",
		"userName":      "user-1",
		"callerContext": map[string]any{"awsSdkVersion": "aws-sdk-unknown-unknown", "clientId": clientID},
		"request": map[string]any{
			"type":           "customSenderRequestV1",
			"code":           code,
			"clientMetadata": map[string]string{},
			"userAttributes": attrs,
		},
	})
	if err != nil {
		panic(err)
	}
	return b
}

// sesEmail is a captured SES send.
type sesEmail struct {
	From, To, Template string
	Data               map[string]any
}

type fakeSES struct {
	mu             sync.Mutex
	sent           []sesEmail
	sendErr        error
	sendingEnabled bool
}

func (f *fakeSES) SendEmail(_ context.Context, in *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	m := sesEmail{
		From:     aws.ToString(in.FromEmailAddress),
		To:       in.Destination.ToAddresses[0],
		Template: aws.ToString(in.Content.Template.TemplateName),
	}
	if err := json.Unmarshal([]byte(aws.ToString(in.Content.Template.TemplateData)), &m.Data); err != nil {
		return nil, err
	}
	f.sent = append(f.sent, m)
	return &sesv2.SendEmailOutput{MessageId: aws.String("ses-message")}, nil
}

func (f *fakeSES) GetAccount(context.Context, *sesv2.GetAccountInput, ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &sesv2.GetAccountOutput{SendingEnabled: f.sendingEnabled}, nil
}

func (f *fakeSES) emails() []sesEmail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sesEmail(nil), f.sent...)
}

type fakeSNS struct {
	mu   sync.Mutex
	sent []*sns.PublishInput
}

func (f *fakeSNS) Publish(_ context.Context, in *sns.PublishInput, _ ...func(*sns.Options)) (*sns.PublishOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, in)
	return &sns.PublishOutput{MessageId: aws.String("sns-message")}, nil
}

func (f *fakeSNS) messages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.sent))
	for i, in := range f.sent {
		out[i] = aws.ToString(in.Message)
	}
	return out
}

// fakeSendGrid serves the SendGrid mail send and validation APIs.
type fakeSendGrid struct {
	*httptest.Server

	mu          sync.Mutex
	mails       []map[string]any
	validations []string
	// verdicts maps an address to its validation verdict ("Valid" by default)
	verdicts map[string]string
	sendCode int
}

func newFakeSendGrid(t *testing.T) *fakeSendGrid {
	f := &fakeSendGrid{verdicts: map[string]string{}, sendCode: http.StatusAccepted}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeSendGrid) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var body map[string]any
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &body)

	switch r.URL.Path {
	case "/v3/mail/send":
		if f.sendCode != http.StatusAccepted {
			http.Error(w, `{"errors":[{"message":"failed"}]}`, f.sendCode)
			return
		}
		f.mails = append(f.mails, body)
		w.WriteHeader(http.StatusAccepted)
	case "/v3/validations/email":
		email, _ := body["email"].(string)
		f.validations = append(f.validations, email)
		verdict := f.verdicts[email]
		if verdict == "" {
			verdict = "Valid"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"email": email, "verdict": verdict, "score": 0.9}})
	default:
		http.NotFound(w, r)
	}
}

// templates returns the template ID of each email sent through SendGrid.
func (f *fakeSendGrid) templates() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.mails))
	for i, m := range f.mails {
		out[i], _ = m["template_id"].(string)
	}
	return out
}

func (f *fakeSendGrid) validationCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.validations)
}
