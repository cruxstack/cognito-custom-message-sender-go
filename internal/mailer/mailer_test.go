package mailer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/sendgrid"
)

type fakeProvider struct {
	name    string
	err     error
	healthy bool
	sent    int
}

func (f *fakeProvider) Name() string { return f.name }

func (f *fakeProvider) Send(context.Context, *Message) error {
	f.sent++
	return f.err
}

func (f *fakeProvider) Healthy(context.Context) bool { return f.healthy }

func message(providers ...string) *Message {
	m := &Message{From: "a@example.com", To: "b@example.com", Templates: map[string]Template{}}
	for _, p := range providers {
		m.Templates[p] = Template{ID: p + "-template"}
	}
	return m
}

func TestChain(t *testing.T) {
	tests := []struct {
		name      string
		ses, sg   fakeProvider
		templates []string
		wantErr   error
		wantSES   int
		wantSG    int
	}{
		{
			name:      "first provider sends",
			ses:       fakeProvider{healthy: true},
			sg:        fakeProvider{healthy: true},
			templates: []string{"ses", "sendgrid"},
			wantSES:   1,
		},
		{
			name:      "fails over on error",
			ses:       fakeProvider{healthy: true, err: errors.New("throttled")},
			sg:        fakeProvider{healthy: true},
			templates: []string{"ses", "sendgrid"},
			wantSES:   1, wantSG: 1,
		},
		{
			name:      "unhealthy provider is tried last",
			ses:       fakeProvider{healthy: false},
			sg:        fakeProvider{healthy: true},
			templates: []string{"ses", "sendgrid"},
			wantSG:    1,
		},
		{
			name:      "unhealthy provider is still tried when the others fail",
			ses:       fakeProvider{healthy: false},
			sg:        fakeProvider{healthy: true, err: errors.New("down")},
			templates: []string{"ses", "sendgrid"},
			wantSES:   1, wantSG: 1,
		},
		{
			name:      "skips providers without a template",
			ses:       fakeProvider{healthy: true},
			sg:        fakeProvider{healthy: true},
			templates: []string{"sendgrid"},
			wantSG:    1,
		},
		{
			name:      "no template for any provider",
			ses:       fakeProvider{healthy: true},
			sg:        fakeProvider{healthy: true},
			templates: []string{"other"},
			wantErr:   ErrNoTemplate,
		},
		{
			name:      "all providers fail",
			ses:       fakeProvider{healthy: true, err: errors.New("ses down")},
			sg:        fakeProvider{healthy: true, err: errors.New("sendgrid down")},
			templates: []string{"ses", "sendgrid"},
			wantErr:   errors.New("all email providers failed"),
			wantSES:   1, wantSG: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ses, sg := tc.ses, tc.sg
			ses.name, sg.name = ProviderSES, ProviderSendGrid

			err := NewChain(&ses, &sg).Send(context.Background(), message(tc.templates...))

			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("Send() = %v", err)
			case errors.Is(tc.wantErr, ErrNoTemplate) && !errors.Is(err, ErrNoTemplate):
				t.Fatalf("Send() = %v, want ErrNoTemplate", err)
			case tc.wantErr != nil && (err == nil || !strings.Contains(err.Error(), tc.wantErr.Error())):
				t.Fatalf("Send() = %v, want %v", err, tc.wantErr)
			}
			if ses.sent != tc.wantSES || sg.sent != tc.wantSG {
				t.Errorf("sends: ses=%d sendgrid=%d, want ses=%d sendgrid=%d", ses.sent, sg.sent, tc.wantSES, tc.wantSG)
			}
		})
	}
}

func TestChain_SingleProviderSkipsHealthCheck(t *testing.T) {
	ses := &fakeProvider{name: ProviderSES, healthy: false}
	if err := NewChain(ses).Send(context.Background(), message("ses")); err != nil || ses.sent != 1 {
		t.Errorf("Send() = %v with %d sends, want one send", err, ses.sent)
	}
}

func TestDryRun(t *testing.T) {
	d := DryRun{Providers: []string{ProviderSES, ProviderSendGrid}}
	if err := d.Send(context.Background(), message("sendgrid")); err != nil {
		t.Errorf("Send() = %v", err)
	}
	if err := d.Send(context.Background(), message()); !errors.Is(err, ErrNoTemplate) {
		t.Errorf("Send() = %v, want ErrNoTemplate", err)
	}
}

type fakeSES struct {
	input          *sesv2.SendEmailInput
	sendErr        error
	sendingEnabled bool
	accountErr     error
	accountCalls   int
}

func (f *fakeSES) SendEmail(_ context.Context, in *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	f.input = in
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	return &sesv2.SendEmailOutput{MessageId: aws.String("msg-1")}, nil
}

func (f *fakeSES) GetAccount(context.Context, *sesv2.GetAccountInput, ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error) {
	f.accountCalls++
	if f.accountErr != nil {
		return nil, f.accountErr
	}
	return &sesv2.GetAccountOutput{SendingEnabled: f.sendingEnabled}, nil
}

func TestSES_Send(t *testing.T) {
	f := &fakeSES{}
	m := &Message{
		From:      "ACME <no-reply@example.com>",
		To:        "user@example.com",
		Code:      "123456",
		Templates: map[string]Template{"ses": {ID: "acme-code", Data: map[string]any{"appName": "ACME", "code": "policy value"}}},
	}

	if err := NewSES(f, time.Minute).Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}

	in := f.input
	if aws.ToString(in.FromEmailAddress) != m.From || in.Destination.ToAddresses[0] != m.To ||
		aws.ToString(in.Content.Template.TemplateName) != "acme-code" {
		t.Errorf("input = %+v", in)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(aws.ToString(in.Content.Template.TemplateData)), &data); err != nil {
		t.Fatal(err)
	}
	if data["code"] != "123456" || data["appName"] != "ACME" {
		t.Errorf("template data = %v, want the code to replace the policy value", data)
	}
	if m.Templates["ses"].Data["code"] != "policy value" {
		t.Error("Send() must not modify the message's template data")
	}

	f.sendErr = errors.New("message rejected")
	if err := NewSES(f, time.Minute).Send(context.Background(), m); err == nil {
		t.Error("Send() should return the ses error")
	}
}

func TestSES_Healthy(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSES{sendingEnabled: true}
	p := NewSES(f, 30*time.Second)
	p.now = func() time.Time { return now }
	ctx := context.Background()

	if !p.Healthy(ctx) {
		t.Error("Healthy() = false with sending enabled")
	}

	// cached until the ttl passes
	f.sendingEnabled = false
	if !p.Healthy(ctx) || f.accountCalls != 1 {
		t.Errorf("Healthy() should use the cached result (calls %d)", f.accountCalls)
	}

	now = now.Add(31 * time.Second)
	if p.Healthy(ctx) || f.accountCalls != 2 {
		t.Errorf("Healthy() should be false after the cache expires (calls %d)", f.accountCalls)
	}

	// an api error is not a reason to skip ses
	now = now.Add(31 * time.Second)
	f.accountErr = errors.New("access denied")
	if !p.Healthy(ctx) {
		t.Error("Healthy() should assume healthy when the account can't be read")
	}
}

func TestSendGrid_Send(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	p := SendGrid{Client: sendgrid.New(srv.URL, "SG.key", nil)}
	m := message("sendgrid")
	m.Code = "654321"
	if err := p.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}

	pers := body["personalizations"].([]any)[0].(map[string]any)
	if body["template_id"] != "sendgrid-template" || pers["dynamic_template_data"].(map[string]any)["code"] != "654321" {
		t.Errorf("body = %v", body)
	}

	if err := p.Send(context.Background(), message("ses")); !errors.Is(err, ErrNoTemplate) {
		t.Errorf("Send() without a sendgrid template = %v, want ErrNoTemplate", err)
	}
}
