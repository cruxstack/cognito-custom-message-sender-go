package email

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/cognito"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/mailer"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/policy"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/ratelimit"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/verify"
)

// echoPolicy denies undeliverable addresses and otherwise echoes its input
// into the template data, so tests can assert what the policy saw.
const echoPolicy = `package cognito_custom_sender_email_policy
import rego.v1

result := {"action": "deny", "reason": "undeliverable"} if {
	input.emailVerification.valid == false
} else := {
	"action": "allow",
	"allow": {
		"srcAddress": "ACME <no-reply@example.com>",
		"providers": {"ses": {"templateId": "acme-code", "templateData": {"input": input}}},
	},
}
`

type fakeMailer struct {
	sent []*mailer.Message
	err  error
}

func (f *fakeMailer) Send(_ context.Context, m *mailer.Message) error {
	f.sent = append(f.sent, m)
	return f.err
}

type fakeDecrypter struct {
	err   error
	calls int
}

func (f *fakeDecrypter) Decrypt(_ context.Context, ciphertext string) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	return strings.TrimPrefix(ciphertext, "enc:"), nil
}

type fakeVerifier struct {
	result *verify.Result
	err    error
}

func (f fakeVerifier) Verify(context.Context, string) (*verify.Result, error) {
	return f.result, f.err
}

type fakeLimiter struct {
	result *ratelimit.Result
}

func (f fakeLimiter) Check(context.Context, ratelimit.Request) *ratelimit.Result {
	return f.result
}

type harness struct {
	sender    *Sender
	mailer    *fakeMailer
	decrypter *fakeDecrypter
}

func newHarness(t *testing.T, src string) *harness {
	t.Helper()
	pol, err := policy.Compile(context.Background(), "policy.rego", src, PolicyQuery)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{mailer: &fakeMailer{}, decrypter: &fakeDecrypter{}}
	h.sender, err = New(Config{Policy: pol, Decrypter: h.decrypter, Mailer: h.mailer})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func event(trigger, email, code string) *cognito.Event {
	attrs := map[string]any{"sub": "user-sub", "email_verified": "false"}
	if email != "" {
		attrs["email"] = email
	}
	return &cognito.Event{
		CognitoEventUserPoolsHeader: events.CognitoEventUserPoolsHeader{
			TriggerSource: trigger,
			Region:        "us-east-1",
			UserPoolID:    "us-east-1_EXAMPLE",
			UserName:      "user-1",
			CallerContext: events.CognitoEventUserPoolsCallerContext{ClientID: "client-1"},
		},
		Request: cognito.Request{Code: code, UserAttributes: attrs},
	}
}

func policyInput(t *testing.T, m *mailer.Message) map[string]any {
	t.Helper()
	in, ok := m.Templates["ses"].Data["input"].(map[string]any)
	if !ok {
		t.Fatalf("template data has no policy input: %v", m.Templates["ses"].Data)
	}
	return in
}

func TestHandle_Sends(t *testing.T) {
	h := newHarness(t, echoPolicy)

	if err := h.sender.Handle(context.Background(), event(cognito.TriggerEmailSignUp, "user@example.com", "enc:123456")); err != nil {
		t.Fatal(err)
	}

	if len(h.mailer.sent) != 1 {
		t.Fatalf("sent %d emails, want 1", len(h.mailer.sent))
	}
	m := h.mailer.sent[0]
	if m.From != "ACME <no-reply@example.com>" || m.To != "user@example.com" || m.Code != "123456" {
		t.Errorf("message = %+v", m)
	}

	in := policyInput(t, m)
	for k, want := range map[string]any{"trigger": cognito.TriggerEmailSignUp, "userPoolId": "us-east-1_EXAMPLE", "region": "us-east-1", "userName": "user-1"} {
		if in[k] != want {
			t.Errorf("input.%s = %v, want %v", k, in[k], want)
		}
	}
	if _, ok := in["clientMetadata"].(map[string]any); !ok {
		t.Errorf("input.clientMetadata = %v, want an empty object", in["clientMetadata"])
	}
	if _, ok := in["emailVerification"]; ok {
		t.Error("input.emailVerification should be unset when verification is disabled")
	}
}

func TestHandle_DeniedByPolicy(t *testing.T) {
	h := newHarness(t, echoPolicy)
	h.sender.cfg.Verifier = fakeVerifier{result: &verify.Result{Valid: false}}

	if err := h.sender.Handle(context.Background(), event(cognito.TriggerEmailSignUp, "user@example.com", "enc:1")); err != nil {
		t.Fatal(err)
	}
	if len(h.mailer.sent) != 0 || h.decrypter.calls != 0 {
		t.Errorf("denied email: %d sends, %d decrypts; want none", len(h.mailer.sent), h.decrypter.calls)
	}
}

func TestHandle_Verification(t *testing.T) {
	t.Run("result is passed to the policy", func(t *testing.T) {
		h := newHarness(t, echoPolicy)
		h.sender.cfg.Verifier = fakeVerifier{result: &verify.Result{Provider: "offline", Valid: true, Verdict: "Valid", Score: 1}}
		if err := h.sender.Handle(context.Background(), event(cognito.TriggerEmailSignUp, "user@example.com", "")); err != nil {
			t.Fatal(err)
		}
		v, _ := policyInput(t, h.mailer.sent[0])["emailVerification"].(map[string]any)
		if v["valid"] != true || v["score"] != 1.0 || v["provider"] != "offline" {
			t.Errorf("input.emailVerification = %v", v)
		}
	})

	t.Run("an unavailable verifier leaves the input unset", func(t *testing.T) {
		h := newHarness(t, echoPolicy)
		h.sender.cfg.Verifier = fakeVerifier{err: errors.New("timeout")}
		if err := h.sender.Handle(context.Background(), event(cognito.TriggerEmailSignUp, "user@example.com", "")); err != nil {
			t.Fatal(err)
		}
		if _, ok := policyInput(t, h.mailer.sent[0])["emailVerification"]; ok {
			t.Error("input.emailVerification should be unset")
		}
	})
}

func TestHandle_RateLimited(t *testing.T) {
	h := newHarness(t, "package cognito_custom_sender_email_policy\nresult := 1") // invalid if evaluated
	h.sender.cfg.RateLimiter = fakeLimiter{result: &ratelimit.Result{Decision: ratelimit.DecisionThrottledDestination}}

	if err := h.sender.Handle(context.Background(), event(cognito.TriggerEmailSignUp, "user@example.com", "enc:1")); err != nil {
		t.Fatalf("Handle() = %v, want a throttle without an error", err)
	}
	if len(h.mailer.sent) != 0 {
		t.Error("throttled email should not be sent")
	}
}

func TestHandle_RateLimitResultIsPassedToPolicy(t *testing.T) {
	h := newHarness(t, echoPolicy)
	h.sender.cfg.RateLimiter = fakeLimiter{result: &ratelimit.Result{Class: "signup", Decision: ratelimit.DecisionSent}}

	if err := h.sender.Handle(context.Background(), event(cognito.TriggerEmailSignUp, "user@example.com", "")); err != nil {
		t.Fatal(err)
	}
	rl, _ := policyInput(t, h.mailer.sent[0])["rateLimit"].(map[string]any)
	if rl["class"] != "signup" || rl["decision"] != "sent" {
		t.Errorf("input.rateLimit = %v", rl)
	}
}

func TestHandle_Errors(t *testing.T) {
	tests := []struct {
		name    string
		policy  string
		setup   func(*harness)
		event   *cognito.Event
		wantErr string
	}{
		{
			name:    "undefined policy result",
			policy:  "package cognito_custom_sender_email_policy\nimport rego.v1\nresult := 1 if false",
			wantErr: "undefined",
		},
		{
			name:    "invalid decision",
			policy:  `package cognito_custom_sender_email_policy` + "\n" + `result := {"action": "send"}`,
			wantErr: "unknown action",
		},
		{
			name:    "decrypt failure",
			policy:  echoPolicy,
			setup:   func(h *harness) { h.decrypter.err = errors.New("kms unavailable") },
			wantErr: "decrypt code",
		},
		{
			name:    "delivery failure",
			policy:  echoPolicy,
			setup:   func(h *harness) { h.mailer.err = errors.New("all providers failed") },
			wantErr: "send email",
		},
		{
			name:    "no destination",
			policy:  echoPolicy,
			event:   event(cognito.TriggerEmailSignUp, "", "enc:1"),
			wantErr: "dstAddress",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.policy)
			if tc.setup != nil {
				tc.setup(h)
			}
			e := tc.event
			if e == nil {
				e = event(cognito.TriggerEmailSignUp, "user@example.com", "enc:1")
			}
			err := h.sender.Handle(context.Background(), e)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Handle() = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestDecision_Message(t *testing.T) {
	ses := map[string]mailer.Template{"ses": {ID: "t"}}

	tests := []struct {
		name    string
		d       Decision
		wantTo  string
		wantNil bool
		wantErr string
	}{
		{name: "allow", d: Decision{Action: "allow", Allow: &Allow{SrcAddress: "a@x.io", DstAddress: "b@x.io", Providers: ses}}, wantTo: "b@x.io"},
		{name: "destination defaults to the user's email", d: Decision{Action: "allow", Allow: &Allow{SrcAddress: "a@x.io", Providers: ses}}, wantTo: "user@x.io"},
		{name: "deny", d: Decision{Action: "deny", Reason: "no"}, wantNil: true},
		{name: "block is deny", d: Decision{Action: "block"}, wantNil: true},
		{name: "missing action", d: Decision{}, wantErr: "action"},
		{name: "unknown action", d: Decision{Action: "drop"}, wantErr: "unknown action"},
		{name: "missing allow", d: Decision{Action: "allow"}, wantErr: `"allow" is required`},
		{name: "missing source", d: Decision{Action: "allow", Allow: &Allow{Providers: ses}}, wantErr: "srcAddress"},
		{name: "missing providers", d: Decision{Action: "allow", Allow: &Allow{SrcAddress: "a@x.io"}}, wantErr: "providers"},
		{name: "legacy template", d: Decision{Action: "allow", Allow: &Allow{SrcAddress: "a@x.io", LegacyTemplateID: "old"}}, wantErr: "no longer supported"},
		{name: "unknown provider", d: Decision{Action: "allow", Allow: &Allow{SrcAddress: "a@x.io", Providers: map[string]mailer.Template{"sengrid": {ID: "t"}}}}, wantErr: "not a known provider"},
		{name: "empty template id", d: Decision{Action: "allow", Allow: &Allow{SrcAddress: "a@x.io", Providers: map[string]mailer.Template{"ses": {}}}}, wantErr: "templateId"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := tc.d.Message("user@x.io")
			switch {
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("Message() error = %v, want %q", err, tc.wantErr)
				}
			case err != nil:
				t.Errorf("Message() error = %v", err)
			case tc.wantNil != (m == nil):
				t.Errorf("Message() = %+v, want nil %v", m, tc.wantNil)
			case m != nil && m.To != tc.wantTo:
				t.Errorf("To = %q, want %q", m.To, tc.wantTo)
			}
		})
	}
}

func TestNew_RequiresDependencies(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New() should require a policy, decrypter, and mailer")
	}
}
