package sender

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/opa"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/ratelimit"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/verifier"
)

const rateLimitPolicy = `
package cognito_custom_sender_email_policy

import rego.v1

default has_rate_limit := false

has_rate_limit if input.rateLimit

result := {"action": "deny", "reason": "global rate limit"} if {
	input.rateLimit.global.wouldThrottle
}

result := {
	"action": "allow",
	"allow": {
		"srcAddress": "noreply@example.com",
		"dstAddress": input.userAttributes.email,
		"providers": {"ses": {"templateId": "t", "templateData": {
			"hasRateLimit": has_rate_limit,
			"class": object.get(input, ["rateLimit", "class"], ""),
			"decision": object.get(input, ["rateLimit", "decision"], ""),
			"window": object.get(input, ["rateLimit", "destination", 0, "window"], ""),
		}}},
	},
} if {
	not input.rateLimit.global.wouldThrottle
}
`

type fakeLimiter struct {
	result *ratelimit.Result
	reqs   []ratelimit.Request
}

func (f *fakeLimiter) Check(_ context.Context, req ratelimit.Request) *ratelimit.Result {
	f.reqs = append(f.reqs, req)
	return f.result
}

type countingVerifier struct{ calls int }

func (v *countingVerifier) VerifyEmail(context.Context, string) (*verifier.EmailVerificationResult, error) {
	v.calls++
	return &verifier.EmailVerificationResult{IsValid: true}, nil
}

type countingProvider struct{ sent []*types.EmailData }

func (p *countingProvider) Name() string { return "ses" }

func (p *countingProvider) Send(_ context.Context, d *types.EmailData) error {
	p.sent = append(p.sent, d)
	return nil
}

type rejectingDecrypter struct{}

func (rejectingDecrypter) Decrypt(context.Context, string) (string, error) {
	return "", errors.New("decrypt should not be called")
}

func newRateLimitedSender(t *testing.T, limiter RateLimiter) (*Sender, *countingVerifier, *countingProvider) {
	t.Helper()
	pp, err := opa.PreparePolicy(context.Background(), rateLimitPolicy, PolicyQuery)
	if err != nil {
		t.Fatal(err)
	}
	v, p := &countingVerifier{}, &countingProvider{}
	return &Sender{
		Config:         &config.Config{AppEmailProvider: "ses", AppEmailVerificationEnabled: true},
		Decrypter:      rejectingDecrypter{},
		EmailVerifier:  v,
		PreparedPolicy: pp,
		Provider:       p,
		RateLimiter:    limiter,
	}, v, p
}

func rateLimitEvent() types.CognitoEventUserPoolsCustomEmailSender {
	return types.CognitoEventUserPoolsCustomEmailSender{
		CognitoEventUserPoolsHeader: events.CognitoEventUserPoolsHeader{
			TriggerSource: "CustomEmailSender_Authentication",
			UserName:      "user-1",
		},
		Request: types.CognitoEventUserPoolsCustomEmailSenderRequest{
			UserAttributes: map[string]any{"email": "user@example.com", "email_verified": "true"},
			Code:           "encrypted-code",
		},
	}
}

func TestSendEmail_RateLimitThrottled(t *testing.T) {
	for _, decision := range []string{
		ratelimit.DecisionThrottledDestination,
		ratelimit.DecisionThrottledUser,
		ratelimit.DecisionThrottledGlobal,
		ratelimit.DecisionFailClosed,
	} {
		t.Run(decision, func(t *testing.T) {
			limiter := &fakeLimiter{result: &ratelimit.Result{Decision: decision}}
			s, v, p := newRateLimitedSender(t, limiter)

			// a throttle is not an error, so lambda does not retry it
			if err := s.SendEmail(context.Background(), rateLimitEvent()); err != nil {
				t.Fatalf("SendEmail() error = %v", err)
			}
			if len(p.sent) != 0 || v.calls != 0 {
				t.Errorf("sent = %d, verifier calls = %d; want both 0", len(p.sent), v.calls)
			}
		})
	}
}

func TestGetEmailData_RateLimitRequest(t *testing.T) {
	limiter := &fakeLimiter{result: &ratelimit.Result{Decision: ratelimit.DecisionSent}}
	s, _, _ := newRateLimitedSender(t, limiter)

	if _, err := s.GetEmailData(context.Background(), rateLimitEvent()); err != nil {
		t.Fatal(err)
	}
	if len(limiter.reqs) != 1 {
		t.Fatalf("limiter called %d times, want 1", len(limiter.reqs))
	}
	req := limiter.reqs[0]
	if req.Trigger != "CustomEmailSender_Authentication" || req.Email != "user@example.com" || req.UserName != "user-1" || req.Code != "encrypted-code" {
		t.Errorf("request = %+v", req)
	}
}

func TestGetEmailData_PolicyInputIncludesRateLimit(t *testing.T) {
	limiter := &fakeLimiter{result: &ratelimit.Result{
		Class:       ratelimit.ClassAuthentication,
		Decision:    ratelimit.DecisionSent,
		Destination: []ratelimit.WindowState{{Window: "15m", Count: 1, Max: 5}},
	}}
	s, v, _ := newRateLimitedSender(t, limiter)

	data, err := s.GetEmailData(context.Background(), rateLimitEvent())
	if err != nil {
		t.Fatal(err)
	}
	td := data.ProviderData("ses").TemplateData
	if td["hasRateLimit"] != true || td["class"] != "authentication" || td["decision"] != "sent" || td["window"] != "15m" {
		t.Errorf("templateData = %v, want rate limit fields from the policy input", td)
	}
	if v.calls != 1 {
		t.Errorf("verifier calls = %d, want 1 for an allowed email", v.calls)
	}
}

func TestGetEmailData_PolicyCanDenyOnRateLimit(t *testing.T) {
	limiter := &fakeLimiter{result: &ratelimit.Result{
		Decision: ratelimit.DecisionSent,
		Global:   ratelimit.GlobalState{Mode: ratelimit.ModeCount, WouldThrottle: true},
	}}
	s, _, _ := newRateLimitedSender(t, limiter)

	data, err := s.GetEmailData(context.Background(), rateLimitEvent())
	if err != nil || data != nil {
		t.Errorf("GetEmailData() = %v, %v; want a policy deny", data, err)
	}
}

func TestGetEmailData_WithoutRateLimiterOmitsInput(t *testing.T) {
	s, _, _ := newRateLimitedSender(t, nil)

	data, err := s.GetEmailData(context.Background(), rateLimitEvent())
	if err != nil {
		t.Fatal(err)
	}
	if td := data.ProviderData("ses").TemplateData; td["hasRateLimit"] != false {
		t.Errorf("hasRateLimit = %v, want input.rateLimit to be absent", td["hasRateLimit"])
	}
}
