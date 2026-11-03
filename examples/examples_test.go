// Package examples_test keeps the example policies working: every policy
// must compile, its Rego unit tests must pass, and it must make the expected
// decision for each sample event.
package examples_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/tester"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/cognito"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/email"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/policy"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/ratelimit"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/sms"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/verify"
)

func readEvents(t *testing.T, path string) []*cognito.Event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var events []*cognito.Event
	if err := json.Unmarshal(data, &events); err != nil {
		t.Fatal(err)
	}
	return events
}

// emailOutcome evaluates an email policy the way the sender does and returns
// "send:<provider templates>", "deny", or "error".
func emailOutcome(t *testing.T, pol *policy.Engine, in email.PolicyInput, to string) string {
	t.Helper()
	d, err := policy.Eval[email.Decision](context.Background(), pol, in)
	if err != nil {
		t.Errorf("%s: eval: %v", in.Trigger, err)
		return "error"
	}
	msg, err := d.Message(to)
	switch {
	case err != nil:
		t.Errorf("%s: invalid decision: %v", in.Trigger, err)
		return "error"
	case msg == nil:
		return "deny"
	}
	var parts []string
	for _, p := range []string{"ses", "sendgrid"} {
		if tmpl, ok := msg.Template(p); ok {
			parts = append(parts, p+"="+tmpl.ID)
		}
	}
	return "send:" + strings.Join(parts, ",")
}

func TestEmailPolicies(t *testing.T) {
	ctx := context.Background()
	events := readEvents(t, "events/email.json")

	tests := map[string][]string{
		"basic.rego": {
			"send:ses=acme-code", "send:ses=acme-code", "send:ses=acme-code",
			"send:ses=acme-code", "send:ses=acme-code", "send:ses=acme-code",
		},
		"route.rego": {
			"send:ses=acme-welcome", "send:ses=acme-reset-password", "send:ses=acme-sign-in-code",
			"send:ses=acme-invitation", "send:ses=acme-security-alert", "send:ses=acme-welcome",
		},
		"failover.rego": {
			"send:ses=acme-code,sendgrid=d-0123456789abcdef0123456789abcdef",
			"send:ses=acme-code,sendgrid=d-0123456789abcdef0123456789abcdef",
			"send:ses=acme-code,sendgrid=d-0123456789abcdef0123456789abcdef",
			"send:ses=acme-code,sendgrid=d-0123456789abcdef0123456789abcdef",
			"send:ses=acme-code,sendgrid=d-0123456789abcdef0123456789abcdef",
			"send:ses=acme-code,sendgrid=d-0123456789abcdef0123456789abcdef",
		},
		// the last event's address fails offline verification
		"verification.rego": {
			"send:ses=acme-code", "send:ses=acme-code", "send:ses=acme-code",
			"send:ses=acme-code", "send:ses=acme-code", "deny",
		},
		"rate-limit.rego": {
			"send:ses=acme-code", "send:ses=acme-code", "send:ses=acme-code",
			"send:ses=acme-code", "send:ses=acme-code", "send:ses=acme-code",
		},
	}

	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			pol, err := policy.Load(ctx, filepath.Join("policies/email", name), email.PolicyQuery)
			if err != nil {
				t.Fatal(err)
			}
			if len(want) != len(events) {
				t.Fatalf("test has %d expectations for %d events", len(want), len(events))
			}
			for i, e := range events {
				to := e.Attribute("email")
				v, _ := verify.Offline{}.Verify(ctx, to)
				if got := emailOutcome(t, pol, email.NewPolicyInput(e, v, nil), to); got != want[i] {
					t.Errorf("event %d (%s) = %s, want %s", i, e.TriggerSource, got, want[i])
				}
			}
		})
	}
}

func TestEmailPolicies_EveryFileIsTested(t *testing.T) {
	files, err := filepath.Glob("policies/email/*.rego")
	if err != nil {
		t.Fatal(err)
	}
	tested := map[string]bool{"basic.rego": true, "route.rego": true, "failover.rego": true, "verification.rego": true, "rate-limit.rego": true}
	for _, f := range files {
		if base := filepath.Base(f); !strings.HasSuffix(base, "_test.rego") && !tested[base] {
			t.Errorf("%s has no expectations in TestEmailPolicies", f)
		}
	}
}

func TestRateLimitPolicy_DeniesLowTrustSignUpsWhenDegraded(t *testing.T) {
	ctx := context.Background()
	pol, err := policy.Load(ctx, "policies/email/rate-limit.rego", email.PolicyQuery)
	if err != nil {
		t.Fatal(err)
	}
	e := readEvents(t, "events/email.json")[0] // unconfirmed sign-up

	rl := &ratelimit.Result{Class: ratelimit.ClassSignUp, Decision: ratelimit.DecisionSent, LowTrust: true}
	rl.Global.Degraded = true
	if got := emailOutcome(t, pol, email.NewPolicyInput(e, nil, rl), "emma@example.com"); got != "deny" {
		t.Errorf("outcome = %s, want deny", got)
	}

	rl.LowTrust = false
	if got := emailOutcome(t, pol, email.NewPolicyInput(e, nil, rl), "emma@example.com"); got != "send:ses=acme-code" {
		t.Errorf("outcome = %s, want send", got)
	}
}

func TestVerificationPolicy_DisposableAndUnavailable(t *testing.T) {
	ctx := context.Background()
	pol, err := policy.Load(ctx, "policies/email/verification.rego", email.PolicyQuery)
	if err != nil {
		t.Fatal(err)
	}
	e := readEvents(t, "events/email.json")[0] // sign-up

	disposable := &verify.Result{Provider: verify.ProviderSendGrid, Valid: true, Verdict: verify.VerdictRisky, Disposable: true}
	if got := emailOutcome(t, pol, email.NewPolicyInput(e, disposable, nil), "emma@example.com"); got != "deny" {
		t.Errorf("disposable sign-up = %s, want deny", got)
	}
	// verification unavailable: the policy lets the email through
	if got := emailOutcome(t, pol, email.NewPolicyInput(e, nil, nil), "emma@example.com"); got != "send:ses=acme-code" {
		t.Errorf("unverified = %s, want send", got)
	}
}

func TestSMSPolicies(t *testing.T) {
	ctx := context.Background()
	pol, err := policy.Load(ctx, "policies/sms/throttle.rego", sms.PolicyQuery)
	if err != nil {
		t.Fatal(err)
	}

	phone, err := sms.ParsePhoneNumber("+12065550100")
	if err != nil {
		t.Fatal(err)
	}
	e := readEvents(t, "events/sms.json")[0]

	for attempts, want := range map[int]string{1: "allow", 5: "allow", 6: "block"} {
		d, err := policy.Eval[sms.Decision](ctx, pol, sms.NewPolicyInput(e, phone, attempts))
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != want {
			t.Errorf("attempts %d: action = %q, want %q", attempts, d.Action, want)
		}
	}
}

// TestRegoUnitTests runs each *_test.rego file with the policy it tests, as
// "opa test policy.rego policy_test.rego" would.
func TestRegoUnitTests(t *testing.T) {
	tests, err := filepath.Glob("policies/*/*_test.rego")
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) == 0 {
		t.Fatal("no rego tests found")
	}
	for _, testFile := range tests {
		policyFile := strings.TrimSuffix(testFile, "_test.rego") + ".rego"
		t.Run(testFile, func(t *testing.T) {
			results, err := tester.Run(context.Background(), policyFile, testFile)
			if err != nil {
				t.Fatal(err)
			}
			if len(results) == 0 {
				t.Fatal("no rego tests ran")
			}
			for _, r := range results {
				if !r.Pass() {
					t.Errorf("%s: %s", r.Name, r.String())
				}
			}
		})
	}
}
