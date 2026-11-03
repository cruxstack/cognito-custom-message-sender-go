package e2e

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/cognito"
)

func TestEmail_SendsWithSESTemplate(t *testing.T) {
	e := newEnv(t, nil)

	e.mustHandle(emailEvent(cognito.TriggerEmailForgotPassword, "mobile-app-client-id", "eli@example.com", "123456"))

	got := e.ses.emails()
	want := sesEmail{
		From:     "ACME Mobile <no-reply@m.example.com>",
		To:       "eli@example.com",
		Template: "acme-reset-password",
		Data:     map[string]any{"appName": "ACME Mobile", "locale": "en", "code": "123456"},
	}
	if len(got) != 1 || fmt.Sprint(got[0]) != fmt.Sprint(want) {
		t.Errorf("ses emails = %+v\nwant         %+v", got, want)
	}
}

func TestEmail_AllTriggers(t *testing.T) {
	e := newEnv(t, nil)
	triggers := []string{
		cognito.TriggerEmailSignUp,
		cognito.TriggerEmailResendCode,
		cognito.TriggerEmailForgotPassword,
		cognito.TriggerEmailUpdateUserAttribute,
		cognito.TriggerEmailVerifyUserAttribute,
		cognito.TriggerEmailAdminCreateUser,
		cognito.TriggerEmailAuthentication,
		cognito.TriggerEmailAccountTakeOverNotification,
	}
	for _, trigger := range triggers {
		e.mustHandle(emailEvent(trigger, "web-app-client-id", "user@example.com", "111111"))
	}
	if got := len(e.ses.emails()); got != len(triggers) {
		t.Errorf("sent %d emails, want %d", got, len(triggers))
	}
}

func TestEmail_TemporaryPasswordIsUnescaped(t *testing.T) {
	e := newEnv(t, nil)
	e.mustHandle(emailEvent(cognito.TriggerEmailAdminCreateUser, "CLIENT_ID_NOT_APPLICABLE", "ella@example.com", "Temp&lt;Pass&gt;1"))

	if got := e.ses.emails()[0].Data["code"]; got != "Temp<Pass>1" {
		t.Errorf("code = %q, want the unescaped password", got)
	}
}

func TestEmail_NoCode(t *testing.T) {
	e := newEnv(t, nil)
	e.mustHandle(emailEvent(cognito.TriggerEmailAccountTakeOverNotification, "web-app-client-id", "eli@example.com", ""))

	if got := e.ses.emails()[0]; got.Template != "acme-security-alert" || got.Data["code"] != "" {
		t.Errorf("email = %+v", got)
	}
}

func TestEmail_DryRun(t *testing.T) {
	e := newEnv(t, map[string]string{"APP_SEND_ENABLED": "false", "APP_EMAIL_PROVIDERS": "ses,sendgrid"})
	e.mustHandle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "user@example.com", "1"))

	if len(e.ses.emails()) != 0 || len(e.sendgrid.templates()) != 0 {
		t.Error("a dry run should not send")
	}
}

func TestEmail_SendGridWithConfiguredHost(t *testing.T) {
	e := newEnv(t, map[string]string{
		"APP_EMAIL_PROVIDERS":          "sendgrid",
		"APP_EMAIL_SENDER_POLICY_PATH": policies + "email/failover.rego",
	})
	e.mustHandle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "user@example.com", "1"))

	if got := e.sendgrid.templates(); !slices.Equal(got, []string{"d-0123456789abcdef0123456789abcdef"}) || len(e.ses.emails()) != 0 {
		t.Errorf("sendgrid templates = %v, ses emails = %d", got, len(e.ses.emails()))
	}
}

func TestEmail_Failover(t *testing.T) {
	vars := map[string]string{
		"APP_EMAIL_PROVIDERS":          "ses,sendgrid",
		"APP_EMAIL_SENDER_POLICY_PATH": policies + "email/failover.rego",
	}

	t.Run("ses error", func(t *testing.T) {
		e := newEnv(t, vars)
		e.ses.sendErr = errors.New("throttling")
		e.mustHandle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "user@example.com", "1"))
		if len(e.sendgrid.templates()) != 1 {
			t.Error("email should fail over to sendgrid")
		}
	})

	t.Run("ses sending paused", func(t *testing.T) {
		e := newEnv(t, vars)
		e.ses.sendingEnabled = false
		e.mustHandle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "user@example.com", "1"))
		if len(e.sendgrid.templates()) != 1 || len(e.ses.emails()) != 0 {
			t.Error("email should go to sendgrid first while ses is paused")
		}
	})

	t.Run("policy without a template for the second provider", func(t *testing.T) {
		e := newEnv(t, map[string]string{"APP_EMAIL_PROVIDERS": "ses,sendgrid"}) // route.rego is ses only
		e.ses.sendErr = errors.New("throttling")
		if err := e.handle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "user@example.com", "1")); err == nil {
			t.Error("Handle() should fail when no provider can send")
		}
	})

	t.Run("all providers fail", func(t *testing.T) {
		e := newEnv(t, vars)
		e.ses.sendErr = errors.New("throttling")
		e.sendgrid.sendCode = 500
		// the error makes lambda retry the event, then send it to the
		// function's failure destination
		if err := e.handle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "user@example.com", "1")); err == nil {
			t.Error("Handle() should return an error when every provider fails")
		}
	})
}

func TestEmail_Verification(t *testing.T) {
	vars := map[string]string{
		"APP_EMAIL_SENDER_POLICY_PATH":     policies + "email/verification.rego",
		"APP_EMAIL_VERIFICATION_ENABLED":   "true",
		"APP_EMAIL_VERIFICATION_PROVIDER":  "sendgrid",
		"APP_EMAIL_VERIFICATION_ALLOWLIST": "trusted.example",
	}

	t.Run("invalid address is denied", func(t *testing.T) {
		e := newEnv(t, vars)
		e.sendgrid.verdicts["bounce@example.com"] = "Invalid"
		e.mustHandle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "bounce@example.com", "1"))
		if len(e.ses.emails()) != 0 || e.sendgrid.validationCount() != 1 {
			t.Errorf("sent %d emails after %d validations, want 0 after 1", len(e.ses.emails()), e.sendgrid.validationCount())
		}
	})

	t.Run("valid address is sent", func(t *testing.T) {
		e := newEnv(t, vars)
		e.mustHandle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "user@example.com", "1"))
		if len(e.ses.emails()) != 1 {
			t.Error("valid address should be sent")
		}
	})

	t.Run("allowlisted domain skips the api", func(t *testing.T) {
		e := newEnv(t, vars)
		e.mustHandle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "user@Trusted.Example", "1"))
		if len(e.ses.emails()) != 1 || e.sendgrid.validationCount() != 0 {
			t.Errorf("sent %d emails after %d validations, want 1 after 0", len(e.ses.emails()), e.sendgrid.validationCount())
		}
	})

	t.Run("offline verification", func(t *testing.T) {
		e := newEnv(t, map[string]string{
			"APP_EMAIL_SENDER_POLICY_PATH":   policies + "email/verification.rego",
			"APP_EMAIL_VERIFICATION_ENABLED": "true",
		})
		e.mustHandle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "typo@localhost", "1"))
		e.mustHandle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "user@example.com", "1"))
		if got := len(e.ses.emails()); got != 1 {
			t.Errorf("sent %d emails, want only the valid address", got)
		}
	})
}

func TestEmail_RateLimit(t *testing.T) {
	vars := map[string]string{
		"APP_EMAIL_RATE_LIMIT_ENABLED":    "true",
		"APP_EMAIL_RATE_LIMIT_TABLE_NAME": "rate-limits",
		"APP_EMAIL_RATE_LIMIT_CONFIG":     `{"classes": {"signup": {"destination": [{"window": "1h", "max": 2}]}, "authentication": {"destination": [{"window": "15m", "max": 2}]}}}`,
	}

	t.Run("aliases of one mailbox share a limit", func(t *testing.T) {
		e := newEnv(t, vars)
		for i, addr := range []string{"user@example.com", "User+a@example.com", "user+b@Example.com"} {
			// a throttled email is dropped without an error, so lambda doesn't retry
			e.mustHandle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", addr, fmt.Sprintf("code-%d", i)))
		}
		e.mustHandle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "other@example.com", "code-x"))

		if got := len(e.ses.emails()); got != 3 {
			t.Errorf("sent %d emails, want 2 to the first mailbox and 1 to the other", got)
		}
	})

	t.Run("a retry is counted once", func(t *testing.T) {
		e := newEnv(t, vars)
		first := emailEvent(cognito.TriggerEmailAuthentication, "web-app-client-id", "user@example.com", "code-1")

		e.ses.sendErr = errors.New("unavailable")
		if err := e.handle(first); err == nil {
			t.Fatal("Handle() should return the delivery error so lambda retries")
		}
		e.ses.sendErr = nil
		e.mustHandle(first) // the retry
		e.mustHandle(emailEvent(cognito.TriggerEmailAuthentication, "web-app-client-id", "user@example.com", "code-2"))
		e.mustHandle(emailEvent(cognito.TriggerEmailAuthentication, "web-app-client-id", "user@example.com", "code-3"))

		var codes []any
		for _, m := range e.ses.emails() {
			codes = append(codes, m.Data["code"])
		}
		if fmt.Sprint(codes) != "[code-1 code-2]" {
			t.Errorf("sent codes %v, want the retry and one new code", codes)
		}
	})

	t.Run("admin-created users are exempt", func(t *testing.T) {
		e := newEnv(t, vars)
		for i := range 5 {
			e.mustHandle(emailEvent(cognito.TriggerEmailAdminCreateUser, "CLIENT_ID_NOT_APPLICABLE", "user@example.com", fmt.Sprintf("pw-%d", i)))
		}
		if got := len(e.ses.emails()); got != 5 {
			t.Errorf("sent %d emails, want 5", got)
		}
	})
}

func TestEmail_PolicyErrorsAreReturned(t *testing.T) {
	e := newEnv(t, map[string]string{"APP_EMAIL_SENDER_POLICY_PATH": "testdata/invalid-decision.rego"})
	if err := e.handle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "user@example.com", "1")); err == nil {
		t.Error("Handle() should return the policy error")
	}
}
