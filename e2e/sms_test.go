package e2e

import (
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/cognito"
)

func smsVars() map[string]string {
	return map[string]string{
		"APP_SMS_SENDER_ENABLED":     "true",
		"APP_SMS_SENDER_POLICY_PATH": policies + "sms/throttle.rego",
		"APP_SMS_HISTORY_TABLE_NAME": "history",
	}
}

func TestSMS_OneFunctionServesEmailAndSMS(t *testing.T) {
	e := newEnv(t, smsVars())

	e.mustHandle(emailEvent(cognito.TriggerEmailSignUp, "web-app-client-id", "user@example.com", "111111"))
	e.mustHandle(smsEvent("CustomSMSSender_SignUp", "+12065550100", "222222"))

	if len(e.ses.emails()) != 1 {
		t.Errorf("sent %d emails, want 1", len(e.ses.emails()))
	}
	if got := e.sns.messages(); !slices.Equal(got, []string{"Your code is: 222222"}) {
		t.Errorf("sms = %v", got)
	}
}

func TestSMS_ThrottlesByHistory(t *testing.T) {
	e := newEnv(t, smsVars())
	for range 7 {
		e.mustHandle(smsEvent("CustomSMSSender_Authentication", "+12065550100", "123456"))
	}
	if got := len(e.sns.messages()); got != 5 {
		t.Errorf("sent %d sms, want 5 before the policy blocks", got)
	}
	if got := len(e.history.Records()); got != 7 {
		t.Errorf("recorded %d attempts, want 7", got)
	}
}

func TestSMS_InvalidPhoneNumberIsDropped(t *testing.T) {
	e := newEnv(t, smsVars())
	e.mustHandle(smsEvent("CustomSMSSender_SignUp", "not-a-phone-number", "1"))
	if len(e.sns.messages()) != 0 {
		t.Error("invalid phone numbers should not be sent")
	}
}

func TestSMS_DisabledSenderIgnoresEvents(t *testing.T) {
	e := newEnv(t, nil)
	e.mustHandle(smsEvent("CustomSMSSender_SignUp", "+12065550100", "1"))
	if len(e.sns.messages()) != 0 {
		t.Error("sms should not be sent when the sms sender is disabled")
	}
}

func TestUnknownTriggerIsIgnored(t *testing.T) {
	e := newEnv(t, nil)
	e.mustHandle(emailEvent("CustomMessage_SignUp", "web-app-client-id", "user@example.com", "1"))
	if len(e.ses.emails()) != 0 {
		t.Error("unknown triggers should be ignored")
	}
}

func TestSMS_RateLimit(t *testing.T) {
	vars := smsVars()
	maps.Copy(vars, map[string]string{
		"APP_SMS_RATE_LIMIT_ENABLED":    "true",
		"APP_SMS_RATE_LIMIT_TABLE_NAME": "rate-limits",
		"APP_SMS_RATE_LIMIT_CONFIG":     `{"classes": {"authentication": {"destination": [{"window": "15m", "max": 2}]}}}`,
	})

	t.Run("throttles a number", func(t *testing.T) {
		e := newEnv(t, vars)
		// formatting differences don't evade the limit: the number is counted in E.164
		for i, phone := range []string{"+12065550100", "+1 (206) 555-0100", "+1 206 555 0100"} {
			e.mustHandle(smsEvent("CustomSMSSender_Authentication", phone, fmt.Sprintf("code-%d", i)))
		}
		e.mustHandle(smsEvent("CustomSMSSender_Authentication", "+12065550199", "code-x"))

		if got := len(e.sns.messages()); got != 3 {
			t.Errorf("sent %d sms, want 2 to the first number and 1 to the other", got)
		}
		// throttled sms reach neither the policy nor the history
		if got := len(e.history.Records()); got != 3 {
			t.Errorf("recorded %d attempts, want 3", got)
		}
	})

	t.Run("works without the history table", func(t *testing.T) {
		v := maps.Clone(vars)
		delete(v, "APP_SMS_HISTORY_TABLE_NAME")
		e := newEnv(t, v)
		for i := range 3 {
			e.mustHandle(smsEvent("CustomSMSSender_Authentication", "+12065550100", fmt.Sprintf("code-%d", i)))
		}
		if got := len(e.sns.messages()); got != 2 {
			t.Errorf("sent %d sms, want 2", got)
		}
		if len(e.history.Records()) != 0 {
			t.Error("history should be off without a table name")
		}
	})

	t.Run("email and sms limits are separate", func(t *testing.T) {
		v := maps.Clone(vars)
		maps.Copy(v, map[string]string{
			"APP_EMAIL_RATE_LIMIT_ENABLED":    "true",
			"APP_EMAIL_RATE_LIMIT_TABLE_NAME": "rate-limits",
			"APP_EMAIL_RATE_LIMIT_CONFIG":     `{"classes": {"authentication": {"destination": [{"window": "15m", "max": 2}]}}}`,
		})
		e := newEnv(t, v)
		for i := range 2 {
			e.mustHandle(emailEvent(cognito.TriggerEmailAuthentication, "web-app-client-id", "user@example.com", fmt.Sprintf("e-%d", i)))
			e.mustHandle(smsEvent("CustomSMSSender_Authentication", "+12065550100", fmt.Sprintf("s-%d", i)))
		}
		if len(e.ses.emails()) != 2 || len(e.sns.messages()) != 2 {
			t.Errorf("sent %d emails and %d sms, want 2 of each", len(e.ses.emails()), len(e.sns.messages()))
		}
	})
}
