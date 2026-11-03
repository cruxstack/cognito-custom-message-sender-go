package e2e

import (
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
