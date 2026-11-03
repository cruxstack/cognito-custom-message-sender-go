package cognito

import (
	"encoding/json"
	"testing"
)

func TestEvent_Decode(t *testing.T) {
	raw := `{
		"version": "1",
		"triggerSource": "CustomEmailSender_SignUp",
		"region": "us-east-1",
		"userPoolId": "us-east-1_EXAMPLE",
		"userName": "user-1",
		"callerContext": {"awsSdkVersion": "aws-sdk-unknown-unknown", "clientId": "client-1"},
		"request": {
			"type": "customEmailSenderRequestV1",
			"code": "ciphertext",
			"clientMetadata": {"k": "v"},
			"userAttributes": {"email": " user@example.com ", "email_verified": "true", "custom:n": 1}
		}
	}`
	var e Event
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatal(err)
	}

	if e.Kind() != KindEmail || e.UserPoolID != "us-east-1_EXAMPLE" || e.CallerContext.ClientID != "client-1" ||
		e.Request.Code != "ciphertext" || e.Request.ClientMetadata["k"] != "v" {
		t.Errorf("decoded event = %+v", e)
	}
	if got := e.Attribute("email"); got != "user@example.com" {
		t.Errorf("Attribute(email) = %q", got)
	}
	if got := e.Attribute("custom:n"); got != "" {
		t.Errorf("Attribute of a non-string = %q, want empty", got)
	}
	if got := e.Attribute("missing"); got != "" {
		t.Errorf("Attribute(missing) = %q, want empty", got)
	}
}

func TestEvent_Kind(t *testing.T) {
	tests := map[string]Kind{
		TriggerEmailSignUp:               "email",
		"CustomSMSSender_Authentication": KindSMS,
		"CustomMessage_SignUp":           KindUnknown,
		"":                               KindUnknown,
	}
	for trigger, want := range tests {
		e := Event{}
		e.TriggerSource = trigger
		if got := e.Kind(); got != want {
			t.Errorf("Kind(%q) = %q, want %q", trigger, got, want)
		}
	}
}
