package handler

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/cognito"
)

type fakeSender struct {
	events []*cognito.Event
	err    error
}

func (f *fakeSender) Handle(_ context.Context, e *cognito.Event) error {
	f.events = append(f.events, e)
	return f.err
}

func event(trigger string) json.RawMessage {
	return json.RawMessage(`{
		"version": "1",
		"triggerSource": "` + trigger + `",
		"region": "us-east-1",
		"userPoolId": "us-east-1_EXAMPLE",
		"userName": "user-1",
		"callerContext": {"awsSdkVersion": "aws-sdk-unknown-unknown", "clientId": "1example23456789"},
		"request": {
			"type": "customSenderRequestV1",
			"code": "ciphertext",
			"clientMetadata": {"k": "v"},
			"userAttributes": {"email": "user@example.com", "phone_number": "+12065550100"}
		}
	}`)
}

func TestHandle_Routes(t *testing.T) {
	tests := []struct {
		trigger   string
		wantEmail int
		wantSMS   int
	}{
		{"CustomEmailSender_SignUp", 1, 0},
		{"CustomEmailSender_AccountTakeOverNotification", 1, 0},
		{"CustomSMSSender_Authentication", 0, 1},
		{"CustomSMSSender_AdminCreateUser", 0, 1},
		{"CustomMessage_SignUp", 0, 0},
	}

	for _, tc := range tests {
		t.Run(tc.trigger, func(t *testing.T) {
			email, sms := &fakeSender{}, &fakeSender{}
			h := &Handler{Email: email, SMS: sms}
			if err := h.Handle(context.Background(), event(tc.trigger)); err != nil {
				t.Fatal(err)
			}
			if len(email.events) != tc.wantEmail || len(sms.events) != tc.wantSMS {
				t.Errorf("email=%d sms=%d, want email=%d sms=%d", len(email.events), len(sms.events), tc.wantEmail, tc.wantSMS)
			}
		})
	}
}

func TestHandle_DecodesEvent(t *testing.T) {
	email := &fakeSender{}
	if err := (&Handler{Email: email}).Handle(context.Background(), event("CustomEmailSender_SignUp")); err != nil {
		t.Fatal(err)
	}
	e := email.events[0]
	if e.UserPoolID != "us-east-1_EXAMPLE" || e.Request.Code != "ciphertext" || e.Attribute("email") != "user@example.com" {
		t.Errorf("event = %+v", e)
	}
}

func TestHandle_DisabledSenderIgnoresEvent(t *testing.T) {
	h := &Handler{}
	for _, trigger := range []string{"CustomEmailSender_SignUp", "CustomSMSSender_SignUp"} {
		if err := h.Handle(context.Background(), event(trigger)); err != nil {
			t.Errorf("%s: Handle() = %v, want the event ignored", trigger, err)
		}
	}
}

func TestHandle_Errors(t *testing.T) {
	sendErr := errors.New("send failed")
	h := &Handler{Email: &fakeSender{err: sendErr}}

	if err := h.Handle(context.Background(), event("CustomEmailSender_SignUp")); !errors.Is(err, sendErr) {
		t.Errorf("Handle() = %v, want the sender error", err)
	}
	if err := h.Handle(context.Background(), json.RawMessage(`not json`)); err == nil {
		t.Error("Handle() should reject an invalid event")
	}
}
