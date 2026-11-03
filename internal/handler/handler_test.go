package handler

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
)

type fakeEmail struct {
	events []types.CognitoEventUserPoolsCustomEmailSender
	err    error
}

func (f *fakeEmail) SendEmail(_ context.Context, e types.CognitoEventUserPoolsCustomEmailSender) error {
	f.events = append(f.events, e)
	return f.err
}

type fakeSMS struct {
	events []types.CognitoEventUserPoolsCustomSMSSender
	err    error
}

func (f *fakeSMS) SendSMS(_ context.Context, e types.CognitoEventUserPoolsCustomSMSSender) error {
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

func TestHandle_Dispatch(t *testing.T) {
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
		{"", 0, 0},
	}

	for _, tc := range tests {
		t.Run(tc.trigger, func(t *testing.T) {
			email, sms := &fakeEmail{}, &fakeSMS{}
			h := &Handler{Email: email, SMS: sms}

			if err := h.Handle(context.Background(), event(tc.trigger)); err != nil {
				t.Fatalf("Handle() error = %v", err)
			}
			if len(email.events) != tc.wantEmail || len(sms.events) != tc.wantSMS {
				t.Errorf("email = %d, sms = %d; want %d, %d", len(email.events), len(sms.events), tc.wantEmail, tc.wantSMS)
			}
		})
	}
}

func TestHandle_DecodesEvents(t *testing.T) {
	email, sms := &fakeEmail{}, &fakeSMS{}
	h := &Handler{Email: email, SMS: sms}
	ctx := context.Background()

	if err := h.Handle(ctx, event("CustomEmailSender_SignUp")); err != nil {
		t.Fatal(err)
	}
	if err := h.Handle(ctx, event("CustomSMSSender_SignUp")); err != nil {
		t.Fatal(err)
	}

	e := email.events[0]
	if e.UserName != "user-1" || e.CallerContext.ClientID != "1example23456789" || e.Request.Code != "ciphertext" || e.Request.UserAttributes["email"] != "user@example.com" {
		t.Errorf("email event = %+v", e)
	}
	s := sms.events[0]
	if s.TriggerSource != "CustomSMSSender_SignUp" || s.Request.Code != "ciphertext" || s.Request.ClientMetadata["k"] != "v" || s.Request.UserAttributes["phone_number"] != "+12065550100" {
		t.Errorf("sms event = %+v", s)
	}
}

func TestHandle_DisabledSenderIgnoresEvent(t *testing.T) {
	h := &Handler{}
	for _, trigger := range []string{"CustomEmailSender_SignUp", "CustomSMSSender_SignUp"} {
		if err := h.Handle(context.Background(), event(trigger)); err != nil {
			t.Errorf("Handle(%s) error = %v, want ignored", trigger, err)
		}
	}
}

func TestHandle_Errors(t *testing.T) {
	sendErr := errors.New("provider unavailable")
	h := &Handler{Email: &fakeEmail{err: sendErr}, SMS: &fakeSMS{err: sendErr}}

	for _, trigger := range []string{"CustomEmailSender_SignUp", "CustomSMSSender_SignUp"} {
		if err := h.Handle(context.Background(), event(trigger)); !errors.Is(err, sendErr) {
			t.Errorf("Handle(%s) error = %v, want the send error for a retry", trigger, err)
		}
	}

	if err := h.Handle(context.Background(), json.RawMessage(`not json`)); err == nil {
		t.Error("Handle() should fail on invalid json")
	}
	if err := h.Handle(context.Background(), json.RawMessage(`{"triggerSource": "CustomSMSSender_SignUp", "request": []}`)); err == nil {
		t.Error("Handle() should fail on a malformed sms event")
	}
}

func TestHandle_LambdaInvoke(t *testing.T) {
	sms := &fakeSMS{}
	h := &Handler{SMS: sms}

	// the same wrapper lambda.Start uses for a json.RawMessage handler
	out, err := lambda.NewHandler(h.Handle).Invoke(context.Background(), event("CustomSMSSender_ResendCode"))
	if err != nil {
		t.Fatalf("Invoke() error = %v", err)
	}
	if string(out) != "null" || len(sms.events) != 1 || sms.events[0].TriggerSource != "CustomSMSSender_ResendCode" {
		t.Errorf("Invoke() = %s, events = %+v", out, sms.events)
	}
}
