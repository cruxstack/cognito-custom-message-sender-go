// Package cognito defines the events Amazon Cognito sends to custom email and
// SMS sender Lambda triggers.
//
// Both triggers send the same event shape; only the trigger source differs.
// See https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-sender-triggers.html
package cognito

import (
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

// Trigger source prefixes for the two custom sender triggers.
const (
	EmailTriggerPrefix = "CustomEmailSender_"
	SMSTriggerPrefix   = "CustomSMSSender_"
)

// Trigger sources sent to the custom email sender trigger.
const (
	TriggerEmailSignUp                      = "CustomEmailSender_SignUp"
	TriggerEmailResendCode                  = "CustomEmailSender_ResendCode"
	TriggerEmailForgotPassword              = "CustomEmailSender_ForgotPassword"
	TriggerEmailUpdateUserAttribute         = "CustomEmailSender_UpdateUserAttribute"
	TriggerEmailVerifyUserAttribute         = "CustomEmailSender_VerifyUserAttribute"
	TriggerEmailAdminCreateUser             = "CustomEmailSender_AdminCreateUser"
	TriggerEmailAuthentication              = "CustomEmailSender_Authentication"
	TriggerEmailAccountTakeOverNotification = "CustomEmailSender_AccountTakeOverNotification"
)

// Kind is the sender trigger an event was sent to.
type Kind string

const (
	KindEmail   Kind = "email"
	KindSMS     Kind = "sms"
	KindUnknown Kind = "unknown"
)

// CallerContext identifies the app client that caused the event.
type CallerContext = events.CognitoEventUserPoolsCallerContext

// Event is a custom email or SMS sender event.
type Event struct {
	events.CognitoEventUserPoolsHeader
	Request Request `json:"request"`
}

// Request is the trigger-specific part of an event.
type Request struct {
	Type string `json:"type"`
	// Code is the secret (verification code or temporary password) encrypted
	// with the AWS Encryption SDK. It is empty for events that carry no
	// secret, such as account takeover notifications.
	Code           string            `json:"code"`
	UserAttributes map[string]any    `json:"userAttributes"`
	ClientMetadata map[string]string `json:"clientMetadata"`
}

// Kind reports which sender trigger the event belongs to.
func (e *Event) Kind() Kind {
	switch {
	case strings.HasPrefix(e.TriggerSource, EmailTriggerPrefix):
		return KindEmail
	case strings.HasPrefix(e.TriggerSource, SMSTriggerPrefix):
		return KindSMS
	default:
		return KindUnknown
	}
}

// Attribute returns a user attribute as a trimmed string, or "" when it is
// missing or not a string.
func (e *Event) Attribute(name string) string {
	s, _ := e.Request.UserAttributes[name].(string)
	return strings.TrimSpace(s)
}
