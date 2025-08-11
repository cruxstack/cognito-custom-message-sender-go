package sender

import (
	"github.com/aws/aws-lambda-go/events"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/verifier"
)

type PolicyInput struct {
	Trigger           string                                    `json:"trigger"`
	CallerContext     events.CognitoEventUserPoolsCallerContext `json:"callerContext"`
	UserAttributes    map[string]any                            `json:"userAttributes"`
	ClientMetadata    map[string]string                         `json:"clientMetadata"`
	EmailVerification *verifier.EmailVerificationResult         `json:"emailVerification,omitempty"`
}

type PolicyOutput struct {
	Action string    `json:"action"`
	Reason string    `json:"reason,omitempty"`
	Allow  EmailData `json:"allow,omitempty"`
}

type EmailData struct {
	DestinationAddress string         `json:"dstAddress"`
	SourceAddress      string         `json:"srcAddress"`
	TemplateID         string         `json:"templateID"`
	TemplateData       map[string]any `json:"templateData"`
}
