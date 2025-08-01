package sender

import "github.com/cruxstack/cognito-custom-message-sender-go/internal/verifier"

type PolicyInput struct {
	Trigger           string                            `json:"trigger"`
	UserAttributes    map[string]any                    `json:"userAttributes"`
	ClientMetadata    map[string]string                 `json:"clientMetadata"`
	EmailVerification *verifier.EmailVerificationResult `json:"emailVerification,omitempty"`
}

type PolicyOutput struct {
	Action string    `json:"action"`
	Allow  EmailData `json:"allow"`
}

type EmailData struct {
	DestinationAddress string         `json:"dstAddress"`
	SourceAddress      string         `json:"srcAddress"`
	TemplateID         string         `json:"templateID"`
	TemplateData       map[string]any `json:"templateData"`
}
