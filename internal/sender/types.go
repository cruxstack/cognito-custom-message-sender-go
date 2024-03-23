package sender

import (
	"github.com/aws/aws-lambda-go/events"
)

type SenderConfig struct {
	KMSKeyID   string
	PolicyPath string
}

type PolicyInput struct {
	Trigger        string                 `json:"trigger"`
	UserAttributes map[string]interface{} `json:"userAttributes"`
	ClientMetadata map[string]string      `json:"clientMetadata"`
}

type PolicyOutput struct {
	Action string    `json:"action"`
	Allow  EmailData `json:"allow"`
}

type EmailData struct {
	DestinationAddress string                 `json:"dstAddress"`
	SourceAddress      string                 `json:"srcAddress"`
	TemplateID         string                 `json:"templateID"`
	TemplateData       map[string]interface{} `json:"templateData"`
}

// structs below used due to bug in aws-lambda-go sdk

type CognitoEventUserPoolsCustomEmailSender struct {
	events.CognitoEventUserPoolsHeader
	Request  CognitoEventUserPoolsCustomEmailSenderRequest  `json:"request"`
	Response CognitoEventUserPoolsCustomEmailSenderResponse `json:"response"`
}

type CognitoEventUserPoolsCustomEmailSenderRequest struct {
	UserAttributes map[string]interface{} `json:"userAttributes"`
	Code           string                 `json:"code"`
	ClientMetadata map[string]string      `json:"clientMetadata"`
	Type           string                 `json:"type"`
}

type CognitoEventUserPoolsCustomEmailSenderResponse struct {
	EmailMessage string `json:"emailMessage"`
	EmailSubject string `json:"emailSubject"`
}
