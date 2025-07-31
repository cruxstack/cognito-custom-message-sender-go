package aws

import (
	"github.com/aws/aws-lambda-go/events"
)

// structs below used due to bug in aws-lambda-go sdk

type CognitoEventUserPoolsCustomEmailSender struct {
	events.CognitoEventUserPoolsHeader
	Request  CognitoEventUserPoolsCustomEmailSenderRequest  `json:"request"`
	Response CognitoEventUserPoolsCustomEmailSenderResponse `json:"response"`
}

type CognitoEventUserPoolsCustomEmailSenderRequest struct {
	UserAttributes map[string]any    `json:"userAttributes"`
	Code           string            `json:"code"`
	ClientMetadata map[string]string `json:"clientMetadata"`
	Type           string            `json:"type"`
}

type CognitoEventUserPoolsCustomEmailSenderResponse struct {
	EmailMessage string `json:"emailMessage"`
	EmailSubject string `json:"emailSubject"`
}
