package sender

import (
	"github.com/aws/aws-lambda-go/events"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/ratelimit"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/verifier"
)

type PolicyInput struct {
	Trigger           string                                    `json:"trigger"`
	CallerContext     events.CognitoEventUserPoolsCallerContext `json:"callerContext"`
	UserAttributes    map[string]any                            `json:"userAttributes"`
	ClientMetadata    map[string]string                         `json:"clientMetadata"`
	EmailVerification *verifier.EmailVerificationResult         `json:"emailVerification,omitempty"`
	// RateLimit is set only when rate limiting is enabled. Throttled emails
	// never reach the policy, but the policy can deny on these values.
	RateLimit *ratelimit.Result `json:"rateLimit,omitempty"`
}

type PolicyOutput struct {
	Action string          `json:"action"`
	Reason string          `json:"reason,omitempty"`
	Allow  types.EmailData `json:"allow,omitempty"`
}
