package email

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/cognito"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/mailer"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/policy"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/ratelimit"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/verify"
)

// PolicyInput is the policy's input document.
type PolicyInput struct {
	Trigger        string                `json:"trigger"`
	UserPoolID     string                `json:"userPoolId"`
	Region         string                `json:"region"`
	UserName       string                `json:"userName"`
	CallerContext  cognito.CallerContext `json:"callerContext"`
	UserAttributes map[string]any        `json:"userAttributes"`
	ClientMetadata map[string]string     `json:"clientMetadata"`
	// EmailVerification is set when verification is enabled and the
	// address could be checked.
	EmailVerification *verify.Result `json:"emailVerification,omitempty"`
	// RateLimit is set when rate limiting is enabled. Throttled emails never
	// reach the policy, but the policy can deny on these values.
	RateLimit *ratelimit.Result `json:"rateLimit,omitempty"`
}

// NewPolicyInput builds the policy input for an event.
func NewPolicyInput(e *cognito.Event, v *verify.Result, rl *ratelimit.Result) PolicyInput {
	return PolicyInput{
		Trigger:           e.TriggerSource,
		UserPoolID:        e.UserPoolID,
		Region:            e.Region,
		UserName:          e.UserName,
		CallerContext:     e.CallerContext,
		UserAttributes:    nonNil(e.Request.UserAttributes),
		ClientMetadata:    nonNil(e.Request.ClientMetadata),
		EmailVerification: v,
		RateLimit:         rl,
	}
}

// Decision is the policy's result document.
type Decision struct {
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
	Allow  *Allow `json:"allow,omitempty"`
}

// Allow describes the email to send.
type Allow struct {
	SrcAddress string `json:"srcAddress"`
	// DstAddress defaults to the user's email attribute.
	DstAddress string                     `json:"dstAddress,omitempty"`
	Providers  map[string]mailer.Template `json:"providers"`

	// LegacyTemplateID is the v1 top-level template, removed in v3. It is
	// decoded only to report a helpful error.
	LegacyTemplateID string `json:"templateID,omitempty"`
}

// Message validates the decision and returns the email to send, or nil when
// the policy denied the email. defaultTo is used when the policy sets no
// destination.
func (d *Decision) Message(defaultTo string) (*mailer.Message, error) {
	action, err := policy.ParseAction(d.Action)
	if err != nil {
		return nil, err
	}
	if action == policy.ActionDeny {
		return nil, nil
	}

	a := d.Allow
	switch {
	case a == nil:
		return nil, errors.New(`"allow" is required when action is "allow"`)
	case a.LegacyTemplateID != "" && len(a.Providers) == 0:
		return nil, errors.New(`"allow.templateID" is no longer supported; use "allow.providers.ses.templateId"`)
	case a.SrcAddress == "":
		return nil, errors.New(`"allow.srcAddress" is required`)
	case len(a.Providers) == 0:
		return nil, errors.New(`"allow.providers" must define a template for at least one provider`)
	}

	to := cmp.Or(a.DstAddress, defaultTo)
	if to == "" {
		return nil, errors.New(`"allow.dstAddress" is required when the user has no email attribute`)
	}

	for name, t := range a.Providers {
		if !slices.Contains(mailer.Providers, name) {
			return nil, fmt.Errorf(`"allow.providers.%s" is not a known provider: must be one of %v`, name, mailer.Providers)
		}
		if t.ID == "" {
			return nil, fmt.Errorf(`"allow.providers.%s.templateId" is required`, name)
		}
	}

	return &mailer.Message{From: a.SrcAddress, To: to, Templates: a.Providers}, nil
}

// nonNil returns m, or an empty map when m is nil, so the policy sees {}
// instead of null.
func nonNil[M ~map[K]V, K comparable, V any](m M) M {
	if m == nil {
		return M{}
	}
	return m
}
