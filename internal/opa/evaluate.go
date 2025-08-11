package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/rego"
)

func EvaluatePolicy[T any](ctx context.Context, policyPath string, data any) (*T, error) {
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	query, err := rego.New(
		rego.Query("data.cognito_custom_sender_email_policy.result"),
		rego.Module("policy.rego", string(policy)),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare policy for evaluation: %w", err)
	}

	results, err := query.Eval(ctx, rego.EvalInput(data))
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no results found during policy evaluation")
	}

	raw := results[0].Expressions[0].Value
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy result: %w", err)
	}

	var output T
	if err := json.Unmarshal(b, &output); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy result: %w", err)
	}

	return &output, nil
}
