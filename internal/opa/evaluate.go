package opa

import (
	"context"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/rego"
)

func EvaluatePolicy(ctx context.Context, policyPath string, data any) (map[string]any, error) {
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

	output, ok := results[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("failed to convert result from policy to map: %v", results[0].Expressions[0].Value)
	}

	return output, nil
}
