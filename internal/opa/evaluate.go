// package opa provides helpers to evaluate rego policies with the v1 sdk
package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// EvaluatePolicy compiles policy and evaluates a query against input
// - returns *T where T matches the rego result shape
// - enforces rego v1 semantics during compilation
func EvaluatePolicy[T any](ctx context.Context, policy *string, query *string, input any) (*T, error) {
	r := rego.New(
		rego.Query(*query),
		rego.Module("policy.rego", *policy),
		rego.SetRegoVersion(ast.RegoV1),
	)

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare policy: %w", err)
	}

	rs, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("no results found during policy evaluation")
	}

	raw := rs[0].Expressions[0].Value
	bs, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy result: %w", err)
	}

	var out T
	if err := json.Unmarshal(bs, &out); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy result: %w", err)
	}

	return &out, nil
}

func ReadPolicy(path string) (*string, error) {
	p, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	policy := string(p)
	return &policy, nil
}
