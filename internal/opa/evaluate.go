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

// PreparedPolicy holds a compiled policy ready for evaluation
type PreparedPolicy struct {
	query rego.PreparedEvalQuery
}

// PreparePolicy compiles a policy and query for later evaluation.
// This should be called once at initialization and the result cached.
func PreparePolicy(ctx context.Context, policy string, query string) (*PreparedPolicy, error) {
	r := rego.New(
		rego.Query(query),
		rego.Module("policy.rego", policy),
		rego.SetRegoVersion(ast.RegoV1),
	)

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare policy: %w", err)
	}

	return &PreparedPolicy{query: pq}, nil
}

// Evaluate runs the prepared policy against the given input and returns the result as type T
func Evaluate[T any](ctx context.Context, pp *PreparedPolicy, input any) (*T, error) {
	rs, err := pp.query.Eval(ctx, rego.EvalInput(input))
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

// EvaluatePolicy compiles policy and evaluates a query against input
// - returns *T where T matches the rego result shape
// - enforces rego v1 semantics during compilation
// Deprecated: Use PreparePolicy + Evaluate for better performance
func EvaluatePolicy[T any](ctx context.Context, policy string, query string, input any) (*T, error) {
	pp, err := PreparePolicy(ctx, policy, query)
	if err != nil {
		return nil, err
	}

	return Evaluate[T](ctx, pp, input)
}

func ReadPolicy(path string) (string, error) {
	p, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read policy file: %w", err)
	}

	return string(p), nil
}
