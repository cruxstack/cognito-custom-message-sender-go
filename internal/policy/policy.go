// Package policy compiles and evaluates the Rego policies that decide
// whether, and how, a message is sent.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// ErrUndefined is returned when the policy defines no result for an input.
var ErrUndefined = errors.New("policy result is undefined")

// Engine is a compiled policy query. It is safe for concurrent use.
type Engine struct {
	query rego.PreparedEvalQuery
}

// Option configures how a policy is compiled.
type Option func(*options)

type options struct {
	allowRegoV0 bool
}

// AllowRegoV0 compiles the policy as Rego v0 when it isn't valid Rego v1.
// It exists for SMS policies written for the earlier Node.js sender.
func AllowRegoV0() Option {
	return func(o *options) { o.allowRegoV0 = true }
}

// Load reads the policy at path and compiles query against it.
func Load(ctx context.Context, path, query string, opts ...Option) (*Engine, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	e, err := Compile(ctx, path, string(src), query, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return e, nil
}

// Compile compiles query against the policy source. name is used in error
// messages.
func Compile(ctx context.Context, name, src, query string, opts ...Option) (*Engine, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	e, err := compile(ctx, name, src, query, ast.RegoV1)
	if err == nil || !o.allowRegoV0 {
		return e, err
	}

	e, errV0 := compile(ctx, name, src, query, ast.RegoV0)
	if errV0 != nil {
		// report the v1 error, since v1 is the recommended syntax
		return nil, err
	}
	slog.WarnContext(ctx, "policy uses rego v0 syntax; rego v1 is recommended", "policy", name)
	return e, nil
}

func compile(ctx context.Context, name, src, query string, v ast.RegoVersion) (*Engine, error) {
	pq, err := rego.New(
		rego.Query(query),
		rego.Module(name, src),
		rego.SetRegoVersion(v),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	return &Engine{query: pq}, nil
}

// Eval evaluates the policy against input and decodes the result into T. It
// returns ErrUndefined when the policy defines no result for the input.
func Eval[T any](ctx context.Context, e *Engine, input any) (T, error) {
	var out T

	rs, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return out, fmt.Errorf("evaluate policy: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return out, ErrUndefined
	}

	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return out, fmt.Errorf("encode policy result: %w", err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("decode policy result: %w", err)
	}
	return out, nil
}

// Action is the decision a policy makes for a message.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// ParseAction validates the action returned by a policy. "block", the action
// used by policies written for the earlier Node.js SMS sender, is accepted as
// an alias for "deny".
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow":
		return ActionAllow, nil
	case "deny", "block":
		return ActionDeny, nil
	case "":
		return "", errors.New(`policy result has no "action"`)
	default:
		return "", fmt.Errorf(`policy result has unknown action %q: must be "allow" or "deny"`, s)
	}
}
