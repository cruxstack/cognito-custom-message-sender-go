package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const query = "data.example.result"

func TestEval(t *testing.T) {
	e, err := Compile(context.Background(), "p.rego", `package example
import rego.v1
result := {"greeting": sprintf("hello %s", [input.name])} if input.name
`, query)
	if err != nil {
		t.Fatal(err)
	}

	type out struct {
		Greeting string `json:"greeting"`
	}
	got, err := Eval[out](context.Background(), e, map[string]any{"name": "eli"})
	if err != nil || got.Greeting != "hello eli" {
		t.Errorf("Eval() = %+v, %v", got, err)
	}

	if _, err := Eval[out](context.Background(), e, map[string]any{}); !errors.Is(err, ErrUndefined) {
		t.Errorf("Eval() with no result: error = %v, want ErrUndefined", err)
	}
}

func TestEval_DecodeError(t *testing.T) {
	e, err := Compile(context.Background(), "p.rego", "package example\nresult := \"not an object\"", query)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Eval[struct{ A int }](context.Background(), e, nil); err == nil || errors.Is(err, ErrUndefined) {
		t.Errorf("Eval() error = %v, want a decode error", err)
	}
}

func TestCompile_RegoVersions(t *testing.T) {
	v0 := "package example\nresult = 1 { true }"
	v1 := "package example\nresult := 1 if true"
	ctx := context.Background()

	if _, err := Compile(ctx, "p.rego", v0, query); err == nil {
		t.Error("v0 policy should not compile without AllowRegoV0")
	}
	if _, err := Compile(ctx, "p.rego", v0, query, AllowRegoV0()); err != nil {
		t.Errorf("v0 policy with AllowRegoV0: %v", err)
	}
	if _, err := Compile(ctx, "p.rego", v1, query, AllowRegoV0()); err != nil {
		t.Errorf("v1 policy with AllowRegoV0: %v", err)
	}
	if _, err := Compile(ctx, "p.rego", "package example\nresult := {", query, AllowRegoV0()); err == nil {
		t.Error("invalid policy should not compile")
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.rego")
	if err := os.WriteFile(path, []byte("package example\nresult := 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), path, query); err != nil {
		t.Errorf("Load() = %v", err)
	}

	_, err := Load(context.Background(), filepath.Join(t.TempDir(), "missing.rego"), query)
	if err == nil {
		t.Error("Load() of a missing file should fail")
	}

	bad := filepath.Join(t.TempDir(), "bad.rego")
	if err := os.WriteFile(bad, []byte("package example\nresult := {"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), bad, query); err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("Load() error = %v, want it to name the file", err)
	}
}

func TestParseAction(t *testing.T) {
	tests := map[string]Action{
		"allow":  ActionAllow,
		"ALLOW ": ActionAllow, //nolint:gocritic // checks trimming and case folding
		"deny":   ActionDeny,
		"block":  ActionDeny,
	}
	for in, want := range tests {
		if got, err := ParseAction(in); err != nil || got != want {
			t.Errorf("ParseAction(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "alow", "send"} {
		if _, err := ParseAction(in); err == nil {
			t.Errorf("ParseAction(%q) should fail", in)
		}
	}
}
