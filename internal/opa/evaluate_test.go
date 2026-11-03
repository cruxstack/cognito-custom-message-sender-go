package opa

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

type testPolicyOutput struct {
	IsAdmin bool `json:"isAdmin"`
}

const testPolicy = `
package mock_policy

result := {"isAdmin": input.user == "admin"}
`

func TestEvaluate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.rego")
	if err := os.WriteFile(path, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	policy, err := ReadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}

	pp, err := PreparePolicy(context.Background(), policy, "data.mock_policy.result")
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name     string
		input    map[string]any
		expected bool
	}{
		{"allow admin user", map[string]any{"user": "admin"}, true},
		{"deny non-admin user", map[string]any{"user": "guest"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Evaluate[testPolicyOutput](context.Background(), pp, tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if result.IsAdmin != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result.IsAdmin)
			}
		})
	}
}

func TestEvaluate_UndefinedResult(t *testing.T) {
	pp, err := PreparePolicy(context.Background(), testPolicy, "data.mock_policy.missing")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Evaluate[testPolicyOutput](context.Background(), pp, nil); err == nil {
		t.Error("expected error for undefined result")
	}
}
