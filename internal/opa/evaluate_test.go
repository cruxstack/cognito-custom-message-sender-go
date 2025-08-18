package opa

import (
	"context"
	"os"
	"testing"
)

type TestPolicyOutput struct {
	IsAdmin bool `json:"isAdmin,omitempty"`
}

func TestEvaluatePolicy(t *testing.T) {
	policyFile, err := os.CreateTemp("", "test-policy-*.rego")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		policyFile.Close()
		os.Remove(policyFile.Name())
	}()

	policy := `
		package mock_policy
		result := {
			"isAdmin": input.user == "admin"
		}
    `
	_, err = policyFile.WriteString(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyFile.Close()

	testCases := []struct {
		name     string
		data     map[string]any
		expected bool
	}{
		{
			name:     "allow admin user",
			data:     map[string]any{"user": "admin"},
			expected: true,
		},
		{
			name:     "deny non-admin user",
			data:     map[string]any{"user": "guest"},
			expected: false,
		},
	}

	ctx := context.Background()

	q := "data.mock_policy.result"
	p, err := ReadPolicy(policyFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := EvaluatePolicy[TestPolicyOutput](ctx, p, &q, tc.data)
			if err != nil {
				t.Fatal(err)
			}
			if result.IsAdmin != tc.expected {
				t.Errorf("Test case %s failed: expected %v but got %v", tc.name, tc.expected, result)
			}
		})
	}
}
