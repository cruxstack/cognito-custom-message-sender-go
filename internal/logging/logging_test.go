package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/aws/aws-lambda-go/lambdacontext"
)

func TestJSONHandler_AddsContextAttrs(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewJSONHandler(&buf, slog.LevelInfo)).With("app", "test")

	ctx := lambdacontext.NewContext(context.Background(), &lambdacontext.LambdaContext{AwsRequestID: "req-1"})
	ctx = WithAttrs(ctx, slog.String("trigger", "t1"))
	ctx = WithAttrs(ctx, slog.String("client_id", "c1"))
	log.InfoContext(ctx, "with lambda context")
	log.InfoContext(context.Background(), "without lambda context")

	dec := json.NewDecoder(&buf)
	var first, second map[string]any
	if err := dec.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(&second); err != nil {
		t.Fatal(err)
	}
	if first["request_id"] != "req-1" || first["app"] != "test" || first["trigger"] != "t1" || first["client_id"] != "c1" {
		t.Errorf("first record = %v, want request_id, app, and context attrs", first)
	}
	if _, ok := second["request_id"]; ok {
		t.Errorf("second record = %v, want no request_id", second)
	}
	if _, ok := second["trigger"]; ok {
		t.Errorf("second record = %v, want no context attrs", second)
	}
}

func TestMaskEmail(t *testing.T) {
	tests := map[string]string{
		"user@example.com": "u***@example.com",
		"u@example.com":    "u***@example.com",
		"no-at-sign":       "***",
		"@example.com":     "***",
		"":                 "",
	}
	for in, want := range tests {
		if got := MaskEmail(in); got != want {
			t.Errorf("MaskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskPhone(t *testing.T) {
	tests := map[string]string{
		"+12065550100": "+*******0100",
		"2065550100":   "******0100",
		"+1234":        "+***",
		"1234":         "***",
		"":             "",
	}
	for in, want := range tests {
		if got := MaskPhone(in); got != want {
			t.Errorf("MaskPhone(%q) = %q, want %q", in, got, want)
		}
	}
}
