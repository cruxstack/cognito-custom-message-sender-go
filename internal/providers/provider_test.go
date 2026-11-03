package providers

import (
	"context"
	"testing"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
)

func TestWithCode_DoesNotMutateInput(t *testing.T) {
	in := map[string]any{"name": "emma"}

	out := withCode(in, "123456")

	if out["code"] != "123456" || out["name"] != "emma" {
		t.Errorf("unexpected output: %v", out)
	}
	if _, ok := in["code"]; ok {
		t.Error("input map was mutated")
	}
	if got := withCode(nil, "1"); got["code"] != "1" {
		t.Errorf("unexpected output for nil input: %v", got)
	}
}

func TestParseNameAddr(t *testing.T) {
	tests := []struct {
		in, name, addr string
	}{
		{"ACME <noreply@example.org>", "ACME", "noreply@example.org"},
		{"noreply@example.org", "", "noreply@example.org"},
		{"not an address", "", "not an address"},
	}

	for _, tc := range tests {
		name, addr := parseNameAddr(tc.in)
		if name != tc.name || addr != tc.addr {
			t.Errorf("parseNameAddr(%q) = (%q, %q), want (%q, %q)", tc.in, name, addr, tc.name, tc.addr)
		}
	}
}

func TestProviders_DryRun(t *testing.T) {
	tests := []struct {
		name     string
		provider Provider
		data     func() *types.EmailData
		wantErr  bool
	}{
		{
			name:     "ses with config",
			provider: &SESProvider{DryRun: true},
			data: func() *types.EmailData {
				return &types.EmailData{Providers: &types.EmailProviderMap{SES: &types.EmailProviderData{TemplateID: "t"}}}
			},
		},
		{
			name:     "ses without config",
			provider: &SESProvider{DryRun: true},
			data: func() *types.EmailData {
				return &types.EmailData{Providers: &types.EmailProviderMap{SendGrid: &types.EmailProviderData{TemplateID: "t"}}}
			},
			wantErr: true,
		},
		{
			name:     "sendgrid with config",
			provider: &SendGridProvider{DryRun: true},
			data: func() *types.EmailData {
				return &types.EmailData{Providers: &types.EmailProviderMap{SendGrid: &types.EmailProviderData{TemplateID: "t"}}}
			},
		},
		{
			name:     "sendgrid without config",
			provider: &SendGridProvider{DryRun: true},
			data:     func() *types.EmailData { return &types.EmailData{} },
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.provider.Send(context.Background(), tc.data())
			if (err != nil) != tc.wantErr {
				t.Errorf("Send() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
