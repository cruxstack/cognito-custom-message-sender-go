package sender

import (
	"testing"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
)

func TestParseEmailData(t *testing.T) {
	single := func(provider string) *config.Config {
		return &config.Config{AppEmailProvider: provider}
	}
	failover := &config.Config{
		AppEmailProvider:          "sendgrid",
		AppEmailFailoverEnabled:   true,
		AppEmailFailoverProviders: []string{"ses"},
	}

	tests := []struct {
		name    string
		cfg     *config.Config
		data    types.EmailData
		wantSES string
		wantErr bool
	}{
		{
			name:    "v1 top-level template maps to ses",
			cfg:     single("ses"),
			data:    types.EmailData{SourceAddress: "a@x.io", DestinationAddress: "b@x.io", TemplateID: "v1"},
			wantSES: "v1",
		},
		{
			name: "explicit ses config wins over v1 template",
			cfg:  single("ses"),
			data: types.EmailData{
				SourceAddress: "a@x.io", DestinationAddress: "b@x.io", TemplateID: "v1",
				Providers: &types.EmailProviderMap{SES: &types.EmailProviderData{TemplateID: "v2"}},
			},
			wantSES: "v2",
		},
		{
			name:    "missing destination",
			cfg:     single("ses"),
			data:    types.EmailData{SourceAddress: "a@x.io", TemplateID: "v1"},
			wantErr: true,
		},
		{
			name:    "missing source",
			cfg:     single("ses"),
			data:    types.EmailData{DestinationAddress: "b@x.io", TemplateID: "v1"},
			wantErr: true,
		},
		{
			name:    "ses without template",
			cfg:     single("ses"),
			data:    types.EmailData{SourceAddress: "a@x.io", DestinationAddress: "b@x.io"},
			wantErr: true,
		},
		{
			name:    "sendgrid without sendgrid config",
			cfg:     single("sendgrid"),
			data:    types.EmailData{SourceAddress: "a@x.io", DestinationAddress: "b@x.io", TemplateID: "v1"},
			wantErr: true,
		},
		{
			name:    "failover accepts config for secondary only",
			cfg:     failover,
			data:    types.EmailData{SourceAddress: "a@x.io", DestinationAddress: "b@x.io", TemplateID: "v1"},
			wantSES: "v1",
		},
		{
			name:    "failover without any config",
			cfg:     failover,
			data:    types.EmailData{SourceAddress: "a@x.io", DestinationAddress: "b@x.io"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Sender{Config: tc.cfg}

			got, err := s.ParseEmailData(&tc.data)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseEmailData() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if pd := got.ProviderData("ses"); pd == nil || pd.TemplateID != tc.wantSES {
				t.Errorf("ses provider data = %+v, want template %q", pd, tc.wantSES)
			}
		})
	}
}
