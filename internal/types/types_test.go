package types

import "testing"

func TestEmailData_ProviderData(t *testing.T) {
	ses := &EmailProviderData{TemplateID: "ses-template"}
	sendgrid := &EmailProviderData{TemplateID: "sg-template"}

	tests := []struct {
		name     string
		data     *EmailData
		provider string
		want     *EmailProviderData
	}{
		{"nil providers", &EmailData{}, "ses", nil},
		{"ses", &EmailData{Providers: &EmailProviderMap{SES: ses}}, "ses", ses},
		{"sendgrid", &EmailData{Providers: &EmailProviderMap{SendGrid: sendgrid}}, "sendgrid", sendgrid},
		{"missing template id", &EmailData{Providers: &EmailProviderMap{SES: &EmailProviderData{}}}, "ses", nil},
		{"other provider only", &EmailData{Providers: &EmailProviderMap{SES: ses}}, "sendgrid", nil},
		{"unknown provider", &EmailData{Providers: &EmailProviderMap{SES: ses}}, "unknown", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.data.ProviderData(tc.provider); got != tc.want {
				t.Errorf("ProviderData(%q) = %v, want %v", tc.provider, got, tc.want)
			}
		})
	}
}
