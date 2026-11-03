package types

type EmailData struct {
	DestinationAddress string            `json:"dstAddress"`
	SourceAddress      string            `json:"srcAddress"`
	Providers          *EmailProviderMap `json:"providers,omitempty"`
	TemplateID         string            `json:"templateID"`
	TemplateData       map[string]any    `json:"templateData"`
	VerificationCode   string            `json:"-"`
}

type EmailProviderMap struct {
	SendGrid *EmailProviderData `json:"sendgrid,omitempty"`
	SES      *EmailProviderData `json:"ses,omitempty"`
}

type EmailProviderData struct {
	TemplateID   string         `json:"templateId"`
	TemplateData map[string]any `json:"templateData"`
}

func (d *EmailData) ProviderData(provider string) *EmailProviderData {
	if d.Providers == nil {
		return nil
	}

	var pd *EmailProviderData
	switch provider {
	case "ses":
		pd = d.Providers.SES
	case "sendgrid":
		pd = d.Providers.SendGrid
	}
	if pd == nil || pd.TemplateID == "" {
		return nil
	}
	return pd
}
