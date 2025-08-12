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
	SES *EmailProviderData `json:"ses,omitempty"`
}

type EmailProviderData struct {
	TemplateID   string         `json:"templateId"`
	TemplateData map[string]any `json:"templateData"`
}
