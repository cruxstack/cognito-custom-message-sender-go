package types

type EmailData struct {
	DestinationAddress string         `json:"dstAddress"`
	SourceAddress      string         `json:"srcAddress"`
	TemplateID         string         `json:"templateID"`
	TemplateData       map[string]any `json:"templateData"`
}
