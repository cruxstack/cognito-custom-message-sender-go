package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
)

type SESClient struct {
	Client *ses.Client
}

func NewSESClient(cfg aws.Config) *SESClient {
	return &SESClient{Client: ses.NewFromConfig(cfg)}
}

func (c *SESClient) SendEmail(ctx context.Context, templateID string, templateData map[string]any, srcAddress, dstAddress string, dryRun bool) error {
	templateDataJSON, err := json.Marshal(templateData)
	if err != nil {
		return fmt.Errorf("error marshaling template data: %w", err)
	}

	if dryRun {
		slog.DebugContext(ctx, "dry-run ses send templated email",
			"template_id", templateID,
			"template_data", string(templateDataJSON),
			"src_address", srcAddress,
			"dst_address", dstAddress,
		)
		return nil
	}

	_, err = c.Client.SendTemplatedEmail(ctx, &ses.SendTemplatedEmailInput{
		Source:       aws.String(srcAddress),
		Template:     aws.String(templateID),
		TemplateData: aws.String(string(templateDataJSON)),
		Destination:  &types.Destination{ToAddresses: []string{dstAddress}},
	})
	if err != nil {
		return fmt.Errorf("error sending templated email: %w", err)
	}

	return nil
}
