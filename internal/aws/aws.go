package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
)

type AWSClient struct {
	KMS *KMSClient
	SES *SESClient
}

func NewAWSClient(ctx context.Context) (*AWSClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	return &AWSClient{
		KMS: NewKMSClient(cfg),
		SES: NewSESClient(cfg),
	}, nil
}
