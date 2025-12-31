package aws

import (
	"context"
	"encoding/base64"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type KMSClient struct {
	Client *kms.Client
}

func NewKMSClient(cfg aws.Config) *KMSClient {
	return &KMSClient{Client: kms.NewFromConfig(cfg)}
}

func (c *KMSClient) Decrypt(ctx context.Context, keyId, encodedEncryptedStr string) (string, error) {
	if encodedEncryptedStr == "" {
		return "", nil
	}

	// mock the decryption for testing - only allowed in debug mode
	if os.Getenv("APP_DEBUG_MODE") == "true" && keyId == "MOCKED_KEY_ID" {
		return encodedEncryptedStr, nil
	}

	decodedCode, err := base64.StdEncoding.DecodeString(encodedEncryptedStr)
	if err != nil {
		return "", err
	}

	decryptInput := &kms.DecryptInput{
		CiphertextBlob: decodedCode,
		KeyId:          aws.String(keyId),
	}
	decryptOutput, err := c.Client.Decrypt(ctx, decryptInput)
	if err != nil {
		return "", err
	}

	return string(decryptOutput.Plaintext), nil
}
