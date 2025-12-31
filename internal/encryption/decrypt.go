package encryption

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers/kmsprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func Decrypt(ctx context.Context, kmsId, encryptedText string) (string, error) {
	// mock the decryption for testing - only allowed in debug mode
	if os.Getenv("APP_DEBUG_MODE") == "true" && kmsId == "MOCKED_KEY_ID" {
		return encryptedText, nil
	}

	cfg, err := clientconfig.NewConfigWithOpts(
		clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyForbidEncryptAllowDecrypt),
	)
	if err != nil {
		return "", fmt.Errorf("client config setup failed: %w", err)
	}
	client := client.NewClientWithConfig(cfg)

	kmsKeyProvider, err := kmsprovider.New(kmsId)
	if err != nil {
		return "", fmt.Errorf("kms key provider setup failed: %w", err)
	}

	cmm, err := materials.NewDefault(kmsKeyProvider)
	if err != nil {
		return "", fmt.Errorf("materials manager setup failed: %w", err)
	}

	cipherText, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	plaintext, _, err := client.Decrypt(ctx, cipherText, cmm)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}
