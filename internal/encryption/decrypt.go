package encryption

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers/kmsprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

const MockKeyID = "MOCKED_KEY_ID"

type Passthrough struct{}

func (Passthrough) Decrypt(_ context.Context, ciphertext string) (string, error) {
	return ciphertext, nil
}

type KMSDecrypter struct {
	// the kms key provider mutates internal maps without locking
	mu     sync.Mutex
	client *client.Client
	cmm    model.CryptoMaterialsManager
}

func NewKMSDecrypter(keyID string) (*KMSDecrypter, error) {
	cfg, err := clientconfig.NewConfigWithOpts(
		clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyForbidEncryptAllowDecrypt),
	)
	if err != nil {
		return nil, fmt.Errorf("client config setup failed: %w", err)
	}

	keyProvider, err := kmsprovider.New(keyID)
	if err != nil {
		return nil, fmt.Errorf("kms key provider setup failed: %w", err)
	}

	cmm, err := materials.NewDefault(keyProvider)
	if err != nil {
		return nil, fmt.Errorf("materials manager setup failed: %w", err)
	}

	return &KMSDecrypter{client: client.NewClientWithConfig(cfg), cmm: cmm}, nil
}

func (d *KMSDecrypter) Decrypt(ctx context.Context, ciphertext string) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("invalid base64 ciphertext: %w", err)
	}

	d.mu.Lock()
	plaintext, _, err := d.client.Decrypt(ctx, blob, d.cmm)
	d.mu.Unlock()
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}
