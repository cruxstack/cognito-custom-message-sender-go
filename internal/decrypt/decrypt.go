// Package decrypt decrypts the secrets (verification codes and temporary
// passwords) that Amazon Cognito sends to custom sender triggers.
//
// Cognito encrypts each secret with the AWS Encryption SDK and the user
// pool's KMS key, then base64-encodes the ciphertext.
package decrypt

import (
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"sync"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers/kmsprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// Decrypter turns a ciphertext from a Cognito event into plaintext.
type Decrypter interface {
	Decrypt(ctx context.Context, ciphertext string) (string, error)
}

// Code decrypts the secret from a Cognito event. It returns "" without
// calling d when ciphertext is empty, which is the case for events that carry
// no secret.
//
// Cognito HTML-escapes reserved characters (such as < and >) in temporary
// passwords before encrypting them, so the plaintext is unescaped here.
func Code(ctx context.Context, d Decrypter, ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	plaintext, err := d.Decrypt(ctx, ciphertext)
	if err != nil {
		return "", err
	}
	return html.UnescapeString(plaintext), nil
}

// Plaintext is a Decrypter that returns its input unchanged. It is meant for
// local runs and tests, where events carry plaintext codes.
type Plaintext struct{}

func (Plaintext) Decrypt(_ context.Context, ciphertext string) (string, error) {
	return ciphertext, nil
}

// KMS decrypts AWS Encryption SDK messages with a single KMS key.
type KMS struct {
	// the kms key provider mutates internal maps without locking
	mu     sync.Mutex
	client *client.Client
	cmm    model.CryptoMaterialsManager
}

// NewKMS returns a KMS decrypter that only accepts messages encrypted with
// keyARN. The key must be given as a full key ARN.
func NewKMS(keyARN string) (*KMS, error) {
	cfg, err := clientconfig.NewConfigWithOpts(
		clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyForbidEncryptAllowDecrypt),
	)
	if err != nil {
		return nil, fmt.Errorf("encryption sdk config: %w", err)
	}

	keyProvider, err := kmsprovider.New(keyARN)
	if err != nil {
		return nil, fmt.Errorf("kms key provider: %w", err)
	}

	cmm, err := materials.NewDefault(keyProvider)
	if err != nil {
		return nil, fmt.Errorf("materials manager: %w", err)
	}

	return &KMS{client: client.NewClientWithConfig(cfg), cmm: cmm}, nil
}

func (d *KMS) Decrypt(ctx context.Context, ciphertext string) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	d.mu.Lock()
	plaintext, _, err := d.client.Decrypt(ctx, blob, d.cmm)
	d.mu.Unlock()
	if err != nil {
		return "", fmt.Errorf("kms decrypt: %w", err)
	}

	return string(plaintext), nil
}
