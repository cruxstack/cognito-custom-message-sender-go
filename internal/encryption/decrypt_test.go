package encryption

import (
	"context"
	"testing"
)

func TestNewKMSDecrypter(t *testing.T) {
	if _, err := NewKMSDecrypter("arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"); err != nil {
		t.Errorf("unexpected error for key arn: %v", err)
	}
	if _, err := NewKMSDecrypter(MockKeyID); err == nil {
		t.Error("expected error for non-arn key id")
	}
}

func TestKMSDecrypter_InvalidBase64(t *testing.T) {
	d, err := NewKMSDecrypter("arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := d.Decrypt(context.Background(), "not base64!"); err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestPassthrough(t *testing.T) {
	got, err := Passthrough{}.Decrypt(context.Background(), "123456")
	if err != nil || got != "123456" {
		t.Errorf("Decrypt() = (%q, %v), want (123456, nil)", got, err)
	}
}
