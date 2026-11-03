package decrypt

import (
	"context"
	"errors"
	"testing"
)

const testKeyARN = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

func TestNewKMS(t *testing.T) {
	if _, err := NewKMS(testKeyARN); err != nil {
		t.Errorf("NewKMS(arn) = %v", err)
	}
	if _, err := NewKMS("alias/not-an-arn"); err == nil {
		t.Error("NewKMS() should reject a key that isn't an ARN")
	}
}

func TestKMS_InvalidBase64(t *testing.T) {
	d, err := NewKMS(testKeyARN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Decrypt(context.Background(), "not base64!"); err == nil {
		t.Error("Decrypt() should reject invalid base64")
	}
}

type fakeDecrypter struct {
	plaintext string
	err       error
	calls     int
}

func (f *fakeDecrypter) Decrypt(context.Context, string) (string, error) {
	f.calls++
	return f.plaintext, f.err
}

func TestCode(t *testing.T) {
	ctx := context.Background()

	t.Run("empty ciphertext skips decryption", func(t *testing.T) {
		f := &fakeDecrypter{err: errors.New("should not be called")}
		if got, err := Code(ctx, f, ""); got != "" || err != nil || f.calls != 0 {
			t.Errorf("Code() = %q, %v with %d calls", got, err, f.calls)
		}
	})

	t.Run("unescapes temporary passwords", func(t *testing.T) {
		f := &fakeDecrypter{plaintext: "Ab1&lt;x&gt;&amp;"}
		if got, err := Code(ctx, f, "ciphertext"); got != "Ab1<x>&" || err != nil {
			t.Errorf("Code() = %q, %v", got, err)
		}
	})

	t.Run("codes pass through", func(t *testing.T) {
		if got, _ := Code(ctx, Plaintext{}, "123456"); got != "123456" {
			t.Errorf("Code() = %q", got)
		}
	})

	t.Run("errors", func(t *testing.T) {
		f := &fakeDecrypter{err: errors.New("kms unavailable")}
		if _, err := Code(ctx, f, "ciphertext"); err == nil {
			t.Error("Code() should return the decrypt error")
		}
	})
}
