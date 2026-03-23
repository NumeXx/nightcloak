package crypto

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		plaintext string
		password  string
	}{
		{"simple", "hello world", "password123"},
		{"empty plaintext", "", "password123"},
		{"long password", "secret", strings.Repeat("p", 1000)},
		{"unicode", "你好世界 🌍", "пароль"},
		{"binary-safe", string([]byte{0x00, 0xFF, 0x80, 0x01}), "key"},
		{"large payload", strings.Repeat("A", 100_000), "pass"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := Encrypt([]byte(tc.plaintext), tc.password)
			if err != nil {
				t.Fatalf("Encrypt error: %v", err)
			}

			pt, err := Decrypt(ct, tc.password)
			if err != nil {
				t.Fatalf("Decrypt error: %v", err)
			}

			if string(pt) != tc.plaintext {
				t.Errorf("roundtrip mismatch: got %q, want %q", string(pt), tc.plaintext)
			}
		})
	}
}

func TestDecrypt_WrongPassword(t *testing.T) {
	ct, err := Encrypt([]byte("secret"), "correct-password")
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	_, err = Decrypt(ct, "wrong-password")
	if err == nil {
		t.Fatal("expected error decrypting with wrong password, got nil")
	}
}

func TestEncrypt_UniqueOutputs(t *testing.T) {
	// Same plaintext + password must produce different ciphertext each time
	// because salt and nonce are random.
	ct1, _ := Encrypt([]byte("same input"), "same pass")
	ct2, _ := Encrypt([]byte("same input"), "same pass")

	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of the same data produced identical output — salt/nonce reuse")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	_, err := Decrypt([]byte("short"), "pass")
	if err == nil {
		t.Fatal("expected error for short ciphertext, got nil")
	}
}

func TestDecrypt_Tampered(t *testing.T) {
	ct, _ := Encrypt([]byte("important data"), "password")

	// Flip a byte in the ciphertext portion (after the header).
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[headerSize+1] ^= 0xFF

	_, err := Decrypt(tampered, "password")
	if err == nil {
		t.Fatal("expected error for tampered ciphertext, got nil")
	}
}

func TestCiphertextFormat(t *testing.T) {
	plaintext := []byte("test payload")
	ct, err := Encrypt(plaintext, "pass")
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	expectedLen := SaltSize + NonceSize + len(plaintext) + chacha20poly1305.Overhead
	if len(ct) != expectedLen {
		t.Errorf("ciphertext length = %d, want %d (salt:%d + nonce:%d + payload:%d + tag:%d)",
			len(ct), expectedLen, SaltSize, NonceSize, len(plaintext), chacha20poly1305.Overhead)
	}
}
