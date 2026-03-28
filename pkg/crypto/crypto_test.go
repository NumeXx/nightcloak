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
// ---------------------------------------------------------------------------
// XChaCha20-Poly1305 layer tests
// ---------------------------------------------------------------------------

func TestXEncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	cases := [][]byte{
		[]byte("hello world"),
		[]byte(""),
		make([]byte, 100_000),
		{0x00, 0xFF, 0x80, 0x01},
	}

	for _, pt := range cases {
		ct, err := XEncrypt(pt, key)
		if err != nil {
			t.Fatalf("XEncrypt error: %v", err)
		}
		got, err := XDecrypt(ct, key)
		if err != nil {
			t.Fatalf("XDecrypt error: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("roundtrip mismatch for %d-byte input", len(pt))
		}
	}
}

func TestXDecrypt_WrongKey(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, KeySize)
	ct, _ := XEncrypt([]byte("secret"), key)

	wrongKey := bytes.Repeat([]byte{0xBB}, KeySize)
	_, err := XDecrypt(ct, wrongKey)
	if err == nil {
		t.Error("expected error with wrong key, got nil")
	}
}

func TestXEncrypt_UniqueNonces(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, KeySize)
	ct1, _ := XEncrypt([]byte("same"), key)
	ct2, _ := XEncrypt([]byte("same"), key)
	if bytes.Equal(ct1, ct2) {
		t.Error("two XEncrypt calls produced identical output — nonce reuse")
	}
}

func TestXDecrypt_TooShort(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, KeySize)
	_, err := XDecrypt([]byte("short"), key)
	if err == nil {
		t.Error("expected error for short ciphertext, got nil")
	}
}

func TestXEncrypt_WireFormat(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, KeySize)
	pt := []byte("test")
	ct, _ := XEncrypt(pt, key)

	expectedLen := chacha20poly1305.NonceSizeX + len(pt) + chacha20poly1305.Overhead
	if len(ct) != expectedLen {
		t.Errorf("XChaCha20 ciphertext length = %d, want %d", len(ct), expectedLen)
	}
}

// ---------------------------------------------------------------------------
// Base58 tests
// ---------------------------------------------------------------------------

func TestBase58_RoundTrip(t *testing.T) {
	cases := [][]byte{
		{0x00, 0x01, 0x02, 0x03},
		make([]byte, 32),
		[]byte("NightCloak rocks"),
		{0xFF, 0xFE, 0xFD},
	}
	// Fill the 32-byte case with non-zero values.
	for i := range cases[1] {
		cases[1][i] = byte(i + 1)
	}

	for _, input := range cases {
		encoded := Base58Encode(input)
		decoded, err := Base58Decode(encoded)
		if err != nil {
			t.Fatalf("Base58Decode error: %v", err)
		}
		if !bytes.Equal(decoded, input) {
			t.Errorf("Base58 roundtrip failed\n  input:   %x\n  encoded: %s\n  decoded: %x",
				input, encoded, decoded)
		}
	}
}

func TestBase58_NoAmbiguousChars(t *testing.T) {
	// The Base58 alphabet must not contain 0, O, I, l.
	ambiguous := "0OIl"
	for _, c := range ambiguous {
		if strings.ContainsRune(base58Alphabet, c) {
			t.Errorf("Base58 alphabet contains ambiguous character %q", c)
		}
	}
}

func TestBase58_32ByteKey(t *testing.T) {
	// A 32-byte random-ish key must decode back to exactly 32 bytes.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*7 + 13)
	}
	encoded := Base58Encode(key)
	decoded, err := Base58Decode(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("decoded length = %d, want 32", len(decoded))
	}
	if !bytes.Equal(decoded, key) {
		t.Errorf("key mismatch after Base58 roundtrip")
	}
}
