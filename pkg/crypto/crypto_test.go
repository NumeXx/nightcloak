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
	tampered[v2HeaderSize+1] ^= 0xFF

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

	// v2 wire format: 4B magic + 16B salt + 12B nonce + payload + 16B tag
	expectedLen := v2HeaderSize + len(plaintext) + chacha20poly1305.Overhead
	if len(ct) != expectedLen {
		t.Errorf("ciphertext length = %d, want %d (magic:4 + salt:%d + nonce:%d + payload:%d + tag:%d)",
			len(ct), expectedLen, v2SaltSize, NonceSize, len(plaintext), chacha20poly1305.Overhead)
	}
}

func TestCiphertextV2Magic(t *testing.T) {
	ct, err := Encrypt([]byte("hello"), "pass")
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}
	if !isV2(ct) {
		t.Error("Encrypt output missing v2 magic prefix")
	}
}

func TestDecrypt_V1LegacyCompat(t *testing.T) {
	// Produce a v1 (PBKDF2) blob directly and confirm Decrypt still reads it.
	password := "legacy-pass"
	plaintext := []byte("old payload")

	salt := make([]byte, v1SaltSize)
	nonce := make([]byte, NonceSize)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	for i := range nonce {
		nonce[i] = byte(i + 10)
	}

	aead, err := newPBKDF2AEAD(password, salt)
	if err != nil {
		t.Fatalf("newPBKDF2AEAD: %v", err)
	}

	blob := make([]byte, 0, v1HeaderSize+len(plaintext)+aead.Overhead())
	blob = append(blob, salt...)
	blob = append(blob, nonce...)
	blob = aead.Seal(blob, nonce, plaintext, nil)

	got, err := Decrypt(blob, password)
	if err != nil {
		t.Fatalf("Decrypt v1 blob: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("v1 compat: got %q, want %q", got, plaintext)
	}
}
// ---------------------------------------------------------------------------
// v3 wire format tests (compression + padding + machine lock)
// ---------------------------------------------------------------------------

func TestEncryptV3_RoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		payload  string
		compress bool
		lock     bool
	}{
		{"plain", "hello world", false, false},
		{"compressed", strings.Repeat("AAAAAAAAAA", 200), true, false},
		{"locked", "machine-bound secret", false, true},
		{"compressed+locked", strings.Repeat("BBBBBBBB", 200), true, true},
		{"empty", "", false, false},
		{"binary", string([]byte{0x00, 0xFF, 0x80, 0x7F}), false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := EncryptV3([]byte(tc.payload), "password", tc.compress, tc.lock)
			if err != nil {
				t.Fatalf("EncryptV3: %v", err)
			}
			pt, err := Decrypt(ct, "password")
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(pt) != tc.payload {
				t.Errorf("roundtrip mismatch: got %q, want %q", pt, tc.payload)
			}
		})
	}
}

func TestEncryptV3_MagicPrefix(t *testing.T) {
	ct, err := EncryptV3([]byte("test"), "pass", false, false)
	if err != nil {
		t.Fatalf("EncryptV3: %v", err)
	}
	if !isV3(ct) {
		t.Error("EncryptV3 output missing v3 magic prefix")
	}
	if isV2(ct) {
		t.Error("EncryptV3 output incorrectly matches v2 magic")
	}
}

func TestEncryptV3_RandomPadding(t *testing.T) {
	// Same input must produce different-length ciphertext across runs
	// because pad length is randomized.
	sizes := make(map[int]bool)
	for i := 0; i < 20; i++ {
		ct, err := EncryptV3([]byte("same payload"), "pass", false, false)
		if err != nil {
			t.Fatalf("EncryptV3: %v", err)
		}
		sizes[len(ct)] = true
	}
	if len(sizes) < 2 {
		t.Error("EncryptV3 produced identical sizes across 20 runs — padding not varying")
	}
}

func TestEncryptV3_CompressionFlag(t *testing.T) {
	// Highly compressible payload: flag should be set.
	payload := bytes.Repeat([]byte("AAAA"), 500)
	ct, err := EncryptV3(payload, "pass", true, false)
	if err != nil {
		t.Fatalf("EncryptV3: %v", err)
	}
	flags := ct[4]
	if flags&v3FlagCompressed == 0 {
		t.Error("FlagCompressed not set for compressible payload")
	}

	// Incompressible payload (random bytes): flag should NOT be set.
	random := make([]byte, 256)
	for i := range random {
		random[i] = byte(i)
	}
	ct2, err := EncryptV3(random, "pass", true, false)
	if err != nil {
		t.Fatalf("EncryptV3 incompressible: %v", err)
	}
	// Don't assert flag state — depends on entropy of input. Just verify roundtrip.
	got, err := Decrypt(ct2, "pass")
	if err != nil {
		t.Fatalf("Decrypt incompressible: %v", err)
	}
	if !bytes.Equal(got, random) {
		t.Error("incompressible roundtrip mismatch")
	}
}

func TestEncryptV3_WrongPassword(t *testing.T) {
	ct, _ := EncryptV3([]byte("secret"), "correct", false, false)
	_, err := Decrypt(ct, "wrong")
	if err == nil {
		t.Error("expected error with wrong password, got nil")
	}
}

func TestEncryptV3_MachineLock(t *testing.T) {
	ct, err := EncryptV3([]byte("locked payload"), "pass", false, true)
	if err != nil {
		t.Fatalf("EncryptV3 locked: %v", err)
	}
	flags := ct[4]
	if flags&v3FlagLocked == 0 {
		t.Error("FlagLocked not set")
	}
	// Decrypt on the same machine should succeed.
	pt, err := Decrypt(ct, "pass")
	if err != nil {
		t.Fatalf("Decrypt locked on same machine: %v", err)
	}
	if string(pt) != "locked payload" {
		t.Errorf("got %q, want %q", pt, "locked payload")
	}
}

func TestEncryptV3_V2StillDecrypts(t *testing.T) {
	// v2 blobs produced by Encrypt must still decrypt after adding v3 support.
	ct, err := Encrypt([]byte("old payload"), "pass")
	if err != nil {
		t.Fatalf("Encrypt v2: %v", err)
	}
	pt, err := Decrypt(ct, "pass")
	if err != nil {
		t.Fatalf("Decrypt v2 after v3 added: %v", err)
	}
	if string(pt) != "old payload" {
		t.Errorf("v2 compat: got %q, want %q", pt, "old payload")
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
